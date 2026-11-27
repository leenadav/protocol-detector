package serve

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startServer runs a Server on a free loopback port with a minimal presentation root (SOURCE.json, web/index.html).
func startLoopbackServer(t *testing.T) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "SOURCE.json"), []byte(`{"build_digest": "d", "version": "v", "commit": "c", "components": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "web"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "web", "index.html"), []byte("<!doctype html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(root, "/nonexistent-protodetect")
	if err != nil {
		t.Fatal(err)
	}
	port, err := s.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(s.Close)
	return s, "127.0.0.1:" + strconv.Itoa(port)
}

// exchange sends one raw HTTP/1.1 request (headers as given, no defaults) and returns the status and body.
func loopbackExchange(t *testing.T, addr, method, path string, headers []string, body string) (int, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	request := method + " " + path + " HTTP/1.1\r\n" + strings.Join(headers, "\r\n")
	if len(headers) > 0 {
		request += "\r\n"
	}
	if method == "POST" {
		request += "Content-Length: " + strconv.Itoa(len(body)) + "\r\n"
	}
	request += "Connection: close\r\n\r\n" + body
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("%s %s: no answer: %v", method, path, err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(data)
}

// SR-61: every request needs the exact loopback Host and a same-origin or absent Origin; every control, job and
// decryption endpoint also needs the per-process token; health never carries the token.
func TestLoopbackHostOriginAndTokenRules(t *testing.T) {
	s, addr := startLoopbackServer(t)
	host := "Host: " + addr
	token := "X-Live-Token: " + s.Live.Token
	if len(s.Live.Token) < 32 {
		t.Fatalf("token %d characters, want a long random token", len(s.Live.Token))
	}

	for _, bad := range [][]string{
		nil,
		{"Host: localhost:" + strings.Split(addr, ":")[1]},
		{"Host: evil.example:" + strings.Split(addr, ":")[1]},
		{"Host: " + addr + ".evil.example"},
	} {
		for _, path := range []string{"/", "/api/health", "/api/live/interfaces"} {
			if code, _ := loopbackExchange(t, addr, "GET", path, bad, ""); code != 403 {
				t.Errorf("GET %s with %q: status %d, want 403", path, bad, code)
			}
		}
		if code, _ := loopbackExchange(t, addr, "POST", "/api/live/start", append(bad, token), "{}"); code != 403 {
			t.Errorf("POST with %q: status %d, want 403", bad, code)
		}
	}
	for _, origin := range []string{"Origin: http://evil.example", "Origin: null", "Origin: https://" + addr, "Origin: http://localhost"} {
		if code, _ := loopbackExchange(t, addr, "GET", "/api/live/interfaces", []string{host, origin}, ""); code != 403 {
			t.Errorf("GET with %q: status %d, want 403", origin, code)
		}
		if code, _ := loopbackExchange(t, addr, "POST", "/api/jobs/analyze", []string{host, origin, token}, ""); code != 403 {
			t.Errorf("POST with %q: status %d, want 403", origin, code)
		}
	}
	if code, _ := loopbackExchange(t, addr, "GET", "/", []string{host, "Origin: http://" + addr}, ""); code != 200 {
		t.Errorf("same-origin GET: status %d, want 200", code)
	}

	for _, path := range []string{"/api/live/start", "/api/live/stop", "/api/live/heartbeat", "/api/live/reset",
		"/api/jobs/analyze", "/api/jobs/demo", "/api/jobs/x/cancel", "/api/decrypt", "/api/decrypt/demo"} {
		for _, headers := range [][]string{{host}, {host, "X-Live-Token: wrong"}, {host, "X-Live-Token: " + s.Live.Token[:len(s.Live.Token)-1]}} {
			if code, _ := loopbackExchange(t, addr, "POST", path, headers, ""); code != 403 {
				t.Errorf("POST %s with %q: status %d, want 403", path, headers, code)
			}
		}
	}
	if code, _ := loopbackExchange(t, addr, "POST", "/api/live/heartbeat", []string{host, token}, "{}"); code == 403 {
		t.Errorf("heartbeat with the token was refused")
	}

	code, body := loopbackExchange(t, addr, "GET", "/api/health", []string{host}, "")
	if code != 200 {
		t.Fatalf("health: status %d (%s)", code, body)
	}
	if strings.Contains(body, s.Live.Token) || strings.Contains(strings.ToLower(body), "token") {
		t.Errorf("health carries the token: %s", body)
	}
	if !strings.Contains(body, `"build_digest"`) || !strings.Contains(body, `"instance"`) {
		t.Errorf("health lacks the build digest or instance: %s", body)
	}
}

// SR-62: the handler pool is bounded and rejects beyond it without queueing: with MaxHandlers requests in progress
// the next connection is answered 503 at once and counted; a slot that frees serves again.
func TestHandlerPoolRejectsBeyondItsBound(t *testing.T) {
	s, addr := startLoopbackServer(t)
	held := make([]net.Conn, 0, MaxHandlers)
	for i := 0; i < MaxHandlers; i++ {
		conn, err := net.DialTimeout("tcp4", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		// An incomplete request keeps its handler reading.
		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(s.slots) < MaxHandlers && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(s.slots) != MaxHandlers {
		t.Fatalf("%d of %d handlers busy", len(s.slots), MaxHandlers)
	}
	started := time.Now()
	code, body := loopbackExchange(t, addr, "GET", "/", []string{"Host: " + addr}, "")
	if code != 503 || !strings.Contains(body, "Too many concurrent requests") || time.Since(started) > 2*time.Second {
		t.Fatalf("beyond the pool: status %d after %v: %s", code, time.Since(started), body)
	}
	if s.rejected.Load() != 1 {
		t.Fatalf("rejected counter %d, want 1", s.rejected.Load())
	}
	held[0].Close()
	deadline = time.Now().Add(5 * time.Second)
	for len(s.slots) >= MaxHandlers && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if code, _ := loopbackExchange(t, addr, "GET", "/", []string{"Host: " + addr}, ""); code != 200 {
		t.Fatalf("after a slot freed: status %d, want 200", code)
	}
	for _, conn := range held[1:] {
		conn.Close()
	}
}
