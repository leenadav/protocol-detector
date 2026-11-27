package serve

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// securityServer starts the loopback service on a free port with a minimal SOURCE.json and returns it.
func securityServer(t *testing.T) (*Server, int) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "SOURCE.json"), []byte(`{"build_digest": "x", "version": "0", "commit": "c", "components": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(root, "/nonexistent/protodetect")
	if err != nil {
		t.Fatal(err)
	}
	port, err := s.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(s.Close)
	return s, port
}

func securityCall(t *testing.T, port int, method, path, body string, headers map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://127.0.0.1:"+strconv.Itoa(port)+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "127.0.0.1:" + strconv.Itoa(port)
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

// SR-61: the loopback management service answers only the exact 127.0.0.1:port Host and a same-origin or absent
// Origin (DNS rebinding and cross-origin requests are 403 on GET and POST); every control, job, heartbeat and
// decryption endpoint requires the per-process token, a wrong token is refused, heartbeat and stop with the token
// are idempotent, and the health answer never carries the token.
func TestSecurityLoopbackHostOriginAndTokenRules(t *testing.T) {
	s, port := securityServer(t)
	self := "127.0.0.1:" + strconv.Itoa(port)
	for _, headers := range []map[string]string{
		{"Host": "127.0.0.1:" + strconv.Itoa(port+1)}, {"Host": "localhost:" + strconv.Itoa(port)}, {"Host": "example.com"},
		{"Origin": "null"}, {"Origin": "http://127.0.0.1:" + strconv.Itoa(port+1)}, {"Origin": "https://" + self}, {"Origin": "https://example.com"},
	} {
		if code, _ := securityCall(t, port, "GET", "/api/live/status", "", headers); code != 403 {
			t.Fatalf("GET with %v: %d", headers, code)
		}
		if code, _ := securityCall(t, port, "POST", "/api/demo", "", headers); code != 403 {
			t.Fatalf("POST /api/demo with %v: %d", headers, code)
		}
	}
	if code, _ := securityCall(t, port, "GET", "/api/live/status", "", map[string]string{"Origin": "http://" + self}); code != 200 {
		t.Fatalf("same-origin status: %d", code)
	}
	code, body := securityCall(t, port, "GET", "/api/live/interfaces", "", nil)
	var interfaces struct{ Token string }
	if err := json.Unmarshal([]byte(body), &interfaces); code != 200 || err != nil || len(interfaces.Token) < 16 || interfaces.Token != s.Live.Token {
		t.Fatalf("interfaces: %d %s", code, body)
	}
	token := interfaces.Token
	wrong := token[:len(token)-1] + "a"
	if token[len(token)-1] == 'a' {
		wrong = token[:len(token)-1] + "b"
	}
	for _, path := range []string{"/api/jobs?kind=demo", "/api/jobs/x/cancel", "/api/live/heartbeat", "/api/live/start", "/api/live/stop",
		"/api/live/reset", "/api/decrypt", "/api/decrypt/demo"} {
		for _, headers := range []map[string]string{nil, {"X-Live-Token": wrong}, {"X-Live-Token": ""}} {
			if code, body := securityCall(t, port, "POST", path, "{}", headers); code != 403 {
				t.Fatalf("POST %s with %v: %d %s", path, headers, code, body)
			}
		}
	}
	withToken := map[string]string{"X-Live-Token": token}
	code, body = securityCall(t, port, "POST", "/api/live/heartbeat", `{"run_id": "x"}`, withToken)
	if code != 200 || !strings.Contains(body, `"renewed": false`) {
		t.Fatalf("heartbeat with the token: %d %s", code, body)
	}
	for i := 0; i < 2; i++ {
		if code, body := securityCall(t, port, "POST", "/api/live/stop", `{"run_id": "x"}`, withToken); code != 200 || !strings.Contains(body, `"state": "idle"`) {
			t.Fatalf("stop %d with the token: %d %s", i, code, body)
		}
	}
	code, body = securityCall(t, port, "GET", "/api/health", "", nil)
	if code != 200 || strings.Contains(body, token) || strings.Contains(body, `"token"`) {
		t.Fatalf("health: %d %s", code, body)
	}
}
