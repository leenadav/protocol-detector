package serve

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

var presentationRoot = filepath.Join("..", "..", "..", "presentation")

func get(t *testing.T, port int, path string) (int, string, []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	host := "127.0.0.1:" + strconv.Itoa(port)
	if _, err := io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header.Get("Content-Type"), body
}

// The demo page's reads need no interpreter: the catalog and the sample capture come from this binary.
func TestCatalogAndSampleWithoutInterpreter(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no python3 to find, even by accident
	s, err := New(presentationRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	port, err := s.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	defer s.Close()

	code, kind, body := get(t, port, "/api/catalog")
	if code != 200 || !strings.HasPrefix(kind, "application/json") {
		t.Fatalf("GET /api/catalog: %d %s %.200s", code, kind, body)
	}
	var catalog struct {
		Source       map[string]interface{}   `json:"source"`
		Protocols    []map[string]interface{} `json:"protocols"`
		Applications []map[string]interface{} `json:"applications"`
		Outcomes     []string                 `json:"outcomes"`
		Limits       map[string]int           `json:"limits"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Protocols) < 50 || len(catalog.Applications) < 100 || len(catalog.Outcomes) == 0 {
		t.Fatalf("catalog tables too small: %d protocols, %d applications, %d outcomes",
			len(catalog.Protocols), len(catalog.Applications), len(catalog.Outcomes))
	}
	if digest, _ := catalog.Source["build_digest"].(string); digest == "" {
		t.Fatalf("catalog source has no build_digest (the launcher matches instances on it): %v", catalog.Source)
	}
	if catalog.Limits["frames"] != MaxFrames || catalog.Limits["worker_seconds"] != WorkerSeconds {
		t.Fatalf("catalog limits: %v", catalog.Limits)
	}
	// The reference's key order: source, protocols, applications, outcomes, limits.
	order := []string{`{"source": {"version": `, `"protocols": [`, `"applications": [`, `"outcomes": [`, `"limits": {"upload_mb": 8`}
	last := -1
	for _, part := range order {
		at := bytes.Index(body, []byte(part))
		if at <= last {
			t.Fatalf("catalog key %q out of order (at %d, previous %d)", part, at, last)
		}
		last = at
	}

	code, kind, body = get(t, port, "/api/sample")
	if code != 200 || kind != "application/vnd.tcpdump.pcap" || !bytes.Equal(body, demoCapture) {
		t.Fatalf("GET /api/sample: %d %s, %d bytes", code, kind, len(body))
	}
}

func TestDemoCaptureIsAPcap(t *testing.T) {
	if len(demoCapture) < 24 || binary.LittleEndian.Uint32(demoCapture) != 0xa1b2c3d4 {
		t.Fatalf("assets/demo.pcap is not a little-endian pcap (%d bytes)", len(demoCapture))
	}
	copied := DemoCapture()
	copied[0] ^= 0xff
	if demoCapture[0] != 0xd4 {
		t.Fatal("DemoCapture shares the embedded bytes")
	}
}

func TestDemoWorkerAnalyzesTheEmbeddedCapture(t *testing.T) {
	var out bytes.Buffer
	if code := DemoWorker(&out); code != 0 {
		t.Fatalf("DemoWorker exit %d", code)
	}
	var result struct {
		Sessions []struct {
			App string `json:"app"`
		} `json:"sessions"`
		Meta map[string]interface{} `json:"meta"`
		Err  string                 `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.Err != "" {
		t.Fatalf("DemoWorker: %v %s", err, result.Err)
	}
	apps := map[string]bool{}
	for _, s := range result.Sessions {
		apps[s.App] = true
	}
	for _, want := range []string{"ssl", "ssh", "dns", "quic", "mqtt"} {
		if !apps[want] {
			t.Errorf("demo analysis has no %s session (apps %v)", want, apps)
		}
	}
}

func TestShowcaseDecryptsAllThreeExchanges(t *testing.T) {
	report, err := Showcase(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dumped, err := ojson.Dumps(report)
	if err != nil {
		t.Fatal(err)
	}
	text := []byte(dumped)
	var parsed struct {
		Connections []struct {
			Version string `json:"version"`
			Cipher  string `json:"cipher_suite"`
			Status  string `json:"status"`
			Layers  struct {
				Inner struct {
					App           string `json:"app"`
					Authenticated bool   `json:"authenticated"`
				} `json:"inner"`
			} `json:"layers"`
		} `json:"connections"`
		Decrypted int  `json:"decrypted"`
		Skipped   int  `json:"skipped"`
		Synthetic bool `json:"synthetic"`
	}
	if err := json.Unmarshal(text, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Connections) != 3 || parsed.Decrypted != 3 || parsed.Skipped != 0 || !parsed.Synthetic {
		t.Fatalf("showcase: %s", text)
	}
	want := []struct{ version, cipher, app string }{{"TLS 1.3", "", "webdav"}, {"TLS 1.2", "0xc02f", "web-browsing"}, {"TLS 1.2", "0xc030", "resp"}}
	for i, c := range parsed.Connections {
		if c.Version != want[i].version || (want[i].cipher != "" && c.Cipher != want[i].cipher) || c.Status != "decrypted" ||
			c.Layers.Inner.App != want[i].app || !c.Layers.Inner.Authenticated {
			t.Errorf("connection %d: %+v, want %+v", i, c, want[i])
		}
	}
}

func TestDecryptDemoWorker(t *testing.T) {
	var out bytes.Buffer
	if code := DecryptDemoWorker(&out); code != 0 {
		t.Fatalf("DecryptDemoWorker exit %d", code)
	}
	if !bytes.HasPrefix(out.Bytes(), []byte(`{"connections": [`)) || !bytes.HasSuffix(out.Bytes(), []byte(`"synthetic": true}`+"\n")) {
		t.Fatalf("DecryptDemoWorker: %.300s", out.Bytes())
	}
}

func TestWorkerCommandsNeedNoInterpreter(t *testing.T) {
	s, err := New(presentationRoot, "/opt/protodetect")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, kind := range []string{"analyze", "demo", "decrypt", "decrypt-demo"} {
		argv, _, err := s.workerCommand(kind, []byte("x"))
		if err != nil || len(argv) != 3 || argv[0] != "/opt/protodetect" || argv[1] != "serve-worker" || argv[2] != kind {
			t.Errorf("workerCommand(%q) = %v, %v", kind, argv, err)
		}
	}
	if _, _, err := s.workerCommand("python", nil); err == nil {
		t.Error("an unknown worker kind is accepted")
	}
}

func TestShowcaseFixtureStopsWhenCancelled(t *testing.T) {
	certificate, err := throwawayCertificate()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := showcaseFixture(ctx, certificate, showcaseCases[0], 51000)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled showcase exchange reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled showcase exchange did not stop")
	}
}
