package serve

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

// SR-62: the handler pool is bounded: with every one of the MaxHandlers slots busy, a further connection is answered
// 503 at once and counted, never queued behind the busy handlers.
func TestSecurityHandlerPoolRejectsBeyondItsBoundWithoutQueueing(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{listener: listener, slots: make(chan struct{}, MaxHandlers)}
	for i := 0; i < MaxHandlers; i++ {
		s.slots <- struct{}{} // every handler is busy
	}
	go s.Serve()
	defer listener.Close()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := io.ReadAll(conn)
	if err != nil || !strings.HasPrefix(string(reply), "HTTP/1.1 503 Service Unavailable\r\n") ||
		!strings.Contains(string(reply), "Too many concurrent requests; retry shortly.") {
		t.Fatalf("a connection beyond the pool: %q %v", reply, err)
	}
	if s.rejected.Load() != 1 || len(s.slots) != MaxHandlers {
		t.Fatalf("rejected %d, %d slots held", s.rejected.Load(), len(s.slots))
	}
}

// SR-63 (launcher and health): /api/health reports the whole-build digest of the shipped SOURCE.json manifest and a
// 16-hex-character instance id that is stable for the life of the server, and carries no token. The launcher's
// reuse decision compares exactly this digest.
func TestSecurityHealthReportsTheBuildDigestAndInstance(t *testing.T) {
	root := "../../../presentation"
	raw, err := os.ReadFile(filepath.Join(root, "SOURCE.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		BuildDigest string `json:"build_digest"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil || len(manifest.BuildDigest) < 16 {
		t.Fatalf("manifest: %v %q", err, manifest.BuildDigest)
	}
	s, err := New(root, "/nonexistent/protodetect")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Jobs.Shutdown()
	first, err := s.health()
	if err != nil {
		t.Fatal(err)
	}
	second, _ := s.health()
	digest, _ := first.Get("build_digest")
	instance, _ := first.Get("instance")
	again, _ := second.Get("instance")
	id, _ := instance.(string)
	if digest != manifest.BuildDigest || len(id) != 16 || strings.Trim(id, "0123456789abcdef") != "" || again != instance {
		t.Fatalf("health digest %v (manifest %s), instance %v then %v", digest, manifest.BuildDigest, instance, again)
	}
	if _, has := first.Get("components"); !has {
		t.Fatal("health has no components")
	}
	if text := ojson.MustDumps(first); strings.Contains(text, "token") {
		t.Fatalf("health carries a token: %s", text)
	}
}
