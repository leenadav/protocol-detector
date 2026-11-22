package livectl

import (
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

func ingestText(t *testing.T, s *State, text string) {
	t.Helper()
	v, err := ojson.Decode([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	s.Ingest(v.(*ojson.Object))
}

// A line whose endpoint is not an [address, port] pair raises IndexError in the reference's ingest, which
// kills its reader thread; here it stays on the legacy path and is kept out of the versioned log.
func TestMalformedEndpointIsKeptOutOfTheLog(t *testing.T) {
	s := NewState(nil)
	s.Begin("00112233aabbccdd", "lo", "running")
	ingestText(t, s, `{"type": "session", "client": "x", "server": ["10.0.0.1", 1], "app": "tls"}`)
	ingestText(t, s, `{"type": "session", "client": ["10.0.0.2", 2], "server": ["10.0.0.1", 1], "app": "tls"}`)
	page, err := s.EventsSince(0, 500)
	if err != nil {
		t.Fatal(err)
	}
	text := ojson.MustDumps(page)
	if strings.Count(text, `"kind": "session"`) != 1 || !strings.Contains(ojson.MustDumps(s.Snapshot()), `"sessions_total": 2`) {
		t.Fatalf("unexpected page %s", text)
	}
}

func TestResetIsScopedToTheNamedRun(t *testing.T) {
	s := NewState(nil)
	s.Begin("aaaaaaaaaaaaaaaa", "lo", "stopped")
	ingestText(t, s, `{"type": "error", "reason": "x"}`)
	for _, stale := range []ojson.Value{nil, "bbbbbbbbbbbbbbbb", ojson.Int("5")} {
		if got := ojson.MustDumps(s.ResetIdle(stale)); !strings.Contains(got, `"reset": false`) {
			t.Fatalf("%v reset the run: %s", stale, got)
		}
	}
	if got := ojson.MustDumps(s.ResetIdle("aaaaaaaaaaaaaaaa")); got != `{"reset": true, "reason": "cleared", "run_id": null}` {
		t.Fatal(got)
	}
	if got := ojson.MustDumps(s.ResetIdle("aaaaaaaaaaaaaaaa")); !strings.Contains(got, `"reason": "stale"`) {
		t.Fatalf("a second reset of the same run was not stale: %s", got)
	}
}

// FuzzIngestNeverPanics: any object a worker could write leaves every view readable and JSON.
func FuzzIngestNeverPanics(f *testing.F) {
	for _, seed := range []string{`{"type": "session", "client": ["1.2.3.4", 1], "server": ["5.6.7.8", 2], "layers": {"application": {}}}`,
		`{"type": "decryption", "report": {"connections": [{"session_id": "a", "generation": "x"}]}}`,
		`{"type": "capture_gap", "session_ids": [1, "a"]}`, `{"type": "capture_gap", "scope": "all_observations_this_capture"}`,
		`{"type": "session", "client": ["a", 1], "server": ["b", 2], "encryption": [1], "app": {"x": 1}}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := ojson.Decode(data)
		event, ok := v.(*ojson.Object)
		if err != nil || !ok {
			return
		}
		s := NewState(nil)
		s.Begin("00112233aabbccdd", "lo", "running")
		for i := 0; i < 3; i++ {
			s.Ingest(event.Copy())
		}
		if _, err := s.EventsSince(0, 500); err != nil {
			t.Fatalf("a logged event cannot be reduced: %v", err)
		}
		_ = s.Snapshot()
		_ = s.StateView()
	})
}
