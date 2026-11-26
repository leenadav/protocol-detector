package serve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/analyze"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

// The frozen catalog (PRO-401) must not drift from what the engine loads: every application of the embedded content
// pack, field for field, and every family the inspector registers. A new release or family fails here until
// catalog.json carries it.
func TestCatalogMatchesTheContentPackAndTheEngine(t *testing.T) {
	var frozen struct {
		Protocols    []struct{ Family string } `json:"protocols"`
		Applications []*content.Application    `json:"applications"`
		Outcomes     []string                  `json:"outcomes"`
	}
	if err := json.Unmarshal(catalogJSON, &frozen); err != nil {
		t.Fatal(err)
	}
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(frozen.Applications) != len(pack.Applications) {
		t.Fatalf("catalog has %d applications, the content pack %d", len(frozen.Applications), len(pack.Applications))
	}
	for _, app := range frozen.Applications {
		loaded, ok := pack.Applications[app.Name]
		if !ok {
			t.Fatalf("catalog application %q is not in the content pack", app.Name)
		}
		want, _ := json.Marshal(loaded)
		got, _ := json.Marshal(app)
		if string(want) != string(got) {
			t.Errorf("application %s differs:\n catalog %s\n pack    %s", app.Name, got, want)
		}
	}
	for _, outcome := range frozen.Outcomes {
		if !pack.Outcomes[outcome] {
			t.Errorf("catalog outcome %q is not a content-pack outcome", outcome)
		}
	}
	if len(frozen.Outcomes) != len(pack.Outcomes) {
		t.Errorf("catalog has %d outcomes, the content pack %d", len(frozen.Outcomes), len(pack.Outcomes))
	}
	var families []string
	for _, protocol := range frozen.Protocols {
		families = append(families, protocol.Family)
	}
	registered := engine.Families()
	sort.Strings(families)
	sort.Strings(registered)
	if !reflect.DeepEqual(families, registered) {
		t.Errorf("catalog families %v\n engine families %v", families, registered)
	}
}

func TestCatalogIsAssembledAsTheReferenceDid(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "SOURCE.json"), []byte(`{"version": "9.9.9", "commit": "abc", "extra": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := catalog(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(value.Keys(), ","); got != "source,protocols,applications,outcomes,limits" {
		t.Fatalf("keys %s", got)
	}
	source, _ := value.Get("source")
	text := ojson.MustDumps(source)
	want := `{"version": "9.9.9", "branch": null, "commit": "abc", "repository": null, "build_digest": null, "components": null}`
	if text != want {
		t.Fatalf("source %s, want %s", text, want)
	}
	limits, _ := value.Get("limits")
	if got := ojson.MustDumps(limits); got != `{"upload_mb": 8, "frames": 20000, "sessions": 500, "worker_seconds": 25}` {
		t.Fatalf("limits %s", got)
	}
	if _, err := catalog(t.TempDir()); err == nil {
		t.Fatal("a missing SOURCE.json must fail, as catalog_data() raises")
	}
}

func TestDemoCaptureIsAnalyzed(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	text, err := analyze.Present(DemoCapture(), pack, analyze.Limits{Frames: MaxFrames, Sessions: MaxSessions, Events: MaxEvents}, func() float64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Sessions []struct {
			Status string `json:"engine_status"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatal(err)
	}
	identified := 0
	for _, session := range result.Sessions {
		if session.Status == "identified" {
			identified++
		}
	}
	if len(result.Sessions) < 15 || identified < 10 {
		t.Fatalf("demo capture: %d sessions, %d identified", len(result.Sessions), identified)
	}
}

// The showcase makes three real TLS exchanges in memory and decrypts each with the engine: every connection is
// decrypted, and the inner applications are the ones each exchange carried.
func TestShowcaseDecryptsItsThreeExchanges(t *testing.T) {
	report, err := Showcase()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(report.Keys(), ","); got != "connections,frames,decrypted,skipped,synthetic" {
		t.Fatalf("keys %s", got)
	}
	text := ojson.MustDumps(report)
	var result struct {
		Connections []struct {
			Status      string `json:"status"`
			Application string `json:"application"`
			Version     string `json:"version"`
		} `json:"connections"`
		Decrypted int  `json:"decrypted"`
		Synthetic bool `json:"synthetic"`
	}
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Connections) != 3 || !result.Synthetic || result.Decrypted < 3 {
		t.Fatalf("showcase: %s", text)
	}
	var applications []string
	for _, connection := range result.Connections {
		if connection.Status != "decrypted" {
			t.Fatalf("connection not decrypted: %s", text)
		}
		applications = append(applications, connection.Application)
	}
	if got := strings.Join(applications, ","); got != "webdav,web-browsing,resp" {
		t.Fatalf("inner applications %s: %s", got, text)
	}
	if strings.Contains(text, "CLIENT_RANDOM") || strings.Contains(text, "TRAFFIC_SECRET") {
		t.Fatal("the report must not carry key-log material")
	}
}
