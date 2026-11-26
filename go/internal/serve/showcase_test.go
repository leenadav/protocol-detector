package serve

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
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

// The catalog's applications are the content pack's (PRO-428): /api/catalog lists every application of the pack
// the binary embeds, each once and field for field, with no catalog edit when a release adds some. catalog.json
// keeps only what the pack does not hold: the protocol descriptors (every family the inspector registers), the
// outcomes (the pack's), and the reference's application order, every name of which must be a pack application of
// the frozen release, each once, with nothing missing.
func TestCatalogMatchesTheContentPackAndTheEngine(t *testing.T) {
	var frozen struct {
		Protocols        []struct{ Family string } `json:"protocols"`
		ApplicationOrder []string                  `json:"application_order"`
		Outcomes         []string                  `json:"outcomes"`
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(catalogJSON, &top); err != nil || len(top) != 3 {
		t.Fatalf("catalog.json holds %d keys (%v), want protocols, application_order and outcomes", len(top), err)
	}
	if err := json.Unmarshal(catalogJSON, &frozen); err != nil {
		t.Fatal(err)
	}
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	frozenPack, err := content.Load("../content/" + content.FrozenPackFile)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, name := range frozen.ApplicationOrder {
		if seen[name] {
			t.Errorf("application_order lists %q twice", name)
		}
		seen[name] = true
		if _, ok := frozenPack.Applications[name]; !ok {
			t.Errorf("application_order name %q is not an application of release %s", name, content.FrozenVersion)
		}
	}
	if len(seen) != len(frozenPack.Applications) {
		t.Errorf("application_order has %d names, release %s %d applications", len(seen), content.FrozenVersion, len(frozenPack.Applications))
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "SOURCE.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := catalog(root)
	if err != nil {
		t.Fatal(err)
	}
	listed, _ := value.Get("applications")
	var served []*content.Application
	if err := json.Unmarshal([]byte(ojson.MustDumps(listed)), &served); err != nil {
		t.Fatal(err)
	}
	if len(served) != len(pack.Applications) {
		t.Fatalf("catalog serves %d applications, the content pack has %d", len(served), len(pack.Applications))
	}
	names := map[string]bool{}
	for k, app := range served {
		loaded, ok := pack.Applications[app.Name]
		if !ok || names[app.Name] {
			t.Fatalf("catalog application %d %q is not in the content pack, or is listed twice", k, app.Name)
		}
		names[app.Name] = true
		want, _ := json.Marshal(loaded)
		got, _ := json.Marshal(app)
		if string(want) != string(got) {
			t.Errorf("application %s differs:\n catalog %s\n pack    %s", app.Name, got, want)
		}
		if k < len(frozen.ApplicationOrder) && seen[app.Name] && app.Name != frozen.ApplicationOrder[k] {
			t.Errorf("catalog application %d is %s, the reference order has %s", k, app.Name, frozen.ApplicationOrder[k])
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

// frozenApplicationsSHA256 is the SHA-256 of the applications of /api/catalog as the reference served them at
// content release content.FrozenVersion (the list catalog.json held until PRO-428, 544 entries, 193,321 bytes).
const frozenApplicationsSHA256 = "0cfa8586db06445e865b69938bc33d947b76c538b7c180d626695ad6e9ce6635"

// Built from the frozen release's pack, the applications are byte for byte the list the reference served
// (the golden server answers record it), so reading them from the pack changed nothing at that release.
func TestCatalogApplicationsOfTheFrozenReleaseAreTheReferences(t *testing.T) {
	var frozen struct {
		ApplicationOrder []string `json:"application_order"`
	}
	if err := json.Unmarshal(catalogJSON, &frozen); err != nil {
		t.Fatal(err)
	}
	pack, err := content.Load("../content/" + content.FrozenPackFile)
	if err != nil {
		t.Fatal(err)
	}
	applications, err := catalogApplications(pack, frozen.ApplicationOrder)
	if err != nil {
		t.Fatal(err)
	}
	text := ojson.MustDumps(applications)
	if sum := fmt.Sprintf("%x", sha256.Sum256([]byte(text))); sum != frozenApplicationsSHA256 || len(text) != 193321 {
		t.Fatalf("catalog applications of release %s: sha256 %s, %d bytes; the reference served %s, 193321 bytes",
			content.FrozenVersion, sum, len(text), frozenApplicationsSHA256)
	}
}

// A release's new applications follow the reference's, by name, and an ordered name the pack lacks is skipped.
func TestCatalogApplicationsAppendNewOnesByName(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	var some []string
	for name := range pack.Applications {
		some = append(some, name)
	}
	sort.Strings(some)
	order := []string{some[2], "no-such-application", some[0]}
	applications, err := catalogApplications(pack, order)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, value := range applications {
		name, _ := value.(*ojson.Object).Get("name")
		got = append(got, name.(string))
	}
	want := append([]string{some[2], some[0]}, append([]string{some[1]}, some[3:]...)...)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v...", got[:4])
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
