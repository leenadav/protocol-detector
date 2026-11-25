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

// The catalog (PRO-428) is read from the embedded content pack: every application of the pack exactly once, field
// for field, in the reference's order, and the pack's outcomes; only the protocol descriptors are frozen in
// catalog.json, and they must stay every family the inspector registers. A new content release is listed without any
// edit here, which TestCatalogFollowsANewContentRelease shows on a pack with an added batch.
func TestCatalogMatchesTheContentPackAndTheEngine(t *testing.T) {
	var frozen struct {
		Protocols        []struct{ Family string } `json:"protocols"`
		ApplicationOrder []string                  `json:"application_order"`
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(catalogJSON, &keys); err != nil || len(keys) != 2 || keys["protocols"] == nil || keys["application_order"] == nil {
		t.Fatalf("catalog.json must hold exactly protocols and application_order (the rest is the content pack's): %v", err)
	}
	if err := json.Unmarshal(catalogJSON, &frozen); err != nil {
		t.Fatal(err)
	}
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]bool{}
	for _, name := range pack.HostEntryOrder {
		hosts[name] = true
	}
	for _, name := range frozen.ApplicationOrder {
		if _, ok := pack.Applications[name]; !ok || hosts[name] {
			t.Errorf("catalog.json application_order names %q, which is not a built-in application of the pack", name)
		}
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "SOURCE.json"), []byte(`{"version": "1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := catalog(root)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Applications []*content.Application `json:"applications"`
		Outcomes     []string               `json:"outcomes"`
	}
	text, err := ojson.Dumps(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(text), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Applications) != len(pack.Applications) {
		t.Fatalf("catalog has %d applications, the content pack %d", len(body.Applications), len(pack.Applications))
	}
	seen := map[string]bool{}
	for i, app := range body.Applications {
		loaded, ok := pack.Applications[app.Name]
		if !ok || seen[app.Name] {
			t.Fatalf("catalog application %q is not in the content pack, or listed twice", app.Name)
		}
		seen[app.Name] = true
		want, _ := json.Marshal(loaded)
		got, _ := json.Marshal(app)
		if string(want) != string(got) {
			t.Errorf("application %s differs:\n catalog %s\n pack    %s", app.Name, got, want)
		}
		if i < len(frozen.ApplicationOrder) && app.Name != frozen.ApplicationOrder[i] {
			t.Errorf("catalog application %d is %s, the reference order has %s", i, app.Name, frozen.ApplicationOrder[i])
		}
	}
	for i, name := range pack.HostEntryOrder {
		if got := body.Applications[len(frozen.ApplicationOrder)+i].Name; got != name {
			t.Errorf("server-name application %d is %s, the pack's entry order has %s", i, got, name)
		}
	}
	if !reflect.DeepEqual(body.Outcomes, pack.OutcomeOrder) {
		t.Errorf("catalog outcomes %v, the content pack %v", body.Outcomes, pack.OutcomeOrder)
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

// A pack with more applications than the embedded one (a content batch: server-name entries appended, a full
// application record) is listed whole: the built-in order first, the server-name entries in entry order, the rest in
// name order, and nothing frozen needs an edit.
func TestCatalogFollowsANewContentRelease(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	grown := *pack
	grown.Applications = map[string]*content.Application{}
	for name, app := range pack.Applications {
		grown.Applications[name] = app
	}
	extra := func(name string) *content.Application {
		app := *pack.Applications["web-browsing"]
		app.Name, app.Aliases = name, []string{}
		return &app
	}
	grown.Applications["zz-batch-service"] = extra("zz-batch-service")
	grown.Applications["aa-batch-service"] = extra("aa-batch-service")
	grown.Applications["batch-video"] = extra("batch-video")
	grown.HostEntryOrder = append(append([]string{}, pack.HostEntryOrder...), "batch-video")
	var frozen struct {
		ApplicationOrder []ojson.Value `json:"application_order"`
	}
	if err := json.Unmarshal(catalogJSON, &frozen); err != nil {
		t.Fatal(err)
	}
	applications, _, err := packCatalog(&grown, frozen.ApplicationOrder)
	if err != nil {
		t.Fatal(err)
	}
	list := applications.([]ojson.Value)
	if len(list) != len(pack.Applications)+3 {
		t.Fatalf("%d applications listed for a pack of %d", len(list), len(pack.Applications)+3)
	}
	at := map[string]int{}
	for i, item := range list {
		name, _ := item.(*ojson.Object).Get("name")
		at[name.(string)] = i
	}
	lastHost := at[pack.HostEntryOrder[len(pack.HostEntryOrder)-1]]
	if at["batch-video"] != lastHost+1 || at["aa-batch-service"] <= at["batch-video"] || at["zz-batch-service"] <= at["aa-batch-service"] {
		t.Fatalf("new applications at batch-video %d, aa %d, zz %d (last server-name entry %d)", at["batch-video"],
			at["aa-batch-service"], at["zz-batch-service"], lastHost)
	}
	if _, _, err := packCatalog(pack, "not a list"); err == nil {
		t.Fatal("a catalog.json without an application_order list was accepted")
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
