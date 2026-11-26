package replay

import (
	"context"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/parity"
)

// frozenPack is the content pack of content.FrozenVersion, the release cases.json was recorded at (PRO-428).
const frozenPack = "../content/" + content.FrozenPackFile

// currentPack is the current content pack, the one the product binary embeds.
const currentPack = "../content/pack.json"

// currentContent describes the current pack relative to the frozen one: its release, and the application names,
// aliases and server names it added.
type currentContent struct {
	version string
	added   map[string]bool
}

func loadCurrentContent(t *testing.T) *currentContent {
	t.Helper()
	frozen, err := content.Load(frozenPack)
	if err != nil {
		t.Fatal(err)
	}
	now, err := content.Load(currentPack)
	if err != nil {
		t.Fatal(err)
	}
	out := &currentContent{version: now.Release.Version, added: map[string]bool{}}
	for name, app := range now.Applications {
		if old, ok := frozen.Applications[name]; !ok {
			out.added[name] = true
			for _, alias := range app.Aliases {
				out.added[alias] = true
			}
		} else if old.Description != app.Description || old.Risk != app.Risk || old.Category != app.Category {
			t.Fatalf("application %s changed since %s; a release that changes a recorded application needs its "+
				"frozen answers re-recorded, which this test does not decide", name, content.FrozenVersion)
		}
	}
	for app, domains := range now.AppDomains {
		known := map[string]bool{}
		for _, domain := range frozen.AppDomains[app] {
			known[domain] = true
		}
		for _, domain := range domains {
			if !known[domain] {
				out.added[domain] = true
				out.added[app] = true
			}
		}
	}
	return out
}

// retag reads every expected session record's content.version as the current release.
func (c *currentContent) retag(want interface{}) {
	result, _ := want.(map[string]interface{})
	records, _ := result["records"].([]interface{})
	for _, r := range records {
		record, _ := r.(map[string]interface{})
		if meta, ok := record["content"].(map[string]interface{}); ok && meta["version"] == content.FrozenVersion {
			meta["version"] = c.version
		}
	}
}

// touches reports whether a result names an application, alias or server name the current release added.
func (c *currentContent) touches(value interface{}) bool {
	switch v := value.(type) {
	case string:
		if c.added[v] {
			return true
		}
		for name := range c.added {
			if strings.Contains(name, ".") && strings.HasSuffix(v, name) {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if c.touches(item) {
				return true
			}
		}
	case map[string]interface{}:
		for _, item := range v {
			if c.touches(item) {
				return true
			}
		}
	}
	return false
}

// The current content release keeps every frozen answer (PRO-428): cases.json replayed with the current pack, the
// one the product binary embeds, gives exactly the recorded results, with content.version read as the current
// release; only a case whose result names an application or server name the current release added may differ.
// While the current release is content.FrozenVersion, nothing is exempt.
func TestCurrentContentKeepsTheFrozenAnswers(t *testing.T) {
	current := loadCurrentContent(t)
	doc, err := parity.Load(context.Background(), "../../../migration/fixtures/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	SetPackPath(currentPack)
	defer SetPackPath("")
	results, err := Run(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	failures, counts := compareCases(t, doc, results, current)
	logCounts(t, counts)
	t.Logf("current release %s, frozen %s, %d added names", current.version, content.FrozenVersion, len(current.added))
	if len(failures) > 0 {
		t.Fatalf("%d failures, first %d:\n%s", len(failures), min(25, len(failures)), strings.Join(failures[:min(25, len(failures))], "\n"))
	}
	exempt := 0
	for k, n := range counts {
		if strings.HasPrefix(k, "exempt/") {
			exempt += n
		}
	}
	if current.version == content.FrozenVersion && (exempt != 0 || len(current.added) != 0) {
		t.Fatalf("the current release is the frozen one, yet %d cases are exempt and %d names added", exempt, len(current.added))
	}
	if counts["matched/session"] < 1000 {
		t.Fatalf("too few matched session cases: %v", counts)
	}
}
