package content

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/errs"
)

const packPath = "../../../migration/fixtures/content.json"

func load(t *testing.T) *Pack {
	t.Helper()
	p, err := Load(packPath)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPackLoadsAndLooksUp(t *testing.T) {
	p := load(t)
	if len(p.Applications) < 100 || p.Release.Version == "" || len(p.Risks) < 20 {
		t.Fatalf("pack: %d applications, release %q, %d risks", len(p.Applications), p.Release.Version, len(p.Risks))
	}
	if p.ApplicationName("http/1.1", "") != "web-browsing" || p.ApplicationName("", "tls") != "ssl" || p.ApplicationName("nope", "") != "" {
		t.Fatal("protocol name mapping")
	}
	web := p.Applications["web-browsing"]
	if !web.UsesPort("tcp", 80) || !web.UsesPort("tcp", 443) || web.UsesPort("tcp", 8000) || web.UsesPort("udp", 80) {
		t.Fatal("port table")
	}
	if name, kind, ok := p.AttributionForHost("teams.microsoft.com"); !ok || kind != "service" || name == "" {
		t.Fatalf("suffix lookup: %q %q %v", name, kind, ok)
	}
	if _, _, ok := p.AttributionForHost("notyoutube.com"); ok {
		t.Fatal("label boundary not respected")
	}
	if name, kind, _ := p.AttributionForHost("www.openai.com"); kind != "provider-web" || name != "openai-chatgpt" {
		t.Fatalf("web front: %q %q", name, kind)
	}
	if p.ApplicationForHost("www.openai.com") != "" || p.ApplicationForHost("api.openai.com") != "openai-platform" {
		t.Fatal("application for host")
	}
	host := p.HostApplication("youtube", "ssl")
	if host.Container == nil || *host.Container != "ssl" || !host.UsesPort("tcp", 443) || host.Category != "media" {
		t.Fatalf("host application: %+v", host)
	}
}

func mutate(t *testing.T, edit func(doc map[string]interface{})) error {
	t.Helper()
	data, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	json.Unmarshal(data, &doc)
	edit(doc)
	out, _ := json.Marshal(doc)
	_, err = Parse(out)
	return err
}

func TestPackFailsClosed(t *testing.T) {
	apps := func(doc map[string]interface{}) []interface{} { return doc["applications"].([]interface{}) }
	cases := map[string]func(doc map[string]interface{}){
		"duplicate application": func(doc map[string]interface{}) { doc["applications"] = append(apps(doc), apps(doc)[0]) },
		"unknown category":      func(doc map[string]interface{}) { apps(doc)[0].(map[string]interface{})["category"] = "made-up" },
		"risk out of range":     func(doc map[string]interface{}) { apps(doc)[0].(map[string]interface{})["risk"] = 9.0 },
		"bad port": func(doc map[string]interface{}) {
			apps(doc)[0].(map[string]interface{})["standard_ports"] = []interface{}{"tcp/70000"}
		},
		"dangling reference": func(doc map[string]interface{}) {
			apps(doc)[0].(map[string]interface{})["implicitly_uses"] = []interface{}{"ghost"}
		},
		"duplicate domain": func(doc map[string]interface{}) {
			entries := doc["host_catalog"].(map[string]interface{})["entries"].([]interface{})
			entries[1].(map[string]interface{})["domains"] = entries[0].(map[string]interface{})["domains"]
		},
		"bad schema":      func(doc map[string]interface{}) { doc["schema"] = 2.0 },
		"missing release": func(doc map[string]interface{}) { doc["release"] = map[string]interface{}{} },
	}
	for name, edit := range cases {
		err := mutate(t, edit)
		if err == nil || (!errors.Is(err, errs.Invalid.Err()) && !errors.Is(err, errs.Unsupported.Err())) {
			t.Fatalf("%s: accepted (%v)", name, err)
		}
	}
	if _, err := Parse([]byte("{not json")); !errors.Is(err, errs.Invalid.Err()) {
		t.Fatal("garbage accepted")
	}
}
