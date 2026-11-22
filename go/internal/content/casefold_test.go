package content

import (
	"encoding/json"
	"os"
	"testing"
)

// SEC-CONTENT-1: encoding/json matches struct field names case-insensitively (with Unicode simple folding, so
// "ſ" U+017F reads as "s"), while the digest verification and the Python reference read exact keys. A key that
// equals a field name only up to case must therefore be ignored, as the reference ignores it: otherwise a pack
// whose exact keys verify could load other tables, or report another release digest, from its variant keys.
// "ſ" variants sort after the exact key, so they are decoded last and would win.
func TestCaseVariantKeysAreIgnoredLikeTheReference(t *testing.T) {
	data, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	genuine := doc["release"].(map[string]interface{})
	forged := map[string]interface{}{}
	for k, v := range genuine {
		forged[k] = v
	}
	forged["version"], forged["digest"] = "9999.12.31", "0123456789abcdef"
	doc["releaſe"] = forged                                                 // Release, folded
	doc["protocol_nameſ"] = map[string]interface{}{"forged/1": "ssl"}       // ProtocolNames: not in the release digest
	doc["Risks"] = map[string]interface{}{"forged": map[string]interface{}{ // plain upper-case variant
		"severity": "low", "description": "forged"}}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(out)
	if err != nil {
		t.Fatalf("a pack whose exact keys verify must load (the reference ignores the variant keys): %v", err)
	}
	if p.Release.Version != genuine["version"] || p.Release.Digest != genuine["digest"] || p.Release.Digest != p.Digests.Release {
		t.Errorf("release %q %q, verified %q: the variant release was decoded", p.Release.Version, p.Release.Digest, p.Digests.Release)
	}
	if _, ok := p.ProtocolNames["forged/1"]; ok {
		t.Error("the variant protocol_names table was decoded")
	}
	if _, ok := p.Risks["forged"]; ok {
		t.Error("the upper-case Risks table was decoded")
	}
}

// PRO-14 (Codex P2): the host catalog is a nested table. Case-variant keys beside it ("Host_Catalog") or beside
// its entries ("entrieſ") are outside the digest and must be ignored, as the reference ignores them; a variant
// key inside an entry ("domainſ", "Web_Fronts") is inside the hashed entry, so the pack must be refused. Either
// way the host lookup never uses an entry the verified release digest does not cover.
func TestCaseVariantHostCatalogKeysAreIgnoredLikeTheReference(t *testing.T) {
	load := func(edit func(doc, catalog, first map[string]interface{}, name string)) (*Pack, error) {
		data, err := os.ReadFile(packPath)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		catalog := doc["host_catalog"].(map[string]interface{})
		first := catalog["entries"].([]interface{})[0].(map[string]interface{})
		edit(doc, catalog, first, first["name"].(string))
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return Parse(out)
	}
	forgedEntry := func(name, domain string) []interface{} {
		return []interface{}{map[string]interface{}{"name": name, "domains": []interface{}{domain}, "web_fronts": []interface{}{}}}
	}
	p, err := load(func(doc, catalog, _ map[string]interface{}, name string) {
		catalog["entrieſ"] = forgedEntry(name, "forged-entries.example")                                   // Entries, folded
		doc["Host_Catalog"] = map[string]interface{}{"entries": forgedEntry(name, "forged-table.example")} // upper-case
	})
	if err != nil {
		t.Fatalf("a pack whose exact keys verify must load (the reference ignores the variant keys): %v", err)
	}
	for _, host := range []string{"forged-entries.example", "forged-table.example"} {
		if app := p.ApplicationForHost(host); app != "" {
			t.Errorf("host %s resolved to %q: a variant host-catalog key was decoded", host, app)
		}
	}
	if _, err := load(func(_, _, first map[string]interface{}, _ string) {
		first["domainſ"] = []interface{}{"forged-domain.example"}   // Domains, folded
		first["Web_Fronts"] = []interface{}{"forged-front.example"} // WebFronts, upper-case
	}); err == nil {
		t.Error("variant keys inside a hashed host-catalog entry must fail the digest, not load")
	}
}
