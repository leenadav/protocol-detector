package childapp

import (
	"strings"
	"testing"
)

// SEC-CHILD-5: a host_suffixes entry was checked only against the owner of the suffix itself, so a suffix with a
// more specific catalog domain of another application under it (googleapis.com, whose maps.googleapis.com is
// google-maps') loaded, and only the match-time owner check kept that application's hosts out of the child.

// anthropicChild is a child of anthropic-claude (owner of anthropic.com) whose suffix rule covers api.anthropic.com,
// which the catalog gives anthropic-api.
const anthropicChild = `{"name": "claude-x", "container": "anthropic-claude", "description": "d",%s
	"evidence": ["https://example.org/doc"], "rules": [{"host_suffixes": ["anthropic.com"], "methods": ["POST"]}]}]}`

func anthropicDoc(dependsOn string) []byte {
	if dependsOn != "" {
		dependsOn = ` "depends_on": [` + dependsOn + `],`
	}
	return []byte(header + strings.Replace(anthropicChild, "%s", dependsOn, 1))
}

// TestSuffixWithForeignOwnerUnderItIsRefused: the loader refuses the suffix and names the nested domain and its owner.
func TestSuffixWithForeignOwnerUnderItIsRefused(t *testing.T) {
	_, err := Load(anthropicDoc(""), pack(t), Options{})
	if err == nil {
		t.Fatal("a host_suffixes entry covering another application's catalog domain loaded")
	}
	for _, want := range []string{"'anthropic.com'", "'api.anthropic.com'", "'anthropic-api'"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %s", err, want)
		}
	}
	// The finding's own case: googleapis.com under google-base covers maps.googleapis.com (google-maps) and more.
	doc := header + `{"name": "google-drive-x", "container": "google-drive", "description": "d", "depends_on": ["google-base"],
		"evidence": ["https://example.org/doc"], "rules": [{"host_suffixes": ["googleapis.com"], "methods": ["POST"]}]}]}`
	if _, err := Load([]byte(doc), pack(t), Options{}); err == nil || !strings.Contains(err.Error(), "host suffix 'googleapis.com' covers") {
		t.Fatalf("googleapis.com under google-base: %v", err)
	}
}

// TestSuffixWithOwnedNestedDomainLoads: a nested domain whose owner is the container or a depends_on is allowed.
func TestSuffixWithOwnedNestedDomainLoads(t *testing.T) {
	s, err := Load(anthropicDoc(`"anthropic-api"`), pack(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"claude.anthropic.com", "api.anthropic.com"} {
		if res := s.Classify(Request{Host: host, Method: "POST", Path: "/x"}); res.App != "claude-x" {
			t.Fatalf("%s: %+v", host, res)
		}
	}
}

// TestShippedSuffixesHaveNoForeignOwners: every shipped host_suffixes entry passes the load-time check.
func TestShippedSuffixesHaveNoForeignOwners(t *testing.T) {
	if _, err := Embedded(pack(t)); err != nil {
		t.Fatal(err)
	}
}

// TestClassifyRechecksHostOwner is the second layer: should a set ever hold a suffix rule whose child does not own
// a nested domain (here anthropic-api is dropped from the owners after a valid load), Classify still never
// relabels that host.
func TestClassifyRechecksHostOwner(t *testing.T) {
	s, err := Load(anthropicDoc(`"anthropic-api"`), pack(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	delete(s.byName["claude-x"].owners, "anthropic-api")
	res := s.Classify(Request{Host: "api.anthropic.com", Method: "POST", Path: "/x"})
	if res.App != "anthropic-api" || res.HostOwner != "anthropic-api" || res.Basis != BasisServerName || res.Container != "" {
		t.Fatalf("another owner's host was moved to a child: %+v", res)
	}
	if res.Evaluated != 1 {
		t.Fatalf("the rule should be reached and skipped: %+v", res)
	}
}

// TestGoogleapisSuffixLoadsWithEveryNestedOwner (from PR #201): the finding's own suffix is refused through
// google-base alone and loads once every nested owner is a depends_on; a suffix with nothing foreign under it is
// unchanged.
func TestGoogleapisSuffixLoadsWithEveryNestedOwner(t *testing.T) {
	body := func(dependsOn string) string {
		return header + `{"name": "google-drive-x", "container": "google-drive", "description": "d", "depends_on": [` + dependsOn +
			`], "evidence": ["https://example.org/doc"], "rules": [{"host_suffixes": ["googleapis.com"], "methods": ["POST"]}]}]}`
	}
	_, err := Load([]byte(body(`"google-base"`)), pack(t), Options{})
	if err == nil || !strings.Contains(err.Error(), "covers 'maps.googleapis.com', which the server-name catalog gives 'google-maps'") {
		t.Fatalf("a suffix over another owner's domain was accepted or refused for another reason: %v", err)
	}
	s, err := Load([]byte(body(`"google-base", "google-maps", "google-play", "chrome-remote-desktop"`)), pack(t), Options{})
	if err != nil {
		t.Fatalf("a suffix whose nested owners are all depends_on was refused: %v", err)
	}
	for host, owner := range map[string]string{"www.googleapis.com": "google-base", "maps.googleapis.com": "google-maps"} {
		if res := s.Classify(Request{Host: host, Method: "POST", Path: "/x"}); res.App != "google-drive-x" || res.HostOwner != owner {
			t.Errorf("%s: %+v, want google-drive-x under %s", host, res, owner)
		}
	}
	if _, err := Load([]byte(header+`{"name": "dropbox-x", "container": "dropbox", "description": "d", "evidence": ["https://e.org"],
		"rules": [{"host_suffixes": ["dropboxapi.com"], "methods": ["POST"]}]}]}`), pack(t), Options{}); err != nil {
		t.Fatalf("dropboxapi.com: %v", err)
	}
}

// TestClassifyRechecksForcedSuffix (from PR #201): the load-time index is not kept, and a suffix rule forced over a
// domain whose host the catalog gives another application never fires there (SEC-CHILD-2, SEC-CHILD-5).
func TestClassifyRechecksForcedSuffix(t *testing.T) {
	doc := header + `{"name": "google-drive-x", "container": "google-drive", "description": "d", "depends_on": ["google-base"],
		"evidence": ["https://example.org/doc"], "rules": [{"hosts": ["www.googleapis.com"], "methods": ["POST"]}]}]}`
	s, err := Load([]byte(doc), pack(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.nested != nil {
		t.Fatal("the load-time domain index is retained after Load")
	}
	s.suffix["googleapis.com"] = append(s.suffix["googleapis.com"], s.exact["www.googleapis.com"]...)
	if res := s.Classify(Request{Host: "api.googleapis.com", Method: "POST", Path: "/x"}); res.App != "google-drive-x" || res.HostOwner != "google-base" {
		t.Fatalf("google-base host: %+v", res)
	}
	res := s.Classify(Request{Host: "maps.googleapis.com", Method: "POST", Path: "/x"})
	if res.App != "google-maps" || res.Container != "" || res.Basis != BasisServerName || res.HostOwner != "google-maps" ||
		len(res.Reasons) != 1 || res.Reasons[0] != ReasonNoChildMatched {
		t.Fatalf("another owner's host was moved to a child: %+v", res)
	}
}
