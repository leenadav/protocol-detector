package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/content"
)

// SR-31: a policy document is validated completely before use; every malformed key, name, port, bound, size or
// duplicate name is an error, and no partial policy is returned.
func TestSecurityPolicyValidationRejectsEveryInvalidDocument(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{
		`[]`, `{"version": 2}`, `{"default": "drop"}`, `{"extra": 1}`, `{"rules": {}}`,
		`{"rules": [{"action": "allow", "match": {"apps": ["no-such-app"]}}]}`,
		`{"rules": [{"action": "allow", "match": {"categories": ["nope"]}}]}`,
		`{"rules": [{"action": "allow", "match": {"risks": ["made-up"]}}]}`,
		`{"rules": [{"action": "allow", "match": {"server_ports": ["tcp/0"]}}]}`,
		`{"rules": [{"action": "allow", "match": {"server_ports": ["sctp/1"]}}]}`,
		`{"rules": [{"action": "allow", "match": {"server_ports": ["tcp/5-3"]}}]}`,
		`{"rules": [{"action": "allow", "match": {"risk_min": 6}}]}`,
		`{"rules": [{"action": "allow", "match": {"risk_min": 4, "risk_max": 2}}]}`,
		`{"rules": [{"action": "allow", "match": {"apps": []}}]}`,
		`{"rules": [{"action": "allow", "match": {"port_usage": ["weird"]}}]}`,
		`{"rules": [{"action": "allow", "match": {"unknown": 1}}]}`,
		`{"rules": [{"action": "allow", "bogus": 1}]}`,
		`{"rules": [{"action": "allow", "application_default": "yes"}]}`,
		`{"rules": [{"name": "a", "action": "allow"}, {"name": "a", "action": "deny"}]}`,
		`{"rules": [{"name": "", "action": "allow"}]}`,
		`{"rules": "x"}`, `not json`,
	}
	for _, text := range bad {
		if p, err := FromJSON([]byte(text), pack); err == nil || p != nil {
			t.Errorf("%s: accepted (%v)", text, p)
		}
	}
	rules := make([]string, maxRules+1)
	for i := range rules {
		rules[i] = `{"action": "allow"}`
	}
	if _, err := FromJSON([]byte(`{"rules": [`+strings.Join(rules, ",")+`]}`), pack); err == nil {
		t.Errorf("%d rules accepted", maxRules+1)
	}
	if _, err := FromJSON([]byte(`{"rules": [`+strings.Join(rules[:maxRules], ",")+`]}`), pack); err != nil {
		t.Errorf("%d rules refused: %v", maxRules, err)
	}
	path := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(path, []byte("["+strings.Repeat(" ", maxFile)+"]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FromPath(path, pack); err == nil || err.Error() != "Policy file exceeds 4 MiB" {
		t.Errorf("oversized policy file: %v", err)
	}
	example, err := FromPath("../../../policy-example.json", pack)
	if err != nil {
		t.Fatal(err)
	}
	if len(example.Rules) != 9 || example.Default != "alert" {
		t.Errorf("example policy: %d rules, default %s", len(example.Rules), example.Default)
	}
}

func telnetVerdict(port string) *appid.Verdict {
	client := "telnet"
	return &appid.Verdict{App: "telnet", Category: "networking", Subcategory: "remote-access", Technology: "client-server", Risk: 5,
		PortUsage: port, Status: "identified", ClientProtocol: &client, Reasons: []string{"r"}, Risks: []string{"cleartext-credentials"},
		Characteristics: []string{"used-by-malware"}}
}

// SR-31 and SR-32: the first matching rule decides, otherwise the default; application-default rules match only on
// standard ports and explain the fallthrough; the decision is a label and never changes the verdict it reads.
func TestSecurityPolicyFirstMatchDefaultAndApplicationDefault(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	p, err := FromJSON([]byte(`{"default": "deny", "rules": [
		{"name": "a", "action": "alert", "match": {"apps": ["telnet"]}},
		{"name": "b", "action": "allow", "match": {"categories": ["networking"]}},
		{"name": "web", "action": "allow", "application_default": true, "match": {"apps": ["web-browsing"]}}]}`), pack)
	if err != nil {
		t.Fatal(err)
	}
	telnet := telnetVerdict("standard")
	before := *telnet
	d := p.Evaluate(telnet, "tcp", 23, true, nil, "handshake")
	if d.Action != "alert" || d.Rule == nil || *d.Rule != "a" || d.Reasons[0] != "rule 'a' matched telnet" || d.Predicates["identity_basis"] == "" {
		t.Fatalf("first match: %+v", d)
	}
	if !reflect.DeepEqual(before, *telnet) {
		t.Fatalf("evaluation changed the verdict: %+v -> %+v", before, *telnet)
	}
	other := telnetVerdict("standard")
	other.App = "rdp"
	if d := p.Evaluate(other, "tcp", 3389, true, nil, "handshake"); d.Rule == nil || *d.Rule != "b" {
		t.Fatalf("second rule: %+v", d)
	}
	none := telnetVerdict("standard")
	none.App, none.Category = "modbus", "business-systems"
	if d := p.Evaluate(none, "tcp", 502, true, nil, "handshake"); d.Action != "deny" || d.Rule != nil {
		t.Fatalf("default: %+v", d)
	}
	web := func(port string) *appid.Verdict {
		v := telnetVerdict(port)
		v.App, v.Category = "web-browsing", "general-internet"
		return v
	}
	if d := p.Evaluate(web("standard"), "tcp", 80, true, nil, "handshake"); d.Action != "allow" || d.Rule == nil || *d.Rule != "web" ||
		len(d.Reasons) < 2 || d.Reasons[1] != "application-default: port usage standard" {
		t.Fatalf("application-default on a standard port: %+v", d)
	}
	moved := p.Evaluate(web("nonstandard"), "tcp", 8081, true, nil, "handshake")
	if moved.Action != "deny" || moved.Rule != nil || len(moved.Reasons) < 2 ||
		!strings.Contains(moved.Reasons[1], "would allow web-browsing on its application-default ports only") {
		t.Fatalf("application-default on a nonstandard port: %+v", moved)
	}
	empty, err := FromJSON([]byte(`{"rules": []}`), pack)
	if err != nil {
		t.Fatal(err)
	}
	if d := empty.Evaluate(telnet, "tcp", 23, true, nil, "handshake"); d.Action != "allow" || d.Rule != nil {
		t.Fatalf("empty policy: %+v", d)
	}
	for _, v := range d.Fields()["reasons"].([]string) {
		if strings.Contains(v, "cleartext") {
			t.Fatalf("decision reasons carry verdict values beyond the application name: %v", v)
		}
	}
}
