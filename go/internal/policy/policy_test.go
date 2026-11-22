package policy

import (
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/content"
)

const document = `{"default": "alert", "rules": [
 {"name": "web", "action": "allow", "application_default": true, "match": {"apps": ["web-browsing"], "server_ports": ["tcp/80", "tcp/8000-8100"]}},
 {"name": "needs-structure", "action": "deny", "match": {"identity_basis": ["structural"], "risk_min": 4}}]}`

func verdict(portUsage string, attribution map[string]interface{}) *appid.Verdict {
	client := "http/1.1"
	return &appid.Verdict{App: "web-browsing", Category: "general-internet", Subcategory: "internet-utility", Technology: "browser-based", Risk: 4,
		PortUsage: portUsage, Status: "identified", ClientProtocol: &client, Reasons: []string{"r"}, Attribution: attribution}
}

// Decisions and messages below were produced by the Python reference (Policy.from_json / evaluate) for the
// same document; a 20,000-document randomized differential preceded this port.
func TestDecisionsMatchTheReference(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	p, err := FromJSON([]byte(document), pack)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		v           *appid.Verdict
		transport   string
		port        int
		observation string
		action      string
		rule        string
		reasons     string
		basis       string
	}{
		{verdict("standard", nil), "tcp", 8050, "handshake", "allow", "web",
			"rule 'web' matched web-browsing|application-default: port usage standard", "structural"},
		{verdict("nonstandard", nil), "tcp", 80, "handshake", "deny", "needs-structure",
			"rule 'needs-structure' matched web-browsing|predicates: identity_basis=structural", "structural"},
		{verdict("standard", map[string]interface{}{"kind": "service"}), "udp", 80, "datagram", "alert", "",
			"no rule matched web-browsing; policy default|rule 'needs-structure' would match but its evidence requirements are not met: " +
				"identity_basis is client_assertion (needs structural)", "client_assertion"},
	} {
		d := p.Evaluate(c.v, c.transport, c.port, true, nil, c.observation)
		rule := ""
		if d.Rule != nil {
			rule = *d.Rule
		}
		if d.Action != c.action || rule != c.rule || strings.Join(d.Reasons, "|") != c.reasons || d.Predicates["identity_basis"] != c.basis ||
			d.Predicates["observation"] != c.observation || d.Predicates["directions"] != "one-direction" {
			t.Errorf("%s/%d: %+v", c.transport, c.port, d)
		}
	}
}

func TestInvalidDocumentsAreRejectedWithTheReferenceMessages(t *testing.T) {
	pack, _ := content.Embedded()
	for text, want := range map[string]string{
		`{"rules": [{"action": "allow", "match": {"server_ports": ["tcp/0"]}}]}`:         "Port range outside 1..65535: tcp/0",
		`{"rules": [{"action": "drop"}]}`:                                                "Rule 'rule-0' action must be one of allow, deny, alert",
		`{"rules": [{"name": "a", "action": "allow"}, {"name": "a", "action": "deny"}]}`: "Rule names must be unique",
		`{"zzz": 1, "aaa": 2}`: "Policy has unknown keys: aaa, zzz",
		`{"rules": [{"action": "allow", "match": {"apps": ["no-such-app"]}}]}`: "Unknown application: no-such-app",
		`{"rules": [{"action": "allow", "match": {"risk_min": 2.0}}]}`:         "Rule 'rule-0' risk_min must be an integer 1..5",
	} {
		if _, err := FromJSON([]byte(text), pack); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", text, err, want)
		}
	}
}
