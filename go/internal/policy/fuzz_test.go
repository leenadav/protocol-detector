package policy

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/content"
)

// FuzzPolicyNeverPanics parses arbitrary policy documents and evaluates what parses (contract C16).
func FuzzPolicyNeverPanics(f *testing.F) {
	f.Add([]byte(`{"version": 1, "default": "alert", "rules": [{"name": "web", "action": "allow", "match": {"apps": ["web-browsing", "ssl"], "server_ports": ["tcp/80", "tcp/8000-8100"]}}, {"name": "risky", "action": "deny", "match": {"risk_min": 4}}, {"name": "ports", "action": "allow", "application_default": true, "match": {"transports": ["tcp"], "identity_basis": ["structural"]}}]}`))
	f.Add([]byte(`{"version": 1, "default": "deny", "rules": []}`))
	f.Add([]byte(`[]`))
	pack, err := content.Embedded()
	if err != nil {
		f.Fatal(err)
	}
	verdict := &appid.Verdict{App: "web-browsing", Category: "general-internet", Subcategory: "internet-utility", Technology: "browser-based",
		Risk: 4, PortUsage: "standard", Status: "identified"}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<14 {
			return
		}
		policy, err := FromJSON(data, pack)
		if err != nil || policy == nil {
			return
		}
		decision := policy.Evaluate(verdict, "tcp", 80, true, nil, "")
		if decision.Action == "" {
			t.Fatalf("a parsed policy gave no action: %q", data)
		}
		_ = decision.Fields()
	})
}
