package replay

import (
	"encoding/json"
	"testing"
)

// PRO-166 / SEC-PAR-2: compare.py is strict on the JSON leaf type, so the replay must keep Python's
// int/float distinction in session records: the reference writes a float capture time 40.0 as 40.0 and the
// integer clock 0 as 0, where encoding/json would write both float64 values without a fractional part.
func TestSessionRecordsKeepPythonNumberTypes(t *testing.T) {
	result := SessionResultFull{Packets: []PacketResult{}, Records: []map[string]interface{}{{
		"start": 0, "end": 40.0, "decision": map[string]interface{}{"first_seconds": 0.0, "stable_seconds": 0.25},
		"handshake_observed": true, "app": "web-browsing",
	}}}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"packets":[],"records":[{"app":"web-browsing","decision":{"first_seconds":0.0,"stable_seconds":0.25},"end":40.0,"handshake_observed":true,"start":0}]}`
	if string(raw) != want {
		t.Fatalf("got  %s\nwant %s", raw, want)
	}
	empty, err := json.Marshal(SessionResultFull{Packets: []PacketResult{}})
	if err != nil || string(empty) != `{"packets":[],"records":[]}` {
		t.Fatalf("empty records: %s %v", empty, err)
	}
}
