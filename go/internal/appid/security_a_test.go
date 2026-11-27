package appid

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// SR-69: structured unknown reasons are a closed vocabulary (exactly these codes, each in one of five stages),
// derived after the fact: explaining an observation never changes it, an identification carries none, and every
// code Explain or SessionUnknown returns is in the vocabulary.
func TestSecurityUnknownReasonsAreClosedAndDerived(t *testing.T) {
	codes := []string{"ambiguous", "budget", "incomplete", "invalidated", "malformed", "midstream", "no-dispatch", "no-handshake", "no-payload", "profile-unsupported"}
	var got []string
	stageSet := map[string]bool{}
	for code, stage := range stages {
		got = append(got, code)
		stageSet[stage] = true
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, codes) {
		t.Fatalf("codes %v, want %v", got, codes)
	}
	if want := map[string]bool{"dispatch": true, "profile": true, "budget": true, "lifecycle": true, "integrity": true}; !reflect.DeepEqual(stageSet, want) {
		t.Fatalf("stages %v", stageSet)
	}
	wantStage := map[string]string{"no-dispatch": "dispatch", "ambiguous": "dispatch", "profile-unsupported": "profile", "malformed": "profile",
		"budget": "budget", "no-payload": "lifecycle", "incomplete": "lifecycle", "no-handshake": "lifecycle", "midstream": "lifecycle", "invalidated": "integrity"}
	inputs := []*contracts.Observation{
		status(contracts.Unknown, "Prefix outside supported protocol families"),
		status(contracts.Unknown, "Ambiguous text line"),
		status(contracts.Unknown, "outside the profile"),
		status(contracts.Malformed, "Invalid header name"),
		status(contracts.BudgetExhausted, "Byte budget exhausted"),
		status(contracts.Incomplete, "fin"),
		status(contracts.Invalidated, "conflict"),
		status(contracts.Detecting, "Waiting for stream prefix"),
		{Status: contracts.Unknown, Transport: "tcp", Reason: "x", Evidence: []contracts.Evidence{{Field: "ambiguous_candidates", Value: "ftp,pop3", Source: "wire", Strength: "context"}}},
	}
	for _, o := range inputs {
		for _, facts := range []DirectionFacts{{}, {Known: true, ResolvedFamily: "http", BytesReceived: 9}, {Known: true}} {
			before, _ := json.Marshal(o)
			out := Explain(o, facts)
			if after, _ := json.Marshal(o); string(before) != string(after) {
				t.Fatalf("Explain changed the observation: %s -> %s", before, after)
			}
			code, _ := out["code"].(string)
			if out == nil || wantStage[code] == "" || out["stage"] != wantStage[code] {
				t.Fatalf("%q: explained as %+v", o.Reason, out)
			}
		}
	}
	if Explain(identifiedHTTP("a.example"), DirectionFacts{Known: true, ResolvedFamily: "http", BytesReceived: 30}) != nil {
		t.Fatal("an identification carries a structured reason")
	}
	v := &Verdict{Status: "unknown", Reasons: []string{"x"}}
	before, _ := json.Marshal(v)
	for _, mode := range []string{"handshake", "midstream"} {
		u := SessionUnknown(v, inputs[0], inputs[3], DirectionFacts{Known: true, BytesReceived: 3}, DirectionFacts{Known: true, BytesReceived: 3}, mode, false)
		for _, side := range []string{"session", "client", "server"} {
			if item, ok := u[side].(map[string]interface{}); ok && wantStage[item["code"].(string)] != item["stage"] {
				t.Fatalf("%s: %+v", side, item)
			}
		}
	}
	if after, _ := json.Marshal(v); string(before) != string(after) {
		t.Fatalf("SessionUnknown changed the verdict: %s -> %s", before, after)
	}
}

// SR-30: every risk name the flow-risk derivation can emit is in the content pack's risk catalog with a severity
// of low, medium or high and a description, and every catalog risk is documented in RISKS.md.
func TestSecurityRiskNamesAreCatalogedAndDocumented(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../../RISKS.md")
	if err != nil {
		t.Fatal(err)
	}
	emitted := map[string]bool{}
	pattern := regexp.MustCompile(`append\((?:found|out)((?:, "[a-z0-9-]+")+)\)`)
	literal := regexp.MustCompile(`"([a-z0-9-]+)"`)
	for _, name := range []string{"risks.go", "appid.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range pattern.FindAllStringSubmatch(string(source), -1) {
			for _, name := range literal.FindAllStringSubmatch(m[1], -1) {
				emitted[name[1]] = true
			}
		}
	}
	if len(emitted) < 40 {
		t.Fatalf("only %d emitted risk names found; the derivation moved", len(emitted))
	}
	for name := range emitted {
		risk, ok := pack.Risks[name]
		if !ok {
			t.Fatalf("risk %q is emitted but not in the risk catalog", name)
		}
		if risk.Severity != "low" && risk.Severity != "medium" && risk.Severity != "high" || strings.TrimSpace(risk.Description) == "" {
			t.Fatalf("risk %q: severity %q description %q", name, risk.Severity, risk.Description)
		}
	}
	for name := range pack.Risks {
		if !strings.Contains(string(doc), "`"+name+"`") {
			t.Fatalf("catalog risk %q is not documented in RISKS.md", name)
		}
	}
	// A Telnet negotiation on a non-standard port raises exactly the documented structural risks.
	telnet := &contracts.Observation{Status: contracts.Identified, Transport: "tcp", ApplicationProtocol: str("telnet"),
		Evidence: []contracts.Evidence{{Field: "application_protocol", Value: "telnet", Source: "wire", Strength: "structural"}}}
	v := SessionVerdict(pack, telnet, nil, "tcp", 2323, true, Bytes{6, true}, Bytes{}, true)
	if strings.Join(v.Risks, ",") != "cleartext-credential-protocol,nonstandard-port,obsolete-protocol" {
		t.Fatalf("telnet on 2323: %v", v.Risks)
	}
}
