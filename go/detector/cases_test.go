package detector

import (
	"context"
	"encoding/hex"
	"sort"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/parity"
)

// TestFacadeMatchesTheEngineOnEveryStreamCase feeds every unhinted stream case of the shared fixtures
// (migration/fixtures/cases.json) through a Flow and through a bare engine Inspector, and checks that the
// facade reports what the engine decided: the same status, protocol, encryption, hostname, offered ALPN and
// revision, or outside_profile / unsupported exactly when the engine attributed the stream to a family
// outside the profile or could not answer. It also records which evidence fields the profile families
// produce, for TestProfileEvidenceFieldsAreClassified.
func TestFacadeMatchesTheEngineOnEveryStreamCase(t *testing.T) {
	doc, err := parity.Load(context.Background(), "../../migration/fixtures/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	compared, outside, unsupported := 0, 0, 0
	for i := range doc.Cases {
		c := &doc.Cases[i]
		if c.Kind != "stream" || c.Hint != nil {
			continue
		}
		in, err := engine.New(c.Config, "")
		if err != nil {
			continue // options the Go backend does not port
		}
		e := mustEngine(t, allFamilies())
		e.cfg = c.Config // the case's own budgets, so both sides inspect the same bytes
		f := mustFlow(t, e)
		var revision int
		for _, chunk := range c.Chunks {
			data, _ := hex.DecodeString(chunk)
			for _, ev := range in.Feed(data) {
				revision = ev.Revision
			}
			if _, err := f.Feed(ClientToServer, data); err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			if in.NotPorted != nil {
				break
			}
		}
		if c.End != nil && in.NotPorted == nil {
			for _, ev := range in.End(*c.End) {
				revision = ev.Revision
			}
			f.EndDirection(ClientToServer, EndEOF)
		}
		got := f.Close().Direction(ClientToServer)
		family := in.ResolvedFamily()
		switch {
		case in.NotPorted != nil:
			unsupported++
			if got.Outcome != OutcomeUnsupported || got.Reason != ReasonNotPorted {
				t.Errorf("%s: engine not ported (%s), facade %s/%s", c.ID, in.NotPorted.What, got.Outcome, got.Reason)
			}
		case family != "" && !e.profile[family]:
			outside++
			if got.Outcome != OutcomeOutsideProfile || got.Family != family {
				t.Errorf("%s: family %s outside the profile, facade %s %q", c.ID, family, got.Outcome, got.Family)
			}
		default:
			compared++
			o := in.Observation
			if string(got.Outcome) != string(o.Status) || got.ApplicationProtocol != deref(o.ApplicationProtocol) ||
				got.Encryption != deref(o.Encryption) || string(got.Hostname) != deref(o.Hostname) ||
				len(got.OfferedALPN) != len(o.OfferedALPN) || (revision > 0 && got.Revision != revision) {
				t.Errorf("%s: facade %+v\nengine %+v (revision %d)", c.ID, got, o, revision)
			}
			if got.Outcome == OutcomeIdentified && got.Family != family {
				t.Errorf("%s: family %q, engine %q", c.ID, got.Family, family)
			}
			if got.Outcome == OutcomeIdentified {
				for _, ev := range o.Evidence {
					profileFields[ev.Field] = append(profileFields[ev.Field], c.ID)
				}
			}
		}
	}
	if compared < 200 || outside < 500 {
		t.Fatalf("too few cases exercised: compared %d, outside profile %d, unsupported %d", compared, outside, unsupported)
	}
	t.Logf("stream cases: %d compared, %d outside the profile, %d not ported", compared, outside, unsupported)
}

// profileFields collects evidence fields seen on identified profile-family cases (filled by the test above).
var profileFields = map[string][]string{}

// TestProfileEvidenceFieldsAreClassified fails when a family admitted to profiles emits an evidence field
// that evidence.go does not classify: its value would be withheld silently.
func TestProfileEvidenceFieldsAreClassified(t *testing.T) {
	if len(profileFields) == 0 {
		TestFacadeMatchesTheEngineOnEveryStreamCase(t)
	}
	var fields []string
	for field := range profileFields {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		if classify(field) == ClassWithheld {
			t.Errorf("profile evidence field %q is not classified (e.g. case %s)", field, profileFields[field][0])
		}
	}
	if len(fields) < 10 {
		t.Fatalf("only %d profile evidence fields seen: %v", len(fields), fields)
	}
}
