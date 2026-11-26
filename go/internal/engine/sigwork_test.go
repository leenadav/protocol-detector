package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/signatures"
)

// pro170Set is the PRO-170 flow-cost shape: n unknown-payload signatures whose anchor the attacker sends first
// and whose `.{0,4096}` tail never completes, so every update searches the whole buffer with every program.
func pro170Set(t testing.TB, n int, tail string) *signatures.Set {
	t.Helper()
	pack, err := content.Load("../../../migration/fixtures/content.json")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name": "s%d", "conditions": [{"context": "unknown-req-tcp-payload", "pattern": "abcdefg.{0,4096}%s%d"}]}`, i, tail, i)
	}
	b.WriteString("]")
	set, err := signatures.FromJSON([]byte(b.String()), pack)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// oneByteFlow feeds the anchor after a prefix dispatch cannot route, then single bytes until the direction is
// terminal or limit updates were fed.
func oneByteFlow(t testing.TB, set *signatures.Set, signatureBytes, limit int, filler byte) (*Inspector, int, time.Duration) {
	t.Helper()
	cfg := retaining()
	cfg.SignatureBytes, cfg.MaxUpdates = signatureBytes, 1000000
	in, err := New(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := in.SetSignatures(set); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	in.Feed([]byte("\x00\x00\x00\x00abcdefg"))
	updates := 1
	for !in.terminal && updates < limit {
		in.Feed([]byte{filler})
		updates++
	}
	return in, updates, time.Since(start)
}

// TestUnknownPayloadSignatureWorkIsBounded reproduces the PRO-170 edge case (1-byte updates, `.{0,4096}`, a
// full 100,000-instruction set): without the budget one such flow costs Σ L x 98,000 units over every buffer length
// L (43 s for a single signature at the defaults, about 38 hours at signature_bytes 65536); with it the direction
// ends budget_exhausted within its allowance (two full-buffer evaluations), never identified.
func TestUnknownPayloadSignatureWorkIsBounded(t *testing.T) {
	set := pro170Set(t, 12, "Z") // 12 x about 8,205 instructions: the set cap allows no 13th
	in, updates, elapsed := oneByteFlow(t, set, 2000, 5000, 'x')
	o := in.Observation
	t.Logf("%d updates, %d of %d work units, %v", updates, in.sigWork.Used, in.sigWork.Limit, elapsed)
	full := 2000*(set.WorkPerByte("unknown-tcp")+1) + set.WorkPerEvaluation("unknown-tcp") // +1: the copy
	if want := int64(SignatureWorkEvaluations) * full; want <= MaxSignatureWork || want <= MaxSignatureWorkCeiling || in.sigWork.Limit != MaxSignatureWorkCeiling {
		t.Fatalf("limit %d, want the ceiling (two full evaluations: %d)", in.sigWork.Limit, want)
	}
	if o.Status != contracts.BudgetExhausted || o.Reason != "Signature work budget exhausted" || o.Application != nil {
		t.Fatalf("observation %+v after %d updates", o, updates)
	}
	if !in.sigWork.Exhausted || in.sigWork.Used > in.sigWork.Limit || updates > 400 {
		t.Fatalf("work %+v after %d updates", in.sigWork, updates)
	}
	if !in.terminal || in.unknown != nil {
		t.Fatalf("direction still collecting: terminal %v, %d buffered", in.terminal, len(in.unknown))
	}
	// Terminal: later bytes do no signature work.
	used := in.sigWork.Used
	in.Feed([]byte("Z0"))
	if in.sigWork.Used != used || in.Observation.Status != contracts.BudgetExhausted {
		t.Fatalf("work after the end: %d -> %d, %s", used, in.sigWork.Used, in.Observation.Status)
	}
	// A small set keeps the MaxSignatureWork floor.
	if small := pro170Set(t, 1, "Z"); signatureWorkLimit(small, 2000) != MaxSignatureWork {
		t.Fatalf("floor: %d", signatureWorkLimit(small, 2000))
	}
}

// An exhausted budget is never a positive result: the byte that would complete a match arrives after the budget
// is spent, so the direction stays budget_exhausted instead of naming the application.
func TestExhaustedSignatureWorkNeverMatches(t *testing.T) {
	set := pro170Set(t, 12, "Z")
	in, _, _ := oneByteFlow(t, set, 2000, 5000, 'x')
	in.Feed([]byte("Z0"))
	if in.Observation.Application != nil || in.Observation.Status == contracts.Identified {
		t.Fatalf("matched after exhaustion: %+v", in.Observation)
	}
}

// Below the budget nothing changes: with the matching byte sent early the flow is identified as without a
// budget; a 1-byte flow with a small set still ends unknown when its buffer is full; and one full-buffer segment
// of the largest set the caps allow is evaluated, not refused (the reference's verdicts).
func TestSignatureWorkBelowTheBudgetKeepsTheReferenceVerdict(t *testing.T) {
	set := pro170Set(t, 2, "Z")
	in, err := New(retaining(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := in.SetSignatures(set); err != nil {
		t.Fatal(err)
	}
	in.Feed([]byte("\x00\x00\x00\x00abcdefg"))
	for i := 0; i < 50; i++ {
		in.Feed([]byte("x"))
	}
	in.Feed([]byte("Z1"))
	if o := in.Observation; o.Status != contracts.Identified || o.Application == nil || *o.Application != "s1" || in.sigWork.Exhausted {
		t.Fatalf("early match: %+v, work %+v", o, in.sigWork)
	}
	in, updates, _ := oneByteFlow(t, testSet(t), 2000, 5000, 'x')
	if o := in.Observation; o.Status != contracts.Unknown || in.sigWork.Exhausted {
		t.Fatalf("full buffer after %d updates: %+v, work %+v", updates, o, in.sigWork)
	}
	t.Logf("default signature_bytes, test set, 1-byte updates to a full buffer: %d units", in.sigWork.Used)
	in, err = New(retaining(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := in.SetSignatures(pro170Set(t, 12, "Z")); err != nil {
		t.Fatal(err)
	}
	in.Feed(append([]byte("\x00\x00\x00\x00abcdefg"), strings.Repeat("x", 2000)...))
	if o := in.Observation; o.Status != contracts.Unknown || in.sigWork.Exhausted {
		t.Fatalf("one full segment: %+v, work %+v", o, in.sigWork)
	}
}

// The engine's own signature tests stay well inside the budget (the margin the constant documents).
func TestSignatureWorkOfTheTestSetIsSmall(t *testing.T) {
	in := signedStream(t, testSet(t), append(make([]byte, 300), "PROBE-v1"...), "fin")
	if in.sigWork.Exhausted || in.sigWork.Used == 0 || in.sigWork.Used > MaxSignatureWork/1000 {
		t.Fatalf("work %+v", in.sigWork)
	}
}

// PRO-370 (Codex PRO-369, P2): a document of length-only conditions has no byte-valued condition, so before the
// fix it cost no work at all and every 1-byte update ran all of them (4,096 signatures x 12 conditions, up to
// 65,536 updates). Each condition and each candidate slot is charged now: the direction ends budget_exhausted.
func TestLengthOnlySignatureWorkIsBounded(t *testing.T) {
	pack, err := content.Load("../../../migration/fixtures/content.json")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 4096; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name":"n%d","conditions":{"or":[`, i)
		for j := 0; j < 12; j++ {
			if j > 0 {
				b.WriteString(",")
			}
			b.WriteString(`{"context":"unknown-req-tcp-payload-length","operator":"equal-to","value":1}`)
		}
		b.WriteString("]}}")
	}
	b.WriteString("]")
	set, err := signatures.FromJSON([]byte(b.String()), pack)
	if err != nil {
		t.Fatal(err)
	}
	in, updates, elapsed := oneByteFlow(t, set, 65536, 1000, 'x')
	t.Logf("%d updates, %d of %d work units, %v", updates, in.sigWork.Used, in.sigWork.Limit, elapsed)
	if o := in.Observation; o.Status != contracts.BudgetExhausted || o.Application != nil || !in.terminal {
		t.Fatalf("after %d updates: %+v, work %+v", updates, o, in.sigWork)
	}
	if per := set.WorkPerEvaluation("unknown-tcp"); per != signatures.FixedWork*4096*(1+12) || in.sigWork.Limit != MaxSignatureWork {
		t.Fatalf("per evaluation %d, limit %d", per, in.sigWork.Limit)
	}
}

// PRO-370 (Codex PRO-369, P2): the allowance scaled with the configured buffer and set without a ceiling, so one
// direction could still take tens of seconds (signature_bytes 65536, a full set). It is capped at
// MaxSignatureWorkCeiling; past the ceiling even a single full segment ends budget_exhausted (a recorded Go-only
// divergence), never a match.
func TestSignatureWorkAllowanceHasACeiling(t *testing.T) {
	set := pro170Set(t, 12, "Z")
	if got := signatureWorkLimit(set, 65536); got != MaxSignatureWorkCeiling {
		t.Fatalf("limit at signature_bytes 65536: %d, want the ceiling %d", got, int64(MaxSignatureWorkCeiling))
	}
	if MaxSignatureWorkCeiling < MaxSignatureWork {
		t.Fatal("ceiling below the floor")
	}
	cfg := retaining()
	cfg.SignatureBytes = 65536
	in, err := New(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := in.SetSignatures(set); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	in.Feed(append([]byte("\x00\x00\x00\x00abcdefg"), strings.Repeat("x", 65536)...))
	t.Logf("one 65536-byte segment: %d of %d units, %v", in.sigWork.Used, in.sigWork.Limit, time.Since(start))
	if o := in.Observation; o.Status != contracts.BudgetExhausted || o.Application != nil || in.sigWork.Used > MaxSignatureWorkCeiling {
		t.Fatalf("%+v, work %+v", o, in.sigWork)
	}
}

// PRO-370: each evaluation copies the whole unknown buffer into its contexts, so a cheap set (one length-only
// condition) left a quadratic copy uncharged: up to 65,536 updates of up to 64 KiB each. The copy is charged
// before it is made, so the work used covers at least every buffered byte copied.
func TestUnknownPayloadCopyIsCharged(t *testing.T) {
	pack, err := content.Load("../../../migration/fixtures/content.json")
	if err != nil {
		t.Fatal(err)
	}
	set, err := signatures.FromJSON([]byte(`[{"name": "n", "conditions": [
		{"context": "unknown-req-tcp-payload-length", "operator": "equal-to", "value": 1}]}]`), pack)
	if err != nil {
		t.Fatal(err)
	}
	in, updates, _ := oneByteFlow(t, set, 65536, 300, 'x')
	if copied := int64(updates) * int64(updates-1) / 2; in.sigWork.Used < copied {
		t.Fatalf("%d updates: %d units used, below the %d bytes copied", updates, in.sigWork.Used, copied)
	}
	if full := int64(65536)*(set.WorkPerByte("unknown-tcp")+1) + set.WorkPerEvaluation("unknown-tcp"); signatureWorkLimit(set, 65536) < 2*full {
		t.Fatalf("allowance %d below two full evaluations with their copy (%d)", signatureWorkLimit(set, 65536), 2*full)
	}
}
