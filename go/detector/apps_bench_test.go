package detector

import "testing"

// appBenchRequests are the three requests of the Culvert lab's BenchmarkRealAppsClassify (PRO-504): a child
// match, a parent-only match and an unowned host.
var appBenchRequests = []struct {
	name string
	req  HTTPRequest
}{
	{"child", HTTPRequest{SNI: "gmail.googleapis.com", Host: "gmail.googleapis.com", Method: "POST",
		Path: "/upload/gmail/v1/users/me/messages?uploadType=media", ContentType: "message/rfc822", RequestBodyBytes: 16,
		HeaderNames: []string{"Content-Type", "Content-Length"}}},
	{"parent", HTTPRequest{SNI: "gmail.googleapis.com", Host: "gmail.googleapis.com", Method: "POST",
		Path: "/gmail/v1/users/me/labels", RequestBodyBytes: 16, HeaderNames: []string{"Content-Length"}}},
	{"unowned", HTTPRequest{SNI: "unowned.example", Host: "unowned.example", Method: "POST", Path: "/upload",
		RequestBodyBytes: 16, HeaderNames: []string{"Content-Length"}}},
}

// BenchmarkAppClassifierClassify is the library's per-request cost of AppClassifier.Classify, the wrapper's
// recover included, on the requests of the Culvert lab benchmark.
func BenchmarkAppClassifierClassify(b *testing.B) {
	c, err := NewAppClassifier(AppLimitsConfig{})
	if err != nil {
		b.Fatal(err)
	}
	for _, q := range appBenchRequests {
		b.Run(q.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = c.Classify(q.req)
			}
		})
	}
}

// TestAppClassifierAllocationCeilings is the library-side floor for Culvert's per-request benchgate (PRO-522):
// a child match costs at most 8 allocations, a parent-only match 4 and an unowned host 2. Measured after PRO-522:
// 1 each (the verdict's own Reasons slice); before it, 14, 7 and 4.
func TestAppClassifierAllocationCeilings(t *testing.T) {
	c, err := NewAppClassifier(AppLimitsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		app, basis string
		ceiling    float64
	}{
		"child":   {"gmail-uploading", "request_rule", 8},
		"parent":  {"google-base", "server_name", 4},
		"unowned": {"", "none", 2},
	}
	for _, q := range appBenchRequests {
		w := want[q.name]
		if v := c.Classify(q.req); v.App != w.app || v.Basis != w.basis || len(v.Reasons) != 1 {
			t.Fatalf("%s: the benchmark request is not a %s case: %+v", q.name, q.name, v)
		}
		got := testing.AllocsPerRun(200, func() { _ = c.Classify(q.req) })
		t.Logf("%s: %.0f allocations per request (ceiling %.0f)", q.name, got, w.ceiling)
		if got > w.ceiling {
			t.Errorf("%s: %.0f allocations per request, over the ceiling of %.0f", q.name, got, w.ceiling)
		}
	}
}

// TestAppVerdictReasonsAreNotShared: every verdict owns its Reasons slice, so a caller that edits one never
// changes another (no package-level slice behind the single allocation).
func TestAppVerdictReasonsAreNotShared(t *testing.T) {
	c, err := NewAppClassifier(AppLimitsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range appBenchRequests {
		a, b := c.Classify(q.req), c.Classify(q.req)
		want := a.Reasons[0]
		a.Reasons[0] = "edited"
		if b.Reasons[0] != want || c.Classify(q.req).Reasons[0] != want {
			t.Fatalf("%s: Reasons shared between verdicts", q.name)
		}
	}
}
