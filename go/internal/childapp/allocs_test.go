package childapp

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// The references below are the request-side helpers as they were before PRO-522 (origin/main 8296a26), kept
// verbatim so the allocation-free rewrites are pinned to the same answers on every input.

func refNormalizeHost(h string) (string, bool) {
	if len(h) > maxHostBytes+7 {
		return "", false
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		port := h[i+1:]
		if port == "" || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
			return "", false
		}
		h = h[:i]
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" || len(h) > maxHostBytes || !strings.Contains(h, ".") {
		return "", false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	return h, true
}

func refCanonicalPath(p string) (string, bool) {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" || p[0] != '/' {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c <= ' ' || c >= 0x7f || c == '\\' {
			return "", false
		}
		if c == '%' {
			if i+2 >= len(p) {
				return "", false
			}
			switch strings.ToLower(p[i+1 : i+3]) {
			case "2f", "5c", "2e", "00", "25":
				return "", false
			}
		}
	}
	if p == "/" {
		return p, true
	}
	if strings.Contains(p, "/./") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..") {
		return "", false
	}
	if strings.Contains(p, "//") {
		return "", false
	}
	return decodeSafe(p), true
}

func refParseQuery(target string) (map[string][]string, bool) {
	i := strings.IndexByte(target, '?')
	if i < 0 {
		return nil, true
	}
	q := target[i+1:]
	if j := strings.IndexByte(q, '#'); j >= 0 {
		q = q[:j]
	}
	out := map[string][]string{}
	pairs := 0
	for _, pair := range strings.Split(q, "&") {
		if pair == "" {
			continue
		}
		if pairs++; pairs > maxQueryPairs {
			return nil, false
		}
		k, v, _ := strings.Cut(pair, "=")
		out[k] = append(out[k], v)
	}
	return out, true
}

func refSplitPath(path string) (int, []string) {
	t := strings.TrimPrefix(path, "/")
	return strings.Count(t, "/") + 1, strings.SplitN(t, "/", MaxPatternSegment+1)
}

// randomField draws a string over the bytes the helpers branch on, with upper case and the non-ASCII runes that
// strings.ToLower maps to ASCII letters (U+212A, U+0130).
func randomField(rng *rand.Rand, max int) string {
	atoms := []string{"a", "b", "z", "A", "Z", "0", "9", "-", ".", ":", "/", "%", "2", "5", "e", "E", "f", "F", "c", "C",
		"?", "#", "&", "=", "\\", " ", "K", "İ", "é", "\xff", "k", "K", "..", "//", "%2f", "%2E", "%5c", "%25",
		"%00", "%41", "%7e", "content-type", "Content-Length", "x", "443"}
	n := rng.Intn(max + 1)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(atoms[rng.Intn(len(atoms))])
	}
	return b.String()
}

func checkHelpersMatchReference(t *testing.T, s string) {
	t.Helper()
	if got, ok := normalizeHost(s); true {
		want, wantOK := refNormalizeHost(s)
		if got != want || ok != wantOK {
			t.Fatalf("normalizeHost(%q) = %q, %v; reference %q, %v", s, got, ok, want, wantOK)
		}
	}
	if got, ok := canonicalPath(s); true {
		want, wantOK := refCanonicalPath(s)
		if got != want || ok != wantOK {
			t.Fatalf("canonicalPath(%q) = %q, %v; reference %q, %v", s, got, ok, want, wantOK)
		}
	}
	m, within := refParseQuery(s)
	q := rawQuery(s)
	if queryWithinLimit(q) != within {
		t.Fatalf("queryWithinLimit(%q) = %v, reference %v", q, !within, within)
	}
	if within {
		keys := []string{"", "a", "uploadType", "k", "K", "x=y"}
		for k := range m {
			keys = append(keys, k)
		}
		for _, k := range keys {
			v, n := queryValue(q, k)
			ref := m[k]
			if (n == 1) != (len(ref) == 1) || n == 1 && v != ref[0] || n > 2 || (n == 0) != (len(ref) == 0) {
				t.Fatalf("queryValue(%q, %q) = %q, %d; reference %q", q, k, v, n, ref)
			}
		}
	}
	for _, h := range []string{"content-type", "k", "x", "a-b", strings.ToLower(s)} {
		if got, want := headerIs(s, h), strings.ToLower(s) == h; got != want {
			t.Fatalf("headerIs(%q, %q) = %v, reference %v", s, h, got, want)
		}
	}
	if p := "/" + s; true {
		ps := splitPath(p)
		n, segs := refSplitPath(p)
		if ps.n != n || len(segs) > len(ps.segs) {
			t.Fatalf("splitPath(%q): n %d, reference %d", p, ps.n, n)
		}
		for i := range segs {
			if ps.segs[i] != segs[i] {
				t.Fatalf("splitPath(%q) segment %d = %q, reference %q", p, i, ps.segs[i], segs[i])
			}
		}
	}
}

// TestRequestHelpersMatchReference: the PRO-522 helpers give the pre-PRO-522 answers on 200,000 random fields.
func TestRequestHelpersMatchReference(t *testing.T) {
	rng := rand.New(rand.NewSource(522))
	for i := 0; i < 200000; i++ {
		checkHelpersMatchReference(t, randomField(rng, 24))
	}
	for _, s := range []string{"", "Gmail.GoogleAPIs.com", "exaKmple.com", "İndia.example", "a.b:", "a.b:443",
		"A.B.", "a..b", "-a.b", strings.Repeat("a", 63) + ".b", strings.Repeat("a", 64) + ".b", "/x?a=1&a=2", "/x?a&b=",
		"/x#f?a=1", "/x?" + strings.Repeat("a=1&", maxQueryPairs) + "b", "/x?" + strings.Repeat("&", 200),
		"/" + strings.Repeat("s/", MaxPatternSegment+5), "Content-Type", "CONTENT-TYPE", "Key"} {
		checkHelpersMatchReference(t, s)
	}
}

// FuzzRequestHelpersMatchReference is the same comparison on fuzzed fields.
func FuzzRequestHelpersMatchReference(f *testing.F) {
	for _, s := range []string{"Gmail.GoogleAPIs.com:443", "exaKmple.com", "/upload/x?uploadType=media&a", "/a%2F%5c",
		"X-Goog-Upload-Protocol"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { checkHelpersMatchReference(t, s) })
}

// TestClassifyIsEvaluateWithReasons: Classify is Evaluate plus Reasons == []string{Reason}, rule ids are those
// the matcher used to format per request, and Verdict reads either form.
func TestClassifyIsEvaluateWithReasons(t *testing.T) {
	s := embeddedSet(t)
	for _, r := range s.rules {
		if r.id != fmt.Sprintf("%s#%d", r.child.Name, r.index) {
			t.Fatalf("rule id %q", r.id)
		}
	}
	rng := rand.New(rand.NewSource(5220))
	hosts := []string{"gmail.googleapis.com", "graph.microsoft.com", "content.dropboxapi.com", "www.googleapis.com",
		"unowned.example", "GMAIL.googleapis.com.", "api.telegram.org", "discord.com"}
	for i := 0; i < 20000; i++ {
		req := Request{SNI: hosts[rng.Intn(len(hosts))], Host: hosts[rng.Intn(len(hosts))], Method: []string{"GET", "POST", "PUT"}[rng.Intn(3)],
			Path: "/" + randomField(rng, 8), ContentType: []string{"", "message/rfc822", "Application/JSON; x=1"}[rng.Intn(3)],
			RequestBodyBytes: int64(rng.Intn(40) - 5), ResponseBodyBytes: int64(rng.Intn(40) - 5), WebSocket: rng.Intn(2) == 0,
			HeaderNames: []string{"Content-Type", "X-Goog-Upload-Protocol", "Key"}[:rng.Intn(4)]}
		if rng.Intn(2) == 0 {
			req.SNI = req.Host
		}
		c := s.Classify(req)
		e := s.Evaluate(&req)
		if e.Reasons != nil || len(c.Reasons) != 1 || c.Reasons[0] != c.Reason || c.Reason != e.Reason || e.Reason == "" {
			t.Fatalf("%+v: Classify %+v, Evaluate %+v", req, c, e)
		}
		e.Reasons = c.Reasons
		if fmt.Sprint(c) != fmt.Sprint(e) {
			t.Fatalf("%+v: Classify %+v, Evaluate %+v", req, c, e)
		}
		vc, _ := json.Marshal(s.Verdict(c))
		ve, _ := json.Marshal(s.Verdict(s.Evaluate(&req)))
		if string(vc) != string(ve) {
			t.Fatalf("%+v: verdicts differ", req)
		}
	}
}

// TestEvaluateAllocatesNothing: the matcher itself allocates nothing for an ordinary request, child, parent or
// unowned (PRO-522); only an upper-case host or a case-folded upper-case path pays for its lower-cased copy.
func TestEvaluateAllocatesNothing(t *testing.T) {
	s := embeddedSet(t)
	for _, req := range []Request{
		{SNI: "gmail.googleapis.com", Host: "gmail.googleapis.com", Method: "POST",
			Path: "/upload/gmail/v1/users/me/messages?uploadType=media", ContentType: "message/rfc822", RequestBodyBytes: 16,
			HeaderNames: []string{"Content-Type", "Content-Length"}},
		{SNI: "gmail.googleapis.com", Host: "gmail.googleapis.com", Method: "POST", Path: "/gmail/v1/users/me/labels",
			RequestBodyBytes: 16, HeaderNames: []string{"Content-Length"}},
		{SNI: "unowned.example", Host: "unowned.example", Method: "POST", Path: "/upload", RequestBodyBytes: 16},
		{Host: "graph.microsoft.com", Method: "POST", Path: "/v1.0/me/sendmail", ContentType: "application/json", RequestBodyBytes: 90},
	} {
		req := req
		if got := testing.AllocsPerRun(200, func() { s.Evaluate(&req) }); got != 0 {
			t.Errorf("%s %s: %.0f allocations", req.Host, req.Path, got)
		}
	}
	// Graph's rules match the path case-insensitively: an upper-case path costs its one lower-cased copy, made
	// once per request however many such rules are evaluated.
	req := Request{Host: "graph.microsoft.com", Method: "POST", Path: "/v1.0/me/sendMail", ContentType: "application/json",
		RequestBodyBytes: 90}
	if got := s.Evaluate(&req); got.App != "outlook-sending" {
		t.Fatalf("got %+v", got)
	}
	if got := testing.AllocsPerRun(200, func() { s.Evaluate(&req) }); got != 1 {
		t.Errorf("graph sendMail: %.0f allocations, want 1", got)
	}
	// Gmail has no case-insensitive rule: an upper-case path there is never lower-cased.
	req = Request{Host: "gmail.googleapis.com", Method: "POST", Path: "/gmail/v1/users/Me/labels", RequestBodyBytes: 16}
	if got := testing.AllocsPerRun(200, func() { s.Evaluate(&req) }); got != 0 {
		t.Errorf("gmail upper-case path: %.0f allocations", got)
	}
}
