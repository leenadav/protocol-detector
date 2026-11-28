package childapp

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// SEC-CHILD-4: path patterns used to re-split the path once per pattern, so one 4 KiB request cost hundreds of
// microseconds on Graph and tens of megabytes in the worst case the loader accepted. The path is now split once
// per request, a pattern rejects on the segment count first, and the loader caps the patterns per host.

// referenceMatch is the pre-SEC-CHILD-4 matcher, kept as the oracle for the split-once matcher.
func referenceMatch(pattern []segment, path string) bool {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, p := range pattern {
		if p.kind == segRest {
			return true
		}
		if i >= len(segments) {
			return false
		}
		switch p.kind {
		case segAny:
			if segments[i] == "" {
				return false
			}
		case segLiteral:
			if p.lits[0] != segments[i] {
				return false
			}
		case segTemplate:
			if !matchTemplate(p.lits, segments[i]) {
				return false
			}
		}
	}
	return len(segments) == len(pattern)
}

func TestSplitOnceMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	pieces := []string{"a", "b", "*", "{x}", "a{x}", "{x}b", "a{x}b"}
	words := []string{"a", "b", "ab", "axb", "", "aab"}
	checked := 0
	for i := 0; i < 4000; i++ {
		n := 1 + rng.Intn(MaxPatternSegment)
		parts := make([]string, n)
		for j := range parts {
			parts[j] = pieces[rng.Intn(len(pieces))]
		}
		if n > 1 && rng.Intn(3) == 0 {
			parts[n-1] = "**"
		}
		pattern, err := parsePattern("/" + strings.Join(parts, "/"))
		if err != nil {
			t.Fatalf("%v: %v", parts, err)
		}
		for k := 0; k < 8; k++ {
			// Around the pattern's own length, and past MaxPatternSegment+1 so the unsplit rest is exercised.
			m := n - 2 + rng.Intn(5)
			if k == 7 {
				m = MaxPatternSegment + 1 + rng.Intn(40)
			}
			if m < 1 {
				m = 1
			}
			segs := make([]string, m)
			for j := range segs {
				if j < n && parts[j] == "a" || parts[0] == "a" && j == 0 {
					segs[j] = "a"
				} else {
					segs[j] = words[rng.Intn(len(words))]
				}
			}
			path := "/" + strings.Join(segs, "/")
			ps := splitPath(path)
			if got, want := matchPattern(pattern, &ps), referenceMatch(pattern, path); got != want {
				t.Fatalf("pattern %v on %q: got %v, reference %v", parts, path, got, want)
			}
			checked++
		}
	}
	if checked < 30000 {
		t.Fatalf("only %d cases", checked)
	}
}

// patternChildren builds children on content.dropboxapi.com (or under the dropboxapi.com suffix) holding total
// distinct path patterns of 32 segments each, near misses for a path of 'a' segments: the last segment is "b"
// for the first pattern and "b<k>" for the others.
func patternChildren(total int, suffix bool) string {
	var b strings.Builder
	b.WriteString(header)
	near := "/" + strings.Repeat("a/", MaxPatternSegment-1) + "b"
	k := 0
	for i := 0; total > 0; i++ {
		n := total
		if n > MaxListEntries {
			n = MaxListEntries
		}
		total -= n
		patterns := make([]string, n)
		for j := range patterns {
			patterns[j] = near
			if k > 0 {
				patterns[j] = fmt.Sprintf("%s%d", near, k)
			}
			k++
		}
		r := map[string]interface{}{"methods": []string{"POST"}, "path_patterns": patterns}
		if suffix {
			r["host_suffixes"] = []string{"dropboxapi.com"}
		} else {
			r["hosts"] = []string{"content.dropboxapi.com"}
		}
		if i > 0 {
			b.WriteString(",")
		}
		doc, _ := json.Marshal(map[string]interface{}{"name": fmt.Sprintf("dropbox-p%03d", i), "container": "dropbox",
			"description": "d", "evidence": []string{"https://e.org"}, "rules": []interface{}{r}})
		b.Write(doc)
	}
	b.WriteString("]}")
	return b.String()
}

func TestLoadCapsPatternsPerHost(t *testing.T) {
	p := pack(t)
	for _, suffix := range []bool{false, true} {
		if _, err := Load([]byte(patternChildren(MaxPatternsPerHost, suffix)), p, Options{}); err != nil {
			t.Errorf("suffix=%v: %d patterns refused: %v", suffix, MaxPatternsPerHost, err)
		}
		_, err := Load([]byte(patternChildren(MaxPatternsPerHost+1, suffix)), p, Options{})
		if err == nil || !strings.Contains(err.Error(), "path patterns") {
			t.Errorf("suffix=%v: %d patterns: %v", suffix, MaxPatternsPerHost+1, err)
		}
	}
}

func longPath(bytes int) string {
	return strings.Repeat("/a", bytes/2)
}

// TestPatternWorkSplitsOncePerRequest pins the allocation count of the worst case the loader accepts: every pattern
// a host may hold against a 4 KiB path of 2,048 segments costs at most one split, as a request with no pattern.
func TestPatternWorkSplitsOncePerRequest(t *testing.T) {
	s, err := Load([]byte(patternChildren(MaxPatternsPerHost, false)), pack(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Host: "content.dropboxapi.com", Method: "POST", Path: longPath(DefaultMaxPathBytes)}
	if got := s.Classify(req); got.Limit != "" || got.Reasons[0] != ReasonNoChildMatched || got.Evaluated != MaxPatternsPerHost/MaxListEntries {
		t.Fatalf("got %+v", got)
	}
	withPatterns := testing.AllocsPerRun(50, func() { s.Classify(req) })
	noPattern := req
	noPattern.Method = "GET" // no rule meets the method, so no pattern runs and the path is never split
	without := testing.AllocsPerRun(50, func() { s.Classify(noPattern) })
	if withPatterns > without+1 {
		t.Fatalf("%v allocations with %d patterns, %v without: the path is split more than once", withPatterns,
			MaxPatternsPerHost, without)
	}
	// The near-miss patterns have 32 segments; a 32-segment path reaches their last segment and still misses.
	req.Path = "/" + strings.Repeat("a/", MaxPatternSegment-1) + "c"
	if got := s.Classify(req); got.Reasons[0] != ReasonNoChildMatched {
		t.Fatalf("got %+v", got)
	}
	req.Path = "/" + strings.Repeat("a/", MaxPatternSegment-1) + "b"
	if got := s.Classify(req); got.Reasons[0] != ReasonChildMatched || got.App != "dropbox-p000" {
		t.Fatalf("got %+v", got)
	}
}

func BenchmarkClassifyGraphLongPath(b *testing.B) {
	s := embeddedSet(b)
	req := Request{SNI: "graph.microsoft.com", Host: "graph.microsoft.com", Method: "PUT", Path: longPath(DefaultMaxPathBytes)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Classify(req)
	}
}

func BenchmarkClassifyPatternCapLongPath(b *testing.B) {
	s, err := Load([]byte(patternChildren(MaxPatternsPerHost, false)), pack(b), Options{})
	if err != nil {
		b.Fatal(err)
	}
	req := Request{Host: "content.dropboxapi.com", Method: "POST", Path: longPath(DefaultMaxPathBytes)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Classify(req)
	}
}

// TestDotSegmentScanMatchesSplit pins normalizePath's allocation-free dot-segment check (canonicalPath before
// SEC-CHILD-1) to the split it replaced.
func TestDotSegmentScanMatchesSplit(t *testing.T) {
	rng := rand.New(rand.NewSource(44))
	parts := []string{"", "a", ".", "..", "...", ".a", "a.", "b..", "x"}
	for i := 0; i < 20000; i++ {
		segs := make([]string, 1+rng.Intn(6))
		for j := range segs {
			segs[j] = parts[rng.Intn(len(parts))]
		}
		p := "/" + strings.Join(segs, "/")
		want := !strings.Contains(p, "//")
		if p != "/" {
			for _, seg := range strings.Split(p[1:], "/") {
				if seg == "." || seg == ".." {
					want = false
				}
			}
		}
		if _, got := normalizePath(p); got != want {
			t.Fatalf("%q: got %v, want %v", p, got, want)
		}
	}
}
