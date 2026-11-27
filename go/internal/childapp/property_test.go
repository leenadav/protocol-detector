package childapp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// The property tests generate a random component over the dropbox entry of the embedded pack and random requests,
// and check the indexed matcher against a brute-force oracle written independently from the spec.

type specRule struct {
	Hosts        []string `json:"hosts,omitempty"`
	HostSuffixes []string `json:"host_suffixes,omitempty"`
	Methods      []string `json:"methods,omitempty"`
	PathPrefixes []string `json:"path_prefixes,omitempty"`
	PathPatterns []string `json:"path_patterns,omitempty"`
	ContentTypes []string `json:"content_types,omitempty"`
	Query        []string `json:"query,omitempty"`
	Headers      []string `json:"header_present,omitempty"`
	Direction    string   `json:"direction,omitempty"`
	MinBytes     int64    `json:"min_bytes,omitempty"`
	WebSocket    bool     `json:"websocket,omitempty"`
}

type specChild struct {
	Name        string     `json:"name"`
	Container   string     `json:"container"`
	Description string     `json:"description"`
	Evidence    []string   `json:"evidence"`
	Rules       []specRule `json:"rules"`
}

var (
	propHosts    = []string{"dropbox.com", "www.dropbox.com", "api.dropboxapi.com", "content.dropboxapi.com", "dropboxapi.com"}
	propSegments = []string{"2", "files", "upload", "download", "x", "sharing", "bot7", "bot", "r.git", ".git", "m:run", ":run", "a:b", ":"}
	propWild     = []string{"*", "{id}", "bot{t}", "{repo}.git", "{model}:run", "{a}:{b}"}
	propQuery    = []string{"alt=media", "alt=json", "uploadType=media|resumable", "name={n}", "alt"}
	propQueryIn  = []string{"alt=media", "alt=json", "uploadType=resumable", "name=f.zip", "alt=", "alt=media&alt=json"}
	propHeaders  = []string{"Dropbox-API-Arg", "X-Upload"}
	propMethods  = []string{"GET", "POST", "PUT"}
	propTypes    = []string{"application/json", "application/octet-stream", "text/plain", "multipart/form-data"}
)

func subset(t *rapid.T, label string, from []string) []string {
	picked := rapid.SliceOfNDistinct(rapid.SampledFrom(from), 0, 3, rapid.ID[string]).Draw(t, label)
	if len(picked) == 0 {
		return nil
	}
	return picked
}

func genPath(t *rapid.T, label string, wild bool) string {
	n := rapid.IntRange(1, 4).Draw(t, label+"-n")
	parts := make([]string, n)
	for i := range parts {
		choices := propSegments
		if wild {
			choices = append(append([]string{}, propSegments...), propWild...)
			if i == n-1 && i > 0 {
				choices = append(choices, "**")
			}
		}
		parts[i] = rapid.SampledFrom(choices).Draw(t, fmt.Sprintf("%s-%d", label, i))
	}
	return "/" + strings.Join(parts, "/")
}

func genRule(t *rapid.T) specRule {
	r := specRule{Hosts: subset(t, "hosts", propHosts), HostSuffixes: subset(t, "suffixes", propHosts),
		Methods: subset(t, "methods", propMethods), ContentTypes: subset(t, "types", append(propTypes, "multipart/*"))}
	if len(r.Hosts)+len(r.HostSuffixes) == 0 {
		r.Hosts = []string{"content.dropboxapi.com"}
	}
	if rapid.Bool().Draw(t, "prefix") {
		r.PathPrefixes = []string{genPath(t, "prefix-path", false)}
	}
	if rapid.Bool().Draw(t, "pattern") {
		r.PathPatterns = []string{genPath(t, "pattern-path", true)}
	}
	if rapid.Bool().Draw(t, "query") {
		r.Query = []string{rapid.SampledFrom(propQuery).Draw(t, "query-cond")}
		if r.Methods == nil {
			r.Methods = []string{"GET"}
		}
	}
	r.Headers = subset(t, "headers", propHeaders)
	r.Direction = rapid.SampledFrom([]string{"", "upload", "download"}).Draw(t, "direction")
	if r.Direction != "" && rapid.Bool().Draw(t, "min") {
		r.MinBytes = rapid.Int64Range(1, 100).Draw(t, "min-bytes")
	}
	r.WebSocket = rapid.Bool().Draw(t, "websocket")
	if r.Methods == nil && r.ContentTypes == nil && r.PathPrefixes == nil && r.PathPatterns == nil && r.Direction == "" && !r.WebSocket {
		r.Methods = []string{"POST"}
	}
	return r
}

func genComponent(t *rapid.T) ([]specChild, []byte) {
	children := make([]specChild, rapid.IntRange(1, 12).Draw(t, "children"))
	for i := range children {
		rules := make([]specRule, rapid.IntRange(1, 3).Draw(t, "rules"))
		for j := range rules {
			rules[j] = genRule(t)
		}
		children[i] = specChild{Name: fmt.Sprintf("dropbox-p%d", i), Container: "dropbox", Description: "d",
			Evidence: []string{"https://e.org"}, Rules: rules}
	}
	body, _ := json.Marshal(children)
	return children, []byte(`{"schema": 1, "release": {"version": "2026.11.0", "note": "n", "review": "r"}, "children": ` + string(body) + `}`)
}

func genRequest(t *rapid.T) Request {
	r := Request{Host: rapid.SampledFrom(propHosts).Draw(t, "host"), Method: rapid.SampledFrom(propMethods).Draw(t, "method"),
		Path: genPath(t, "path", false), ContentType: rapid.SampledFrom(append(propTypes, "")).Draw(t, "type"),
		RequestBodyBytes: rapid.Int64Range(-1, 200).Draw(t, "up"), ResponseBodyBytes: rapid.Int64Range(-1, 200).Draw(t, "down"),
		WebSocket: rapid.Bool().Draw(t, "ws"), HeaderNames: subset(t, "req-headers", append(propHeaders, "dropbox-api-arg"))}
	if rapid.Bool().Draw(t, "has-query") {
		r.Path += "?" + rapid.SampledFrom(propQueryIn).Draw(t, "query-in")
	}
	if rapid.Bool().Draw(t, "sni") {
		r.SNI = r.Host
	}
	return r
}

// patternRegexp is an independent reading of the pattern language: '*' and '{name}' are one or more non-'/' bytes,
// a final '**' is any rest, everything else is literal.
func patternRegexp(p string) (*regexp.Regexp, int) {
	literal := 0
	var b strings.Builder
	b.WriteString("^")
	parts := strings.Split(p[1:], "/")
	for i, part := range parts {
		literal++
		if part == "**" && i == len(parts)-1 {
			b.WriteString("(/.*)?")
			continue
		}
		b.WriteString("/")
		if part == "*" {
			b.WriteString("[^/]+")
			continue
		}
		for _, piece := range regexp.MustCompile(`\{[^{}]+\}|[^{}]+`).FindAllString(part, -1) {
			if strings.HasPrefix(piece, "{") {
				b.WriteString("[^/]+")
			} else {
				b.WriteString(regexp.QuoteMeta(piece))
				literal += len(piece)
			}
		}
	}
	// "/a/**" also matches "/a": the optional group above covers it once the '/' of '**' is not required.
	b.WriteString("$")
	return regexp.MustCompile(b.String()), literal
}

// oracleRule is the spec read literally, without the matcher's index or helpers: whether it matches and its score.
func oracleRule(r specRule, req Request) (bool, int) {
	host := strings.ToLower(req.Host)
	hostHit := false
	for _, h := range r.Hosts {
		hostHit = hostHit || h == host
	}
	for _, h := range r.HostSuffixes {
		hostHit = hostHit || host == h || strings.HasSuffix(host, "."+h)
	}
	if !hostHit {
		return false, 0
	}
	conditions := 0
	if r.Methods != nil {
		conditions++
		ok := false
		for _, m := range r.Methods {
			ok = ok || m == req.Method
		}
		if !ok {
			return false, 0
		}
	}
	if r.WebSocket {
		conditions++
		if !req.WebSocket {
			return false, 0
		}
	}
	path, rawQuery, _ := strings.Cut(req.Path, "?")
	best := 0
	if r.PathPrefixes != nil || r.PathPatterns != nil {
		conditions++
		ok := false
		for _, p := range r.PathPrefixes {
			if strings.HasPrefix(path, p) {
				ok = true
				if len(p) > best {
					best = len(p)
				}
			}
		}
		for _, p := range r.PathPatterns {
			if re, literal := patternRegexp(p); re.MatchString(path) {
				ok = true
				if literal > best {
					best = literal
				}
			}
		}
		if !ok {
			return false, 0
		}
	}
	if r.ContentTypes != nil {
		conditions++
		ok := false
		for _, ct := range r.ContentTypes {
			ok = ok || ct == req.ContentType || (ct == "multipart/*" && strings.HasPrefix(req.ContentType, "multipart/"))
		}
		if !ok {
			return false, 0
		}
	}
	if r.Query != nil {
		conditions++
		params := map[string][]string{}
		for _, pair := range strings.Split(rawQuery, "&") {
			if pair != "" {
				k, v, _ := strings.Cut(pair, "=")
				params[k] = append(params[k], v)
			}
		}
		for _, q := range r.Query {
			key, want, hasValue := strings.Cut(q, "=")
			got := params[key]
			if len(got) != 1 || got[0] == "" {
				return false, 0
			}
			if hasValue && !strings.HasPrefix(want, "{") && !strings.Contains("|"+want+"|", "|"+got[0]+"|") {
				return false, 0
			}
		}
	}
	if r.Headers != nil {
		conditions++
		for _, h := range r.Headers {
			ok := false
			for _, have := range req.HeaderNames {
				ok = ok || strings.EqualFold(h, have)
			}
			if !ok {
				return false, 0
			}
		}
	}
	min := r.MinBytes
	if min == 0 {
		min = 1
	}
	switch r.Direction {
	case "upload":
		conditions++
		if !(req.RequestBodyBytes >= min && (req.ResponseBodyBytes < 0 || req.RequestBodyBytes > req.ResponseBodyBytes)) {
			return false, 0
		}
	case "download":
		conditions++
		if !(req.ResponseBodyBytes >= min && (req.RequestBodyBytes < 0 || req.ResponseBodyBytes > req.RequestBodyBytes)) {
			return false, 0
		}
	}
	return true, best*16 + conditions
}

// oracle is the most specific matching rule (highest score, the first one in file order on a tie).
func oracle(children []specChild, req Request) (string, int) {
	evaluated, winner, top := 0, "", -1
	for _, c := range children {
		for j, r := range c.Rules {
			evaluated++
			if ok, score := oracleRule(r, req); ok && score > top {
				winner, top = fmt.Sprintf("%s#%d", c.Name, j), score
			}
		}
	}
	return winner, evaluated
}

func TestPropertyMatcherAgreesWithOracle(t *testing.T) {
	p := pack(t)
	rapid.Check(t, func(rt *rapid.T) {
		children, doc := genComponent(rt)
		max := rapid.IntRange(1, 40).Draw(rt, "max")
		s, err := Load(doc, p, Options{MaxRuleEvaluations: max})
		if err != nil {
			rt.Fatalf("generated component refused: %v", err)
		}
		req := genRequest(rt)
		got := s.Classify(req)
		if got.Evaluated > max {
			rt.Fatalf("evaluated %d > ceiling %d", got.Evaluated, max)
		}
		if got.App != "dropbox" && got.Container != "dropbox" {
			rt.Fatalf("dropbox host gave app %q container %q", got.App, got.Container)
		}
		want, _ := oracle(children, req)
		switch {
		case got.Limit != "":
			// A ceiling never yields a child, and only happens when the oracle needs more evaluations of rules on
			// this host than allowed (the oracle counts every rule, so its count is an upper bound).
			if got.Container != "" || got.Rule != "" || got.Limit != LimitRuleEvaluations {
				rt.Fatalf("limit with a child: %+v", got)
			}
		case got.Rule != want:
			rt.Fatalf("matcher %q, oracle %q for %+v", got.Rule, want, req)
		}
		// Invariances: a query string, host case, a port and a trailing dot change nothing.
		variant := req
		variant.Path += "#f"
		variant.Host = strings.ToUpper(req.Host) + ".:443"
		variant.SNI = ""
		if again := s.Classify(variant); again.Rule != got.Rule || again.Limit != got.Limit || again.App != got.App {
			rt.Fatalf("variant changed the verdict: %+v vs %+v", again, got)
		}
		if again := s.Classify(req); fmt.Sprint(again) != fmt.Sprint(got) {
			rt.Fatalf("not deterministic: %+v vs %+v", again, got)
		}
	})
}

func TestPropertyUnownedHostsNeverGetAnApplication(t *testing.T) {
	s := embeddedSet(t)
	rapid.Check(t, func(rt *rapid.T) {
		label := rapid.StringMatching(`[a-z0-9]{1,12}`).Draw(rt, "label")
		req := genRequest(rt)
		req.Host, req.SNI = label+".invalid", ""
		if got := s.Classify(req); got.App != "" || got.Container != "" || got.Basis != BasisNone {
			rt.Fatalf("unowned host %s gave %+v", req.Host, got)
		}
	})
}
