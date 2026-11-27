package childapp

import (
	"encoding/json"
	"fmt"
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
	propSegments = []string{"2", "files", "upload", "download", "x", "sharing"}
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
			choices = append(append([]string{}, propSegments...), "*")
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
		WebSocket: rapid.Bool().Draw(t, "ws")}
	if rapid.Bool().Draw(t, "sni") {
		r.SNI = r.Host
	}
	return r
}

// oracleRule is the spec read literally, without the matcher's index or helpers.
func oracleRule(r specRule, req Request) bool {
	host := strings.ToLower(req.Host)
	hostHit := false
	for _, h := range r.Hosts {
		hostHit = hostHit || h == host
	}
	for _, h := range r.HostSuffixes {
		hostHit = hostHit || host == h || strings.HasSuffix(host, "."+h)
	}
	if !hostHit {
		return false
	}
	if r.Methods != nil {
		ok := false
		for _, m := range r.Methods {
			ok = ok || m == req.Method
		}
		if !ok {
			return false
		}
	}
	if r.WebSocket && !req.WebSocket {
		return false
	}
	if r.PathPrefixes != nil || r.PathPatterns != nil {
		ok := false
		for _, p := range r.PathPrefixes {
			ok = ok || strings.HasPrefix(req.Path, p)
		}
		for _, p := range r.PathPatterns {
			ps, qs := strings.Split(p[1:], "/"), strings.Split(req.Path[1:], "/")
			hit := true
			for i, seg := range ps {
				if seg == "**" {
					break
				}
				if i >= len(qs) || (seg != "*" && seg != qs[i]) {
					hit = false
					break
				}
				if i == len(ps)-1 && len(qs) != len(ps) {
					hit = false
				}
			}
			ok = ok || hit
		}
		if !ok {
			return false
		}
	}
	if r.ContentTypes != nil {
		ok := false
		for _, ct := range r.ContentTypes {
			ok = ok || ct == req.ContentType || (ct == "multipart/*" && strings.HasPrefix(req.ContentType, "multipart/"))
		}
		if !ok {
			return false
		}
	}
	min := r.MinBytes
	if min == 0 {
		min = 1
	}
	switch r.Direction {
	case "upload":
		return req.RequestBodyBytes >= min && (req.ResponseBodyBytes < 0 || req.RequestBodyBytes > req.ResponseBodyBytes)
	case "download":
		return req.ResponseBodyBytes >= min && (req.RequestBodyBytes < 0 || req.ResponseBodyBytes > req.RequestBodyBytes)
	}
	return true
}

func oracle(children []specChild, req Request) (string, int) {
	evaluated := 0
	for _, c := range children {
		for j, r := range c.Rules {
			evaluated++
			if oracleRule(r, req) {
				return fmt.Sprintf("%s#%d", c.Name, j), evaluated
			}
		}
	}
	return "", evaluated
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
		variant.Path += "?a=/2/files/upload#f"
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
