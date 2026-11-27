// Package childapp splits one catalog application into child applications per function (the enterprise App-ID
// model: gmail-uploading, gmail-downloading, whatsapp-voice, ...). A child is data, never code per application:
// childapps.json lists each child, its container (the parent catalog application), the official documentation it
// was written from, and request rules over what a decrypting forward proxy (Culvert) sees of one HTTP request:
// the server name and Host, the method, a path prefix or pattern, the request content type, the size direction
// (upload or download) and a WebSocket upgrade.
//
// A rule only refines an identity the server-name catalog already established: every host a rule names must be
// claimed in the content pack by the child's container or by an application the child declares in depends_on.
// Request metadata never establishes an application on its own, and an unowned host yields no application.
//
// Work is bounded. Rules are indexed by host, the number of rules evaluated for one request is capped
// (Options.MaxRuleEvaluations), and paths longer than Options.MaxPathBytes are not matched. A request that hits a
// ceiling reports it in Result.Limit and gets no child: a limit is never silent (PRO-477) and never a match.
package childapp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/content"
)

// Defaults of the per-request work ceiling.
const (
	DefaultMaxRuleEvaluations = 64
	DefaultMaxPathBytes       = 4096
	maxHostBytes              = 253
	maxMethodBytes            = 32
	maxContentTypeBytes       = 256
)

// Basis values: what established Result.App.
const (
	BasisNone        = "none"
	BasisServerName  = "server_name"  // the content pack's server-name catalog; no child rule matched
	BasisRequestRule = "request_rule" // a child rule matched the request inside the catalog's identity
)

// Reasons form a closed vocabulary (they may be used as metric labels).
const (
	ReasonNoHost           = "no_host"
	ReasonHostInvalid      = "host_invalid"
	ReasonHostUnowned      = "host_unowned"
	ReasonHostWebFront     = "host_web_front"
	ReasonSNIHostMismatch  = "sni_host_owner_mismatch"
	ReasonPathNotCanonical = "path_not_canonical"
	ReasonFieldTooLong     = "field_too_long"
	ReasonNoChildMatched   = "no_child_rule_matched"
	ReasonChildMatched     = "child_rule_matched"
	ReasonWorkLimit        = "work_limit"
	ReasonPanic            = "panic" // set by a caller that recovered a panic around Classify
)

// Limit values: the ceiling a request hit ("" when none).
const (
	LimitRuleEvaluations = "child_rule_evaluations"
	LimitPathBytes       = "child_path_bytes"
	LimitFieldBytes      = "child_field_bytes"
)

// Reasons lists the reason vocabulary.
func Reasons() []string {
	return []string{ReasonNoHost, ReasonHostInvalid, ReasonHostUnowned, ReasonHostWebFront, ReasonSNIHostMismatch,
		ReasonPathNotCanonical, ReasonFieldTooLong, ReasonNoChildMatched, ReasonChildMatched, ReasonWorkLimit, ReasonPanic}
}

// Limits lists the limit vocabulary.
func Limits() []string { return []string{LimitRuleEvaluations, LimitPathBytes, LimitFieldBytes} }

// Request is what the proxy saw of one HTTP request (after decryption, or in plaintext). Byte counts are body
// bytes; a negative count is unknown.
type Request struct {
	SNI               string // TLS server name of the client connection ("" for plaintext)
	Host              string // HTTP Host or :authority
	Method            string
	Path              string // request target in origin form; the query and fragment are ignored
	ContentType       string // request Content-Type
	RequestBodyBytes  int64
	ResponseBodyBytes int64
	WebSocket         bool // an HTTP/1.1 Upgrade: websocket or an HTTP/2 extended CONNECT for websocket
}

// Result is the verdict for one request.
type Result struct {
	App         string   // the child when one matched, else the catalog application ("" when none)
	Container   string   // the parent of App when App is a child, else ""
	Rule        string   // the matched rule, "<child>#<index>" ("" when none)
	Basis       string   // BasisNone, BasisServerName or BasisRequestRule
	Reasons     []string // closed vocabulary, in evaluation order
	Limit       string   // the ceiling hit, "" when none
	Evaluated   int      // rules evaluated for this request
	Release     string   // the child-app release
	PackRelease string   // the content release the catalog identity came from
}

// Options bound the per-request work.
type Options struct {
	MaxRuleEvaluations int // <= 0: DefaultMaxRuleEvaluations
	MaxPathBytes       int // <= 0: DefaultMaxPathBytes
}

// Child is one validated child application.
type Child struct {
	Name, Container, Description string
	Risk                         int
	Characteristics, DependsOn   []string
	ImplicitlyUses, Evidence     []string
	app                          *content.Application
}

type rule struct {
	child        *Child
	index        int // position of the rule inside its child
	order        int // global evaluation order
	methods      map[string]bool
	pathPrefixes []string
	pathPatterns [][]string
	contentTypes []string
	direction    string
	minBytes     int64
	websocket    bool
}

// Set is the validated child-app component over one content pack.
type Set struct {
	Release  Release
	Digest   string // SHA-256 of the component file
	pack     *content.Pack
	children []*Child
	byName   map[string]*Child
	rules    []*rule
	exact    map[string][]int // host -> rule orders, ascending
	suffix   map[string][]int // domain -> rule orders, ascending
	opts     Options
}

// Release identifies the child-app component.
type Release struct {
	Version, Note, Review string
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Children lists the children in file order.
func (s *Set) Children() []*Child { return append([]*Child(nil), s.children...) }

// Child returns the named child, nil when none.
func (s *Set) Child(name string) *Child { return s.byName[name] }

// Has reports whether name is a child application (policy name resolution).
func (s *Set) Has(name string) bool {
	if s == nil {
		return false
	}
	_, ok := s.byName[name]
	return ok
}

// WithOptions returns a copy of the set with other work bounds; the rule data is shared and immutable.
func (s *Set) WithOptions(o Options) *Set {
	c := *s
	c.opts = normalize(o)
	return &c
}

func normalize(o Options) Options {
	if o.MaxRuleEvaluations <= 0 {
		o.MaxRuleEvaluations = DefaultMaxRuleEvaluations
	}
	if o.MaxPathBytes <= 0 {
		o.MaxPathBytes = DefaultMaxPathBytes
	}
	return o
}

// normalizeHost lower-cases a host, drops a port and one trailing dot, and checks it is a DNS name of at least
// two labels; ok is false otherwise.
func normalizeHost(h string) (string, bool) {
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

// canonicalPath strips the query and fragment and refuses forms a filter and a server could read differently:
// no leading slash, dot segments, empty segments, backslashes, encoded slashes, dots or backslashes, controls.
func canonicalPath(p string) (string, bool) {
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
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	if strings.Contains(p, "//") {
		return "", false
	}
	return p, true
}

// mediaType is the lower-cased type/subtype without parameters ("" when absent or malformed).
func mediaType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	slash := strings.IndexByte(ct, '/')
	if slash <= 0 || slash == len(ct)-1 || strings.ContainsAny(ct, " \t") || strings.Count(ct, "/") != 1 {
		return ""
	}
	return ct
}

func matchPattern(pattern []string, path string) bool {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, p := range pattern {
		if p == "**" { // validated: only last
			return true
		}
		if i >= len(segments) {
			return false
		}
		if p == "*" {
			if segments[i] == "" {
				return false
			}
			continue
		}
		if p != segments[i] {
			return false
		}
	}
	return len(segments) == len(pattern)
}

func (r *rule) matches(req *Request, path, ct string) bool {
	if r.methods != nil && !r.methods[req.Method] {
		return false
	}
	if r.websocket && !req.WebSocket {
		return false
	}
	if r.pathPrefixes != nil || r.pathPatterns != nil {
		hit := false
		for _, prefix := range r.pathPrefixes {
			if strings.HasPrefix(path, prefix) {
				hit = true
				break
			}
		}
		for _, pattern := range r.pathPatterns {
			if !hit && matchPattern(pattern, path) {
				hit = true
			}
		}
		if !hit {
			return false
		}
	}
	if r.contentTypes != nil {
		hit := false
		for _, want := range r.contentTypes {
			if want == ct || strings.HasSuffix(want, "/*") && ct != "" && strings.HasPrefix(ct, want[:len(want)-1]) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	switch r.direction {
	case "upload":
		up, down := req.RequestBodyBytes, req.ResponseBodyBytes
		if up < 0 || up < r.minBytes || (down >= 0 && up <= down) {
			return false
		}
	case "download":
		up, down := req.RequestBodyBytes, req.ResponseBodyBytes
		if down < 0 || down < r.minBytes || (up >= 0 && down <= up) {
			return false
		}
	}
	return true
}

// candidates are the rule orders indexed under host and its parent domains, merged ascending without repeats.
func (s *Set) candidates(host string) [][]int {
	var lists [][]int
	if l := s.exact[host]; len(l) > 0 {
		lists = append(lists, l)
	}
	for position := 0; ; {
		if l := s.suffix[host[position:]]; len(l) > 0 {
			lists = append(lists, l)
		}
		dot := strings.IndexByte(host[position:], '.')
		if dot < 0 {
			return lists
		}
		position += dot + 1
	}
}

// Classify returns the verdict for one request. It never panics on any input and does at most
// MaxRuleEvaluations rule evaluations.
func (s *Set) Classify(req Request) Result {
	res := Result{Basis: BasisNone, Release: s.Release.Version, PackRelease: s.pack.Release.Version}
	raw := req.Host
	if raw == "" {
		raw = req.SNI
	}
	if raw == "" {
		res.Reasons = []string{ReasonNoHost}
		return res
	}
	host, ok := normalizeHost(raw)
	if !ok {
		res.Reasons = []string{ReasonHostInvalid}
		return res
	}
	owner, kind, attributed := s.pack.AttributionForHost(host)
	if req.SNI != "" && req.Host != "" {
		sni, valid := normalizeHost(req.SNI)
		if !valid {
			res.Reasons = []string{ReasonHostInvalid}
			return res
		}
		if sni != host {
			sniOwner, sniKind, _ := s.pack.AttributionForHost(sni)
			if sniOwner != owner || sniKind != kind || owner == "" {
				res.Reasons = []string{ReasonSNIHostMismatch}
				return res
			}
		}
	}
	if !attributed {
		res.Reasons = []string{ReasonHostUnowned}
		return res
	}
	if kind != "service" {
		res.Reasons = []string{ReasonHostWebFront}
		return res
	}
	res.App, res.Basis = owner, BasisServerName
	if len(req.Method) > maxMethodBytes || len(req.ContentType) > maxContentTypeBytes {
		res.Reasons, res.Limit = []string{ReasonFieldTooLong}, LimitFieldBytes
		return res
	}
	if len(req.Path) > s.opts.MaxPathBytes {
		res.Reasons, res.Limit = []string{ReasonWorkLimit}, LimitPathBytes
		return res
	}
	path, canonical := canonicalPath(req.Path)
	if !canonical && req.Path != "" {
		res.Reasons = []string{ReasonPathNotCanonical}
		return res
	}
	ct := mediaType(req.ContentType)
	lists := s.candidates(host)
	heads := make([]int, len(lists))
	last := -1
	for {
		best := -1
		for i, l := range lists {
			for heads[i] < len(l) && l[heads[i]] <= last {
				heads[i]++
			}
			if heads[i] < len(l) && (best < 0 || l[heads[i]] < lists[best][heads[best]]) {
				best = i
			}
		}
		if best < 0 {
			res.Reasons = []string{ReasonNoChildMatched}
			return res
		}
		if res.Evaluated >= s.opts.MaxRuleEvaluations {
			res.Reasons, res.Limit = []string{ReasonWorkLimit}, LimitRuleEvaluations
			return res
		}
		last = lists[best][heads[best]]
		r := s.rules[last]
		res.Evaluated++
		if r.matches(&req, path, ct) {
			res.App, res.Container, res.Basis = r.child.Name, r.child.Container, BasisRequestRule
			res.Rule = fmt.Sprintf("%s#%d", r.child.Name, r.index)
			res.Reasons = []string{ReasonChildMatched}
			return res
		}
	}
}

// Application is the catalog record of a child: the container's category, subcategory and technology with the
// child's own risk and characteristics; it implicitly uses its container.
func (s *Set) Application(name string) *content.Application {
	if c := s.byName[name]; c != nil {
		return c.app
	}
	return nil
}

// Verdict presents a Result as a session verdict for policy evaluation: App is the child or the catalog
// application and BaseApp its container. It returns nil when the result names no application.
func (s *Set) Verdict(res Result) *appid.Verdict {
	if res.App == "" {
		return nil
	}
	app := s.pack.Applications[res.App]
	if c := s.byName[res.App]; c != nil {
		app = c.app
	}
	if app == nil {
		return nil
	}
	reasons := append([]string{}, res.Reasons...)
	v := &appid.Verdict{App: app.Name, Category: app.Category, Subcategory: app.Subcategory, Technology: app.Technology,
		Risk: app.Risk, Characteristics: append([]string{}, app.Characteristics...),
		ImplicitlyUses: append([]string{}, app.ImplicitlyUses...), PortUsage: "unknown", Status: "identified",
		Reasons: reasons, Risks: []string{}}
	if res.Container != "" {
		container := res.Container
		v.BaseApp = &container
	}
	return v
}

func sortedUnique(in []int) []int {
	sort.Ints(in)
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}
