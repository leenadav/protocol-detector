// Package childapp splits one catalog application into child applications per function (the enterprise App-ID
// model: gmail-uploading, gmail-downloading, whatsapp-voice, ...). A child is data, never code per application:
// childapps.json lists each child, its container (the parent catalog application), the official documentation it
// was written from, and request rules over what a decrypting forward proxy (Culvert) sees of one HTTP request:
// the server name and Host, the method, a path prefix or pattern, query parameters, request headers present, the
// request content type, the size direction (upload or download) and a WebSocket upgrade. When several rules match,
// the most specific wins (most literal path bytes, then most condition kinds, then file order).
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
	maxQueryPairs             = 64
	maxHeaderNames            = 128
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
	Path              string // request target in origin form; query conditions read the query, the fragment is ignored
	ContentType       string // request Content-Type
	RequestBodyBytes  int64
	ResponseBodyBytes int64
	WebSocket         bool     // an HTTP/1.1 Upgrade: websocket or an HTTP/2 extended CONNECT for websocket
	HeaderNames       []string // names of the request headers present (any case); only rules with header conditions read them
}

// Result is the verdict for one request.
type Result struct {
	App         string   // the child when one matched, else the catalog application ("" when none)
	Container   string   // the parent of App when App is a child, else ""
	HostOwner   string   // the catalog application owning the host (the server-name identity), "" when none
	Rule        string   // the matched rule, "<child>#<index>" ("" when none)
	Basis       string   // BasisNone, BasisServerName or BasisRequestRule
	Reason      string   // the reason of the verdict, one of the closed vocabulary
	Reasons     []string // []string{Reason} from Classify; nil from Evaluate
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
	owners                       map[string]bool // the container and depends_on: the only host owners it refines
}

type rule struct {
	child        *Child
	index        int    // position of the rule inside its child
	id           string // "<child>#<index>", built once at load (PRO-522)
	order        int    // global evaluation order
	methods      map[string]bool
	pathPrefixes []string
	pathPatterns [][]segment
	contentTypes []string
	query        []queryCond
	headers      []string // lower case
	conditions   int      // number of condition kinds present, for precedence
	direction    string
	minBytes     int64
	websocket    bool
	foldCase     bool // path literals are lower case; matched against the lower-cased path
}

// Set is the validated child-app component over one content pack.
type Set struct {
	Release  Release
	Digest   string // SHA-256 of the component file
	pack     *content.Pack
	children []*Child
	byName   map[string]*Child
	rules    []*rule
	exact    map[string][]int          // host -> rule orders, ascending
	suffix   map[string][]int          // domain -> rule orders, ascending
	nested   map[string][]nestedDomain // while loading: parent domain -> catalog domains under it (SEC-CHILD-5)
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
// two labels; ok is false otherwise. It allocates only when the host has upper case (PRO-522).
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
	// strings.ToLower maps a few non-ASCII runes to ASCII letters (U+212A KELVIN SIGN to 'k', U+0130 to 'i'): a host
	// with any non-ASCII byte is lower-cased first, exactly as before. An ASCII host is checked first and
	// lower-cased only when it has upper case, which maps nothing but A-Z.
	for i := 0; i < len(h); i++ {
		if h[i] >= 0x80 {
			h = strings.ToLower(h)
			break
		}
	}
	if strings.HasSuffix(h, ".") {
		h = h[:len(h)-1]
	}
	if h == "" || len(h) > maxHostBytes || strings.IndexByte(h, '.') < 0 {
		return "", false
	}
	upper := false
	start := 0
	for i := 0; i <= len(h); i++ {
		if i == len(h) || h[i] == '.' {
			n := i - start
			if n == 0 || n > 63 || h[start] == '-' || h[i-1] == '-' {
				return "", false
			}
			start = i + 1
			continue
		}
		c := h[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-':
		case c >= 'A' && c <= 'Z':
			upper = true
		default:
			return "", false
		}
	}
	if upper {
		h = strings.ToLower(h)
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
			switch p[i+1] {
			case '2':
				if c := p[i+2] | 0x20; c == 'f' || c == 'e' || p[i+2] == '5' {
					return "", false // %2F, %2E, %25
				}
			case '5':
				if p[i+2]|0x20 == 'c' {
					return "", false // %5C
				}
			case '0':
				if p[i+2] == '0' {
					return "", false // %00
				}
			}
		}
	}
	if p == "/" {
		return p, true
	}
	// p starts with '/', so a dot segment is a "/." or "/.." followed by '/' or the end; no split (SEC-CHILD-4).
	if strings.Contains(p, "/./") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..") {
		return "", false
	}
	if strings.Contains(p, "//") {
		return "", false
	}
	return decodeSafe(p), true
}

// decodeSafe decodes the percent-encoded bytes a server reads as the plain character: RFC 3986 unreserved
// characters other than '.', and the sub-delimiters, ':' and '@'. So /v1.0/%24batch is /v1.0/$batch and
// /2/files/%75pload is /2/files/upload (SEC-CHILD-3). '/', '\', '.', '%' and NUL encodings were refused before;
// any other encoding (UTF-8 names, '?', '#') stays as written, where a placeholder still matches it.
func decodeSafe(p string) string {
	i := strings.IndexByte(p, '%')
	if i < 0 {
		return p
	}
	var b strings.Builder
	b.Grow(len(p))
	b.WriteString(p[:i])
	for ; i < len(p); i++ {
		if p[i] == '%' && i+2 < len(p) {
			if c, ok := unhex(p[i+1], p[i+2]); ok && decodable(c) {
				b.WriteByte(c)
				i += 2
				continue
			}
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

func unhex(h, l byte) (byte, bool) {
	v := func(c byte) (byte, bool) {
		switch {
		case c >= '0' && c <= '9':
			return c - '0', true
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10, true
		case c >= 'A' && c <= 'F':
			return c - 'A' + 10, true
		}
		return 0, false
	}
	a, ok1 := v(h)
	z, ok2 := v(l)
	return a<<4 | z, ok1 && ok2
}

func decodable(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_~!$&'()*+,;=:@", c) >= 0
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

// segment kinds of a compiled path pattern.
const (
	segLiteral  = iota // lits[0] exactly
	segAny             // '*' or '{name}': one non-empty segment
	segRest            // final '**': any rest, including none
	segTemplate        // literals with '{name}' placeholders between them, each placeholder non-empty
)

type segment struct {
	kind int
	lits []string // segLiteral: the segment; segTemplate: the literal parts around the placeholders
}

// literalBytes is the number of literal bytes a pattern pins, its weight in precedence.
func literalBytes(pattern []segment) int {
	n := 0
	for _, seg := range pattern {
		n++ // the '/'
		for _, l := range seg.lits {
			n += len(l)
		}
	}
	return n
}

// matchTemplate matches lits[0] {p} lits[1] ... {p} lits[n-1] against seg with every placeholder non-empty. The
// leftmost choice of each middle literal is optimal for wildcards that match any non-empty run, so this is linear.
func matchTemplate(lits []string, seg string) bool {
	first, last := lits[0], lits[len(lits)-1]
	if !strings.HasPrefix(seg, first) || !strings.HasSuffix(seg, last) {
		return false
	}
	pos, end := len(first), len(seg)-len(last)
	for _, mid := range lits[1 : len(lits)-1] {
		pos++ // the placeholder before mid takes at least one byte
		if pos > end {
			return false
		}
		i := strings.Index(seg[pos:end], mid)
		if i < 0 {
			return false
		}
		pos += i + len(mid)
	}
	return end-pos >= 1
}

// pathSegments is a request path split once per request (SEC-CHILD-4): n counts every segment, and segs holds at
// most MaxPatternSegment+1 of them (the last one keeps the unsplit rest), which is all a pattern can read. The
// segments live in a fixed array, so a split allocates nothing (PRO-522).
type pathSegments struct {
	n    int
	segs [MaxPatternSegment + 1]string
}

func splitPath(path string) (ps pathSegments) {
	t := strings.TrimPrefix(path, "/")
	ps.n = strings.Count(t, "/") + 1
	k := 0
	for k < MaxPatternSegment {
		i := strings.IndexByte(t, '/')
		if i < 0 {
			break
		}
		ps.segs[k], t = t[:i], t[i+1:]
		k++
	}
	ps.segs[k] = t
	return ps
}

// pathView splits the path on the first pattern condition only, so a request that meets no pattern never splits.
type pathView struct {
	path  string
	split bool
	segs  pathSegments
}

func (v *pathView) segments() *pathSegments {
	if !v.split {
		v.segs, v.split = splitPath(v.path), true
	}
	return &v.segs
}

// matchPattern matches a compiled pattern against a split path. The segment count is checked first: a pattern
// without a final '**' needs exactly len(pattern) segments, one with it at least len(pattern)-1.
func matchPattern(pattern []segment, ps *pathSegments) bool {
	fixed := len(pattern)
	if pattern[fixed-1].kind == segRest { // validated: only last
		fixed--
		if ps.n < fixed {
			return false
		}
	} else if ps.n != fixed {
		return false
	}
	for i, p := range pattern[:fixed] { // fixed <= MaxPatternSegment, so segs[i] is a whole segment
		switch p.kind {
		case segAny:
			if ps.segs[i] == "" {
				return false
			}
		case segLiteral:
			if p.lits[0] != ps.segs[i] {
				return false
			}
		case segTemplate:
			if !matchTemplate(p.lits, ps.segs[i]) {
				return false
			}
		}
	}
	return true
}

// queryCond requires one query parameter: present with one of values, or with any non-empty value when values is
// nil. A parameter that appears more than once never satisfies a condition (servers disagree on which one wins).
type queryCond struct {
	key    string
	values map[string]bool
}

// rawQuery is the query of a request target: after the first '?', up to the first '#' after it ("" when none).
func rawQuery(target string) string {
	i := strings.IndexByte(target, '?')
	if i < 0 {
		return ""
	}
	q := target[i+1:]
	if j := strings.IndexByte(q, '#'); j >= 0 {
		q = q[:j]
	}
	return q
}

// queryWithinLimit reports whether the query has at most maxQueryPairs non-empty '&'-separated parameters.
func queryWithinLimit(q string) bool {
	pairs := 0
	for q != "" {
		var pair string
		pair, q, _ = strings.Cut(q, "&")
		if pair != "" {
			if pairs++; pairs > maxQueryPairs {
				return false
			}
		}
	}
	return true
}

// queryValue scans the raw query (no percent-decoding) for key: its value when the key appears exactly once
// (a parameter without '=' has the value ""), and how often it appears, stopping at two. No map, no copy (PRO-522).
func queryValue(q, key string) (string, int) {
	value, seen := "", 0
	for q != "" {
		var pair string
		pair, q, _ = strings.Cut(q, "&")
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		if k == key {
			if seen++; seen > 1 {
				return "", seen
			}
			value = v
		}
	}
	return value, seen
}

// hasHeader reports whether a request header name equals the lower-case rule header h after strings.ToLower,
// comparing ASCII names byte by byte and lower-casing only a non-ASCII name, so the usual request allocates
// nothing (PRO-522).
func hasHeader(names []string, h string) bool {
	for _, name := range names {
		if headerIs(name, h) {
			return true
		}
	}
	return false
}

func headerIs(name, h string) bool {
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			return strings.ToLower(name) == h // a non-ASCII rune can lower-case to an ASCII letter
		}
	}
	if len(name) != len(h) {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != h[i] {
			return false
		}
	}
	return true
}

// requestPaths holds the canonical path of a request, split on first use, and its lower-cased form for
// path_case_insensitive rules, made only when such a rule is evaluated and the path has upper case (PRO-522).
type requestPaths struct {
	path      string
	view      pathView
	lowered   bool
	lower     pathView
	lowerSame bool // the path has no upper case: the folded form is the path itself
}

func (p *requestPaths) folded() (string, *pathView) {
	if !p.lowered {
		p.lowered = true
		lower := strings.ToLower(p.path) // no copy when the path has no upper case
		if lower == p.path {
			p.lowerSame = true
		} else {
			p.lower.path = lower // split at most once more, and only when it differs
		}
	}
	if p.lowerSame {
		return p.path, &p.view
	}
	return p.lower.path, &p.lower
}

// matches reports whether every condition holds and, if so, the rule's precedence score for this request: the
// literal bytes of the path condition that hit, then the number of condition kinds.
func (r *rule) matches(req *Request, paths *requestPaths, ct, query string) (bool, int) {
	if r.methods != nil && !r.methods[req.Method] {
		return false, 0
	}
	if r.websocket && !req.WebSocket {
		return false, 0
	}
	pathScore := 0
	path, view := paths.path, &paths.view
	if r.pathPrefixes != nil || r.pathPatterns != nil {
		if r.foldCase {
			path, view = paths.folded()
		}
		hit := false
		for _, prefix := range r.pathPrefixes {
			if strings.HasPrefix(path, prefix) && len(prefix) > pathScore {
				hit, pathScore = true, len(prefix)
			}
		}
		for _, pattern := range r.pathPatterns {
			if matchPattern(pattern, view.segments()) {
				hit = true
				if n := literalBytes(pattern); n > pathScore {
					pathScore = n
				}
			}
		}
		if !hit {
			return false, 0
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
			return false, 0
		}
	}
	for _, q := range r.query {
		value, n := queryValue(query, q.key)
		if n != 1 || value == "" || (q.values != nil && !q.values[value]) {
			return false, 0
		}
	}
	for _, h := range r.headers {
		if !hasHeader(req.HeaderNames, h) {
			return false, 0
		}
	}
	switch r.direction {
	case "upload":
		up, down := req.RequestBodyBytes, req.ResponseBodyBytes
		if up < 0 || up < r.minBytes || (down >= 0 && up <= down) {
			return false, 0
		}
	case "download":
		up, down := req.RequestBodyBytes, req.ResponseBodyBytes
		if down < 0 || down < r.minBytes || (up >= 0 && down <= up) {
			return false, 0
		}
	}
	return true, pathScore*16 + r.conditions
}

// candidateStack is the number of candidate lists kept on the stack: the exact host plus three parent domains
// covers ordinary names; a deeper name falls back to the heap.
const candidateStack = 8

// candidates appends the rule orders indexed under host and its parent domains to lists (merged by the caller
// ascending without repeats).
func (s *Set) candidates(host string, lists [][]int) [][]int {
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

// Classify returns the verdict for one request with Reasons set to []string{Reason}. It never panics on any input
// and does at most MaxRuleEvaluations rule evaluations.
func (s *Set) Classify(req Request) Result {
	res := s.Evaluate(&req)
	res.Reasons = []string{res.Reason}
	return res
}

// Evaluate is Classify without the Reasons slice: the verdict's single reason is in Result.Reason and Reasons is
// nil. It allocates nothing for an ordinary request (PRO-522); req is only read.
func (s *Set) Evaluate(req *Request) Result {
	res := Result{Basis: BasisNone, Release: s.Release.Version, PackRelease: s.pack.Release.Version}
	raw := req.Host
	if raw == "" {
		raw = req.SNI
	}
	if raw == "" {
		res.Reason = ReasonNoHost
		return res
	}
	host, ok := normalizeHost(raw)
	if !ok {
		res.Reason = ReasonHostInvalid
		return res
	}
	owner, kind, attributed := s.pack.AttributionForHost(host)
	if req.SNI != "" && req.Host != "" {
		sni, valid := host, true
		if req.SNI != req.Host { // the same text normalizes the same way
			sni, valid = normalizeHost(req.SNI)
		}
		if !valid {
			res.Reason = ReasonHostInvalid
			return res
		}
		if sni != host {
			sniOwner, sniKind, _ := s.pack.AttributionForHost(sni)
			if sniOwner != owner || sniKind != kind || owner == "" {
				res.Reason = ReasonSNIHostMismatch
				return res
			}
		}
	}
	if !attributed {
		res.Reason = ReasonHostUnowned
		return res
	}
	if kind != "service" {
		res.Reason = ReasonHostWebFront
		return res
	}
	res.App, res.HostOwner, res.Basis = owner, owner, BasisServerName
	if len(req.Method) > maxMethodBytes || len(req.ContentType) > maxContentTypeBytes {
		res.Reason, res.Limit = ReasonFieldTooLong, LimitFieldBytes
		return res
	}
	if len(req.Path) > s.opts.MaxPathBytes {
		res.Reason, res.Limit = ReasonWorkLimit, LimitPathBytes
		return res
	}
	path, canonical := canonicalPath(req.Path)
	if !canonical && req.Path != "" {
		res.Reason = ReasonPathNotCanonical
		return res
	}
	ct := mediaType(req.ContentType)
	query := rawQuery(req.Path)
	if !queryWithinLimit(query) || len(req.HeaderNames) > maxHeaderNames {
		res.Reason, res.Limit = ReasonFieldTooLong, LimitFieldBytes
		return res
	}
	paths := requestPaths{path: path, view: pathView{path: path}}
	var listBuf [candidateStack][]int
	lists := s.candidates(host, listBuf[:0])
	var headBuf [candidateStack]int
	heads := headBuf[:0]
	if len(lists) <= len(headBuf) {
		heads = headBuf[:len(lists)]
	} else {
		heads = make([]int, len(lists))
	}
	last := -1
	var winner *rule
	winnerScore := 0
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
			break
		}
		if res.Evaluated >= s.opts.MaxRuleEvaluations {
			// An unevaluated rule could be more specific than any match so far: the ceiling never picks a child.
			res.Reason, res.Limit = ReasonWorkLimit, LimitRuleEvaluations
			return res
		}
		last = lists[best][heads[best]]
		r := s.rules[last]
		res.Evaluated++
		// A host_suffixes rule is indexed under a domain its child's owner claims, but the catalog can give a more
		// specific host to another application: a child only refines its own owners' identity (SEC-CHILD-2).
		if !r.child.owners[owner] {
			continue
		}
		// Precedence: the highest score wins; on a tie the earlier rule (file order) keeps it.
		if hit, score := r.matches(req, &paths, ct, query); hit && (winner == nil || score > winnerScore) {
			winner, winnerScore = r, score
		}
	}
	if winner == nil {
		res.Reason = ReasonNoChildMatched
		return res
	}
	res.App, res.Container, res.Basis = winner.child.Name, winner.child.Container, BasisRequestRule
	res.Rule = winner.id
	res.Reason = ReasonChildMatched
	return res
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
	if res.Reasons == nil && res.Reason != "" { // a Result from Evaluate
		reasons = []string{res.Reason}
	}
	v := &appid.Verdict{App: app.Name, Category: app.Category, Subcategory: app.Subcategory, Technology: app.Technology,
		Risk: app.Risk, Characteristics: append([]string{}, app.Characteristics...),
		ImplicitlyUses: append([]string{}, app.ImplicitlyUses...), PortUsage: "unknown", Status: "identified",
		Reasons: reasons, Risks: []string{}}
	if res.Container != "" {
		container := res.Container
		v.BaseApp = &container
	}
	if res.HostOwner != "" {
		owner := res.HostOwner
		v.HostOwner = &owner
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
