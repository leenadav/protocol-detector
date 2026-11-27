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
//
// Refusals fail closed (SEC-CHILD-1). Result.ChildStatus is appid.ChildUndetermined whenever a child rule of the
// host could apply but the request was refused (a path that is not canonical), capped (a field or work ceiling) or
// ambiguous (a repeated query parameter or a malformed content type a rule reads, a trailing slash a pattern only
// matches without): the verdict then names the parent and no child, and a policy denies the status with
// child_status. Before matching, percent-encoded unreserved bytes (RFC 3986 section 2.3) in the path and the query,
// and sub-delimiters, ':' and '@' in the path (SEC-CHILD-3), are decoded and every other escape is upper-cased, so
// %6f and o match alike.
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
	ReasonAmbiguous        = "request_ambiguous" // the most specific candidate rule depends on an ambiguous field
	ReasonPanic            = "panic"             // set by a caller that recovered a panic around Classify
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
		ReasonPathNotCanonical, ReasonFieldTooLong, ReasonNoChildMatched, ReasonChildMatched, ReasonWorkLimit, ReasonAmbiguous, ReasonPanic}
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
	Reasons     []string // closed vocabulary, in evaluation order
	Limit       string   // the ceiling hit, "" when none
	ChildStatus string   // appid.ChildMatched, ChildNone, ChildUndetermined (fail closed) or ChildNotApplicable
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
	index        int // position of the rule inside its child
	order        int // global evaluation order
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
	exact    map[string][]int // host -> rule orders, ascending
	suffix   map[string][]int // domain -> rule orders, ascending
	opts     Options
	foldCase bool // some rule matches its path case-insensitively
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

// Owners lists the applications the named child's hosts may belong to: its container, then its depends_on in
// file order; nil when name is not a child. A policy deny on the child also holds for an undetermined verdict of
// one of them (SEC-CHILD-8), the same test as AppClassifier.MayBe.
func (s *Set) Owners(name string) []string {
	if s == nil {
		return nil
	}
	c := s.byName[name]
	if c == nil {
		return nil
	}
	return append([]string{c.Container}, c.DependsOn...)
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

// unhex is the value of a hex digit; ok is false for any other byte.
func unhex(c byte) (byte, bool) {
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

// unreserved reports an RFC 3986 unreserved byte other than '.': decoding it never changes how a server splits
// or resolves a path ('.' stays encoded and is refused in a path, so %2e can never form a dot segment).
func unreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '~'
}

// pathDecodable reports a byte a server reads the same encoded or plain in a path: an unreserved byte, a
// sub-delimiter, ':' or '@' (RFC 3986 section 3.3), so /v1.0/%24batch is /v1.0/$batch (SEC-CHILD-3). In a query
// only unreserved bytes are decoded: '+', '&' and '=' mean something else there plain than encoded.
func pathDecodable(c byte) bool {
	return unreserved(c) || strings.IndexByte("!$&'()*+,;=:@", c) >= 0
}

// normalizePercent decodes escapes of unreserved bytes (and, when path is true, of the other pathDecodable bytes)
// and upper-cases every other escape (RFC 3986 sections 6.2.2.1 and 6.2.2.2), so a UTF-8 name stays encoded and a
// placeholder still matches it. ok is false on a malformed escape and, when path is true, on an escape of '/',
// '\', '.', '%' or a control byte. The output is never longer than the input.
func normalizePercent(in string, path bool) (string, bool) {
	if strings.IndexByte(in, '%') < 0 {
		return in, true
	}
	const hexdigits = "0123456789ABCDEF"
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c != '%' {
			out = append(out, c)
			continue
		}
		if i+2 >= len(in) {
			return "", false
		}
		hi, okHi := unhex(in[i+1])
		lo, okLo := unhex(in[i+2])
		if !okHi || !okLo {
			return "", false
		}
		d := hi<<4 | lo
		if path && (d == '/' || d == '\\' || d == '.' || d == '%' || d < 0x20 || d == 0x7f) {
			return "", false
		}
		if unreserved(d) || (path && pathDecodable(d)) {
			out = append(out, d)
		} else {
			out = append(out, '%', hexdigits[hi], hexdigits[lo])
		}
		i += 2
	}
	return string(out), true
}

// normalizePath strips the query and fragment, normalizes percent escapes, and refuses forms a filter and a
// server could read differently: no leading slash, dot segments, empty segments, backslashes, encoded slashes,
// dots, backslashes or percent signs, controls, malformed escapes.
func normalizePath(p string) (string, bool) {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" || p[0] != '/' {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c <= ' ' || c >= 0x7f || c == '\\' {
			return "", false
		}
	}
	p, ok := normalizePercent(p, true)
	if !ok {
		return "", false
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

func matchPattern(pattern []segment, path string) bool {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, p := range pattern {
		if p.kind == segRest { // validated: only last
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

// queryCond requires one query parameter: present with one of values, or with any non-empty value when values is
// nil. A parameter that appears more than once never satisfies a condition (servers disagree on which one wins).
type queryCond struct {
	key    string
	values map[string]bool
}

// parseQuery splits the query into its parameters, with escapes of unreserved bytes decoded in keys and values (a
// malformed escape keeps its raw text); ok is false past maxQueryPairs.
func parseQuery(target string) (map[string][]string, bool) {
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
		if n, valid := normalizePercent(k, false); valid {
			k = n
		}
		if n, valid := normalizePercent(v, false); valid {
			v = n
		}
		out[k] = append(out[k], v)
	}
	return out, true
}

// matches reports whether every condition holds and, if so, the rule's precedence score for this request: the
// literal bytes of the path condition that hit, then the number of condition kinds. ambiguous is true when the
// rule holds only if an ambiguous field is read its way: a query parameter it reads is repeated, the content type
// it reads is malformed, or a path pattern holds only without a trailing slash. Servers disagree on those
// readings, so such a rule never picks a child and, if it would be the most specific, the child is undetermined.
func (r *rule) matches(req *Request, path, lower, ct string, query map[string][]string, headers map[string]bool) (hit bool, score int, ambiguous bool) {
	if r.methods != nil && !r.methods[req.Method] {
		return false, 0, false
	}
	if r.websocket && !req.WebSocket {
		return false, 0, false
	}
	pathScore := 0
	if r.pathPrefixes != nil || r.pathPatterns != nil {
		if r.foldCase {
			path = lower
		}
		hit := false
		for _, prefix := range r.pathPrefixes {
			if strings.HasPrefix(path, prefix) && len(prefix) > pathScore {
				hit, pathScore = true, len(prefix)
			}
		}
		for _, pattern := range r.pathPatterns {
			if matchPattern(pattern, path) {
				hit = true
				if n := literalBytes(pattern); n > pathScore {
					pathScore = n
				}
			}
		}
		if !hit && len(path) > 1 && path[len(path)-1] == '/' && r.pathPatterns != nil {
			trimmed := path[:len(path)-1]
			for _, pattern := range r.pathPatterns {
				if matchPattern(pattern, trimmed) {
					hit, ambiguous = true, true
					if n := literalBytes(pattern); n > pathScore {
						pathScore = n
					}
				}
			}
		}
		if !hit {
			return false, 0, false
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
			if req.ContentType == "" || ct != "" {
				return false, 0, false
			}
			ambiguous = true // a content type was sent but does not parse: the rule may hold for the server
		}
	}
	for _, q := range r.query {
		values := query[q.key]
		if len(values) > 1 {
			ambiguous = true // a repeated parameter: servers disagree on which one wins
			continue
		}
		if len(values) != 1 || values[0] == "" || (q.values != nil && !q.values[values[0]]) {
			return false, 0, false
		}
	}
	for _, h := range r.headers {
		if !headers[h] {
			return false, 0, false
		}
	}
	switch r.direction {
	case "upload":
		up, down := req.RequestBodyBytes, req.ResponseBodyBytes
		if up < 0 || up < r.minBytes || (down >= 0 && up <= down) {
			return false, 0, false
		}
	case "download":
		up, down := req.RequestBodyBytes, req.ResponseBodyBytes
		if down < 0 || down < r.minBytes || (up >= 0 && down <= up) {
			return false, 0, false
		}
	}
	return true, pathScore*16 + r.conditions, ambiguous
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
	res := Result{Basis: BasisNone, ChildStatus: appid.ChildNotApplicable, Release: s.Release.Version, PackRelease: s.pack.Release.Version}
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
	res.App, res.HostOwner, res.Basis = owner, owner, BasisServerName
	lists := s.candidates(host)
	// A refusal below is fail closed when a child rule of this host could apply: the function is undetermined.
	// With no rule on the host no child can apply whatever the request says, so it is none.
	refused := appid.ChildUndetermined
	if len(lists) == 0 {
		refused = appid.ChildNone
	}
	res.ChildStatus = refused
	if len(req.Method) > maxMethodBytes || len(req.ContentType) > maxContentTypeBytes {
		res.Reasons, res.Limit = []string{ReasonFieldTooLong}, LimitFieldBytes
		return res
	}
	if len(req.Path) > s.opts.MaxPathBytes {
		res.Reasons, res.Limit = []string{ReasonWorkLimit}, LimitPathBytes
		return res
	}
	path, canonical := normalizePath(req.Path)
	if !canonical && req.Path != "" {
		res.Reasons = []string{ReasonPathNotCanonical}
		return res
	}
	ct := mediaType(req.ContentType)
	query, ok := parseQuery(req.Path)
	if !ok || len(req.HeaderNames) > maxHeaderNames {
		res.Reasons, res.Limit = []string{ReasonFieldTooLong}, LimitFieldBytes
		return res
	}
	var headers map[string]bool
	if len(req.HeaderNames) > 0 {
		headers = make(map[string]bool, len(req.HeaderNames))
		for _, h := range req.HeaderNames {
			headers[strings.ToLower(h)] = true
		}
	}
	lower := path
	if s.foldCase {
		lower = strings.ToLower(path) // no copy when the path has no upper case
	}
	heads := make([]int, len(lists))
	last := -1
	var winner *rule
	winnerScore, winnerAmbiguous := 0, false
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
			res.Reasons, res.Limit = []string{ReasonWorkLimit}, LimitRuleEvaluations
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
		// Precedence: the highest score wins; on a tie the earlier rule (file order) keeps it. An ambiguous rule
		// competes too: if it would win, no reading of the request decides the child.
		if hit, score, ambiguous := r.matches(&req, path, lower, ct, query, headers); hit && (winner == nil || score > winnerScore) {
			winner, winnerScore, winnerAmbiguous = r, score, ambiguous
		}
	}
	if winner == nil {
		res.Reasons, res.ChildStatus = []string{ReasonNoChildMatched}, appid.ChildNone
		return res
	}
	if winnerAmbiguous {
		res.Reasons = []string{ReasonAmbiguous}
		return res
	}
	res.App, res.Container, res.Basis = winner.child.Name, winner.child.Container, BasisRequestRule
	res.Rule = fmt.Sprintf("%s#%d", winner.child.Name, winner.index)
	res.Reasons, res.ChildStatus = []string{ReasonChildMatched}, appid.ChildMatched
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
	v := &appid.Verdict{App: app.Name, Category: app.Category, Subcategory: app.Subcategory, Technology: app.Technology,
		Risk: app.Risk, Characteristics: append([]string{}, app.Characteristics...),
		ImplicitlyUses: append([]string{}, app.ImplicitlyUses...), PortUsage: "unknown", Status: "identified",
		Reasons: reasons, Risks: []string{}, ChildStatus: res.ChildStatus}
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
