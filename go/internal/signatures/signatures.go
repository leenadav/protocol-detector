// Package signatures ports protocol_engine/signatures.py: custom application signatures evaluated over bounded parser
// contexts. A set is compiled once from JSON and shared. A signature is evaluated only after a parser completed its
// structural profile (or after an unknown prefix of bounded size was collected), against the small map of named
// contexts the parser exposed; contexts never leave the engine and a match contributes only the signature's name and
// catalog metadata. Patterns follow the reference's rules exactly (pattern.go); a construct the Go backend cannot
// express faithfully makes the whole set NotPorted instead of matching differently.
package signatures

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/ojson"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// Limits of signatures.py.
const (
	maxPattern    = 512
	maxSignatures = 4096
	maxConditions = 64
	maxDepth      = 4
)

// Contexts maps the reference's context names (a fixed table) to (kind, owning family).
var Contexts = map[string][2]string{
	"http-req-method": {"text", "http"}, "http-req-uri-path": {"text", "http"}, "http-req-version": {"text", "http"},
	"http-req-host-header": {"text", "http"}, "http-req-user-agent-header": {"text", "http"}, "http-req-headers": {"raw", "http"},
	"http-rsp-status": {"integer", "http"}, "http-rsp-reason": {"text", "http"}, "http-req-content-length": {"integer", "http"},
	"http2-req-method": {"text", "http2"}, "http2-req-uri-path": {"text", "http2"}, "http2-req-host-header": {"text", "http2"},
	"http2-req-user-agent-header": {"text", "http2"}, "http2-req-headers": {"raw", "http2"}, "http2-rsp-status": {"integer", "http2-server"},
	"ssl-req-chello-sni": {"text", "tls"}, "ssl-req-alpn": {"text", "tls"}, "ssl-req-client-hello": {"raw", "tls"},
	"ssl-req-client-hello-ext-type": {"set", "tls"}, "ssl-req-cipher-suite": {"set", "tls"}, "ssl-req-version": {"integer", "tls"},
	"ssh-req-banner": {"text", "ssh"}, "smtp-req-argument": {"text", "smtp"}, "dns-req-query-name": {"text", "dns"},
	"dns-req-query-type": {"integer", "dns"}, "socks-req-target": {"text", "socks5"}, "socks-req-port": {"integer", "socks5"},
	"unknown-req-tcp-payload": {"raw", "unknown-tcp"}, "unknown-req-tcp-payload-length": {"integer", "unknown-tcp"},
	"unknown-req-udp-payload": {"raw", "unknown-udp"}, "unknown-req-udp-payload-length": {"integer", "unknown-udp"},
}

// Values are a parser's contexts: []byte for text/raw, int64 for integer, map[int64]bool for set.
type Values = parsing.Contexts

// Error is a signature document the reference rejects (SignatureError).
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

func fail(format string, a ...interface{}) error { return &Error{fmt.Sprintf(format, a...)} }

// --- conditions ---

type condition struct {
	context, kind, operator string
	negate, ignorecase      bool
	pattern                 *compiledPattern
	text                    []byte
	number                  int64
}

func truthy(v interface{}) bool { // Python bool() of a JSON value
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, _ := x.Float64()
		return f != 0
	case []interface{}:
		return len(x) > 0
	case map[string]interface{}:
		return len(x) > 0
	}
	return true
}

// pyInt is a JSON value Python reads as an int (not bool, not float).
func pyInt(v interface{}) (*big.Int, bool) {
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(string(n), ".eE") {
		return nil, false
	}
	b, ok := new(big.Int).SetString(string(n), 10)
	return b, ok
}

func latin1Bytes(s string) ([]byte, bool) {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 255 {
			return nil, false
		}
		out = append(out, byte(r))
	}
	return out, true
}

func lowerASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = byte(lowerByte(int(c)))
	}
	return out
}

func newCondition(data interface{}) (*condition, error) {
	m, ok := data.(map[string]interface{})
	if !ok {
		return nil, fail("Condition requires a context")
	}
	raw, ok := m["context"]
	if !ok {
		return nil, fail("Condition requires a context")
	}
	name, _ := raw.(string)
	spec, ok := Contexts[name]
	if !ok {
		return nil, fail("Unknown context: %s", pyStr(raw))
	}
	c := &condition{context: name, kind: spec[0], operator: "pattern-match"}
	if op, present := m["operator"]; present {
		s, _ := op.(string)
		if s != "pattern-match" && s != "equal-to" && s != "less-than" && s != "greater-than" {
			return nil, fail("Unknown operator: %s", pyStr(op))
		}
		c.operator = s
	}
	c.negate, c.ignorecase = truthy(m["negate"]), truthy(m["case_insensitive"])
	switch {
	case c.operator == "pattern-match":
		if c.kind == "integer" || c.kind == "set" {
			return nil, fail("pattern-match requires a text or raw context")
		}
		pattern, isString := m["pattern"].(string)
		if !isString {
			return nil, fail("Pattern must contain 1..%d characters", maxPattern)
		}
		compiled, err := compilePattern(pattern, c.kind, c.ignorecase)
		if err != nil {
			if pe, ok := err.(*patternError); ok {
				return nil, &Error{pe.msg}
			}
			return nil, &parsing.NotPorted{What: err.Error()}
		}
		c.pattern = compiled
	case c.kind == "integer" || c.kind == "set":
		n, ok := pyInt(m["value"])
		if !ok || n.Sign() < 0 || n.Cmp(new(big.Int).Lsh(big.NewInt(1), 32)) > 0 {
			return nil, fail("Integer condition requires an integer value")
		}
		if c.kind == "set" && c.operator != "equal-to" {
			return nil, fail("Set contexts support equal-to (membership) only")
		}
		c.number = n.Int64()
	default:
		if c.operator != "equal-to" {
			return nil, fail("Text contexts support pattern-match and equal-to")
		}
		value, isString := m["value"].(string)
		if !isString || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > maxPattern {
			return nil, fail("equal-to requires a text value")
		}
		b, ok := latin1Bytes(value)
		if !ok {
			return nil, fail("equal-to value must be Latin-1 encodable")
		}
		if c.ignorecase {
			b = lowerASCII(b)
		}
		c.text = b
	}
	return c, nil
}

func (c *condition) evaluate(values Values) bool {
	value, ok := values[c.context]
	if !ok || value == nil {
		return false // absent context: never a match, negate does not apply
	}
	var result bool
	switch {
	case c.operator == "pattern-match":
		haystack := value.([]byte)
		probe := haystack
		if c.ignorecase {
			probe = lowerASCII(haystack)
		}
		result = bytes.Contains(probe, c.pattern.anchor) && c.pattern.search(haystack)
	case c.kind == "set":
		result = value.(map[int64]bool)[c.number]
	case c.kind == "integer":
		v := value.(int64)
		switch c.operator {
		case "equal-to":
			result = v == c.number
		case "less-than":
			result = v < c.number
		default:
			result = v > c.number
		}
	default:
		v := value.([]byte)
		if c.ignorecase {
			v = lowerASCII(v)
		}
		result = bytes.Equal(v, c.text)
	}
	return result != c.negate
}

// --- groups and signatures ---

type member struct {
	group     *group
	condition *condition
}

type group struct {
	and     bool
	members []member
}

func newGroup(data interface{}, counter *int, depth int) (*group, error) {
	if depth > maxDepth {
		return nil, fail("Condition nesting exceeds %d levels", maxDepth)
	}
	m, ok := data.(map[string]interface{})
	var key string
	if ok && len(m) == 1 {
		for k := range m {
			key = k
		}
	}
	if !ok || len(m) != 1 || (key != "and" && key != "or") {
		return nil, fail("Group requires exactly one of 'and'/'or'")
	}
	list, ok := m[key].([]interface{})
	if !ok || len(list) == 0 {
		return nil, fail("Group needs a nonempty list of conditions")
	}
	g := &group{and: key == "and"}
	for _, item := range list {
		*counter++
		if *counter > maxConditions {
			return nil, fail("Signature exceeds %d conditions", maxConditions)
		}
		if im, isMap := item.(map[string]interface{}); isMap && (im["and"] != nil || im["or"] != nil || hasKey(im, "and") || hasKey(im, "or")) {
			sub, err := newGroup(item, counter, depth+1)
			if err != nil {
				return nil, err
			}
			g.members = append(g.members, member{group: sub})
		} else {
			c, err := newCondition(item)
			if err != nil {
				return nil, err
			}
			g.members = append(g.members, member{condition: c})
		}
	}
	return g, nil
}

func hasKey(m map[string]interface{}, k string) bool { _, ok := m[k]; return ok }

func (g *group) evaluate(values Values) bool {
	for _, m := range g.members {
		var r bool
		if m.group != nil {
			r = m.group.evaluate(values)
		} else {
			r = m.condition.evaluate(values)
		}
		if g.and && !r {
			return false
		}
		if !g.and && r {
			return true
		}
	}
	return g.and
}

func (g *group) leaves(out *[]*condition) {
	for _, m := range g.members {
		if m.group != nil {
			m.group.leaves(out)
		} else {
			*out = append(*out, m.condition)
		}
	}
}

// Signature is one compiled signature with its catalog metadata.
type Signature struct {
	Name, Category, Subcategory, Technology, Parent, Description string
	HasParent                                                    bool
	Risk                                                         int
	Characteristics                                              []string
	root                                                         *group
	families                                                     map[string]bool
}

func newSignature(data interface{}, pack *content.Pack) (*Signature, error) {
	m, ok := data.(map[string]interface{})
	if !ok {
		return nil, fail("Signature must be an object")
	}
	name, isString := m["name"].(string)
	if !isString || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 128 || strings.IndexFunc(name, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return nil, fail("Signature name must contain 1..128 printable characters")
	}
	s := &Signature{Name: name, Category: "custom", Subcategory: "custom-signature", Technology: "client-server", Risk: 3}
	if v, ok := m["category"]; ok {
		s.Category, _ = v.(string)
		if _, isStr := v.(string); !isStr {
			return nil, fail("Unknown category/subcategory in %s", name)
		}
	}
	if v, ok := m["subcategory"]; ok {
		s.Subcategory, _ = v.(string)
		if _, isStr := v.(string); !isStr {
			return nil, fail("Unknown category/subcategory in %s", name)
		}
	}
	subs, known := pack.Categories[s.Category]
	if !known || !containsString(subs, s.Subcategory) {
		return nil, fail("Unknown category/subcategory in %s", name)
	}
	if v, ok := m["technology"]; ok {
		t, isStr := v.(string)
		if !isStr || !pack.Technologies[t] {
			return nil, fail("Unknown technology in %s", name)
		}
		s.Technology = t
	} else if !pack.Technologies[s.Technology] {
		return nil, fail("Unknown technology in %s", name)
	}
	if v, ok := m["risk"]; ok {
		n, isInt := pyInt(v)
		if !isInt || !n.IsInt64() || n.Int64() < 1 || n.Int64() > 5 {
			return nil, fail("Risk must be 1..5 in %s", name)
		}
		s.Risk = int(n.Int64())
	}
	if v, ok := m["characteristics"]; ok {
		switch x := v.(type) {
		case []interface{}:
			for _, item := range x {
				str, isStr := item.(string)
				if !isStr || !pack.Characteristics[str] {
					return nil, fail("Unknown characteristic in %s", name)
				}
				s.Characteristics = append(s.Characteristics, str)
			}
		case string:
			for _, r := range x {
				if !pack.Characteristics[string(r)] {
					return nil, fail("Unknown characteristic in %s", name)
				}
				s.Characteristics = append(s.Characteristics, string(r))
			}
		case map[string]interface{}:
			for _, k := range sortedKeysInsertion(x) {
				if !pack.Characteristics[k] {
					return nil, fail("Unknown characteristic in %s", name)
				}
				s.Characteristics = append(s.Characteristics, k)
			}
		default:
			return nil, &parsing.NotPorted{What: "signature characteristics of a non-iterable type"}
		}
	}
	if v, ok := m["parent"]; ok && v != nil {
		p, isStr := v.(string)
		if !isStr {
			return nil, fail("Parent must be an application name")
		}
		s.Parent, s.HasParent = p, true
	}
	if v, ok := m["description"]; ok {
		text, err := pyStrValue(v)
		if err != nil {
			return nil, err
		}
		if r := []rune(text); len(r) > 256 {
			text = string(r[:256])
		}
		s.Description = text
	}
	if v, ok := m["scope"]; ok {
		if str, isStr := v.(string); !isStr || str != "transaction" {
			return nil, fail("Only transaction scope is supported in %s", name)
		}
	}
	conditions := m["conditions"]
	if list, isList := conditions.([]interface{}); isList {
		conditions = map[string]interface{}{"and": list}
	}
	counter := 0
	root, err := newGroup(conditions, &counter, 1)
	if err != nil {
		return nil, err
	}
	s.root, s.families = root, map[string]bool{}
	var leaves []*condition
	root.leaves(&leaves)
	positive := false
	for _, c := range leaves {
		s.families[Contexts[c.context][1]] = true
		positive = positive || !c.negate
	}
	if !positive {
		return nil, fail("Signature needs at least one non-negated condition: %s", name)
	}
	return s, nil
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// exactKey is signatures._exact_key: a top-level AND member that is a case-sensitive, non-negated equal-to on a
// text context, or ok=false.
func (s *Signature) exactKey() (string, string, bool) {
	if !s.root.and {
		return "", "", false
	}
	for _, m := range s.root.members {
		c := m.condition
		if c != nil && c.operator == "equal-to" && c.kind == "text" && !c.negate && !c.ignorecase {
			return c.context, string(c.text), true
		}
	}
	return "", "", false
}

// --- the set ---

type indexed struct {
	position  int
	signature *Signature
}

type familyIndex struct {
	exact      map[string]map[string][]indexed
	exactOrder []string // contexts in first-seen order (dict order)
	scan       []indexed
}

// Set is signatures.SignatureSet.
type Set struct {
	byFamily map[string][]*Signature
	index    map[string]*familyIndex
	byName   map[string]*Signature
	Digest   string
	Count    int
}

// FromJSON is SignatureSet.from_json over a content pack's vocabularies. It also applies from_path's MaxFile
// limit before decoding, so no caller can make it materialize a larger document; every CLI path already reads
// through ReadFile, which enforces the same limit with the same message.
func FromJSON(text []byte, pack *content.Pack) (*Set, error) {
	if len(text) > MaxFile {
		return nil, fail("Signature file exceeds 4 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(text))
	decoder.UseNumber()
	var document interface{}
	if err := decoder.Decode(&document); err != nil {
		return nil, fail("Invalid JSON: %v", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fail("Invalid JSON: extra data")
	}
	if m, isMap := document.(map[string]interface{}); isMap {
		if v, ok := m["version"]; ok && !equalsOne(v) {
			return nil, fail("Unsupported signature file version")
		}
		document = m["signatures"]
		if _, ok := m["signatures"]; !ok {
			document = []interface{}{}
		}
	}
	list, isList := document.([]interface{})
	if !isList {
		return nil, fail("Signature document must be a list or an object with 'signatures'")
	}
	set := &Set{byFamily: map[string][]*Signature{}, index: map[string]*familyIndex{}, byName: map[string]*Signature{}}
	hasher := sha256.New()
	byFamily := map[string][]indexed{}
	var familyOrder []string
	var ordered []ojson.Value // the items in Python's key order, decoded only when a description is a container
	for i, item := range list {
		built := item
		if m, isMap := item.(map[string]interface{}); isMap {
			if d, ok := m["description"]; ok && isContainer(d) {
				if ordered == nil {
					ordered = orderedItems(text)
				}
				if i < len(ordered) {
					if o, isObject := ordered[i].(*ojson.Object); isObject {
						if dv, ok := o.Get("description"); ok {
							copied := make(map[string]interface{}, len(m))
							for k, v := range m {
								copied[k] = v
							}
							copied["description"] = pyValueRepr(dv) // str() of a dict or list is its repr
							built = copied
						}
					}
				}
			}
		}
		s, err := newSignature(built, pack)
		if err != nil {
			return nil, err
		}
		set.Count++
		if set.Count > maxSignatures {
			return nil, fail("Signature count exceeds %d", maxSignatures)
		}
		if _, dup := set.byName[s.Name]; dup {
			return nil, fail("Duplicate signature name: %s", s.Name)
		}
		set.byName[s.Name] = s
		dumped, err := pyDumps(item)
		if err != nil {
			return nil, err
		}
		hasher.Write([]byte(dumped))
		hasher.Write([]byte{0})
		for _, family := range sortedFamilies(s) {
			if _, seen := byFamily[family]; !seen {
				familyOrder = append(familyOrder, family)
			}
			byFamily[family] = append(byFamily[family], indexed{set.Count - 1, s})
		}
	}
	for _, family := range familyOrder {
		items := byFamily[family]
		fi := &familyIndex{exact: map[string]map[string][]indexed{}}
		for _, it := range items {
			set.byFamily[family] = append(set.byFamily[family], it.signature)
			if ctx, value, ok := it.signature.exactKey(); ok {
				if fi.exact[ctx] == nil {
					fi.exact[ctx] = map[string][]indexed{}
					fi.exactOrder = append(fi.exactOrder, ctx)
				}
				fi.exact[ctx][value] = append(fi.exact[ctx][value], it)
			} else {
				fi.scan = append(fi.scan, it)
			}
		}
		set.index[family] = fi
	}
	set.Digest = hex.EncodeToString(hasher.Sum(nil))[:16]
	return set, nil
}

// equalsOne is Python's `value == 1` for a JSON value: 1, 1.0 and true compare equal.
func equalsOne(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if _, isInt := pyInt(x); isInt {
			b, _ := new(big.Int).SetString(string(x), 10)
			return b.Cmp(big.NewInt(1)) == 0
		}
		return err == nil && f == 1
	}
	return false
}

func sortedFamilies(s *Signature) []string {
	out := make([]string, 0, len(s.families))
	for f := range s.families {
		out = append(out, f)
	}
	sort.Strings(out) // a signature's families only select index lists; their order does not matter
	return out
}

// Len is the number of signatures.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.byName)
}

// Wants reports whether any signature reads a context of family.
func (s *Set) Wants(family string) bool {
	if s == nil {
		return false
	}
	_, ok := s.byFamily[family]
	return ok
}

// Get returns the signature named name.
func (s *Set) Get(name string) *Signature {
	if s == nil {
		return nil
	}
	return s.byName[name]
}

func (s *Set) candidates(family string, values Values) []*Signature {
	fi := s.index[family]
	if fi == nil {
		return nil
	}
	var hits []indexed
	for _, ctx := range fi.exactOrder {
		if v, ok := values[ctx]; ok && v != nil {
			if b, isBytes := v.([]byte); isBytes {
				hits = append(hits, fi.exact[ctx][string(b)]...)
			}
		}
	}
	if len(hits) == 0 {
		out := make([]*Signature, len(fi.scan))
		for i, it := range fi.scan {
			out[i] = it.signature
		}
		return out
	}
	merged := append(append([]indexed{}, hits...), fi.scan...)
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].position < merged[j].position })
	out := make([]*Signature, len(merged))
	for i, it := range merged {
		out[i] = it.signature
	}
	return out
}

// MatchCounted is SignatureSet.match_counted: the first matching signature (definition order) and how many
// candidates were evaluated.
func (s *Set) MatchCounted(family string, values Values) (*Signature, int) {
	if s == nil {
		return nil, 0
	}
	evaluated := 0
	for _, sig := range s.candidates(family, values) {
		evaluated++
		if sig.root.evaluate(values) {
			return sig, evaluated
		}
	}
	return nil, evaluated
}

func isContainer(v interface{}) bool {
	switch v.(type) {
	case map[string]interface{}, []interface{}:
		return true
	}
	return false
}

// orderedItems is the signature list of the document in Python's key order (json.loads keeps insertion order,
// a repeated key keeps its first position), or nil when the ordered decoder refuses the document.
func orderedItems(text []byte) []ojson.Value {
	v, err := ojson.Decode(text)
	if err != nil {
		return nil
	}
	if o, isObject := v.(*ojson.Object); isObject {
		v, _ = o.Get("signatures")
	}
	list, _ := v.([]ojson.Value)
	return list
}

// pyValueRepr is Python's repr() of a decoded JSON value (str() of a dict or list is the repr of its contents).
func pyValueRepr(v ojson.Value) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case ojson.Int:
		return string(x)
	case float64:
		switch {
		case math.IsNaN(x):
			return "nan"
		case math.IsInf(x, 1):
			return "inf"
		case math.IsInf(x, -1):
			return "-inf"
		}
		return pyFloatRepr(x)
	case string:
		return pyStrRepr(x)
	case []ojson.Value:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = pyValueRepr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *ojson.Object:
		parts := make([]string, 0, x.Len())
		for _, k := range x.Keys() {
			e, _ := x.Get(k)
			parts = append(parts, pyStrRepr(k)+": "+pyValueRepr(e))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return ""
}

// pyStrRepr is repr(str): quotes chosen as Python chooses them, printable characters as they are, the rest
// escaped (\xNN, \uNNNN, \UNNNNNNNN); lone surrogates (WTF-8 from ojson) are \udNNN.
func pyStrRepr(s string) string {
	quote := byte('\'')
	if strings.IndexByte(s, '\'') >= 0 && strings.IndexByte(s, '"') < 0 {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 && i+2 < len(s) && s[i] == 0xed {
			r = rune(s[i]&0x0f)<<12 | rune(s[i+1]&0x3f)<<6 | rune(s[i+2]&0x3f)
			size = 3
		}
		i += size
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case r >= 0xd800 && r <= 0xdfff || !unicode.IsPrint(r):
			switch {
			case r <= 0xff:
				fmt.Fprintf(&b, `\x%02x`, r)
			case r <= 0xffff:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// --- Python json.dumps(item, sort_keys=True) and str() for the digest and descriptions ---

func pyStr(v interface{}) string {
	text, err := pyStrValue(v)
	if err != nil {
		return "?"
	}
	return text
}

func pyStrValue(v interface{}) (string, error) {
	switch x := v.(type) {
	case nil:
		return "None", nil
	case bool:
		if x {
			return "True", nil
		}
		return "False", nil
	case string:
		return x, nil
	case json.Number:
		if _, isInt := pyInt(x); isInt {
			b, _ := new(big.Int).SetString(string(x), 10)
			return b.String(), nil
		}
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return "", &parsing.NotPorted{What: "a non-finite JSON number"}
		}
		return pyFloatRepr(f), nil
	}
	return "", &parsing.NotPorted{What: "str() of a JSON container in a signature description"}
}

// pyFloatRepr is Python's repr(float): the shortest round-trip digits, fixed notation for 1e-4 <= |x| < 1e16.
func pyFloatRepr(f float64) string {
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	mantissa, expText, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expText)
	sign := ""
	if strings.HasPrefix(mantissa, "-") {
		sign, mantissa = "-", mantissa[1:]
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	decpt := exp + 1
	if -4 < decpt && decpt <= 16 {
		switch {
		case decpt <= 0:
			return sign + "0." + strings.Repeat("0", -decpt) + digits
		case decpt >= len(digits):
			return sign + digits + strings.Repeat("0", decpt-len(digits)) + ".0"
		default:
			return sign + digits[:decpt] + "." + digits[decpt:]
		}
	}
	out := digits[:1]
	if len(digits) > 1 {
		out += "." + digits[1:]
	}
	es := "+"
	if exp < 0 {
		es, exp = "-", -exp
	}
	return fmt.Sprintf("%s%se%s%02d", sign, out, es, exp)
}

func pyString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || r > 0x7e: // json.dumps ensure_ascii escapes everything outside space..tilde, DEL included
			if r > 0xffff {
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func sortedKeysInsertion(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// pyDumps is json.dumps(value, sort_keys=True) with the default separators and ensure_ascii.
func pyDumps(v interface{}) (string, error) {
	switch x := v.(type) {
	case nil:
		return "null", nil
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	case string:
		return pyString(x), nil
	case json.Number:
		if _, isInt := pyInt(x); isInt {
			b, _ := new(big.Int).SetString(string(x), 10)
			return b.String(), nil
		}
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil || math.IsInf(f, 0) {
			return "", &parsing.NotPorted{What: "a non-finite JSON number"}
		}
		return pyFloatRepr(f), nil
	case []interface{}:
		parts := make([]string, len(x))
		for i, item := range x {
			s, err := pyDumps(item)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return pyLess(keys[i], keys[j]) })
		parts := make([]string, len(keys))
		for i, k := range keys {
			s, err := pyDumps(x[k])
			if err != nil {
				return "", err
			}
			parts[i] = pyString(k) + ": " + s
		}
		return "{" + strings.Join(parts, ", ") + "}", nil
	}
	return "", &parsing.NotPorted{What: "an unexpected JSON value"}
}

// pyLess orders strings by code point, as Python's str comparison does (Go's byte order agrees for valid UTF-8).
func pyLess(a, b string) bool { return a < b }

// MaxFile is SignatureSet.from_path's size limit.
const MaxFile = 4 * 1024 * 1024

// ReadFile ports the reading half of SignatureSet.from_path: at most MaxFile bytes of UTF-8 text.
func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFile {
		return nil, fail("Signature file exceeds 4 MiB")
	}
	if !utf8.Valid(data) {
		return nil, fail("Signature file is not UTF-8")
	}
	return data, nil
}
