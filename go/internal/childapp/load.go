package childapp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/errs"
)

// Component limits, checked when the file loads.
const (
	MaxFileBytes      = 4 << 20
	MaxChildren       = 4096
	MaxRulesPerChild  = 32
	MaxRules          = 16384
	MaxListEntries    = 32
	MaxEntryBytes     = 256
	MaxPatternSegment = 32
	MaxEvidence       = 8
)

//go:embed childapps.json
var embedded []byte

// Embedded loads the child-app component built into the binary over pack.
func Embedded(pack *content.Pack) (*Set, error) { return Load(embedded, pack, Options{}) }

// Builtin loads the built-in content pack and component with opts. It is what the public facade uses, so the
// facade never holds the pack itself (the pin's immutability boundary, internal/content/immutable_test.go).
func Builtin(opts Options) (*Set, error) {
	pack, err := content.Embedded()
	if err != nil {
		return nil, err
	}
	return Load(embedded, pack, opts)
}

// EmbeddedBytes is a copy of the built-in component file.
func EmbeddedBytes() []byte { return append([]byte(nil), embedded...) }

func invalid(format string, a ...interface{}) error {
	return errs.New(errs.Invalid, errs.ScopeProcess, "child apps: "+fmt.Sprintf(format, a...))
}

// object decodes one JSON object with exact, unique keys out of allowed (encoding/json would match keys case
// insensitively and keep the last of a repeated key).
func object(raw json.RawMessage, allowed []string, required ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("not an object")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		found := false
		for _, a := range allowed {
			found = found || a == key
		}
		if !found {
			return nil, fmt.Errorf("unknown key %q", key)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("repeated key %q", key)
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		out[key] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("extra data")
	}
	for _, r := range required {
		if _, ok := out[r]; !ok {
			return nil, fmt.Errorf("missing key %q", r)
		}
	}
	return out, nil
}

func str(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("not a string")
	}
	return s, nil
}

func strs(raw json.RawMessage, limit int) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil || list == nil {
		return nil, fmt.Errorf("not a list of strings")
	}
	if len(list) == 0 || len(list) > limit {
		return nil, fmt.Errorf("list must have 1..%d entries", limit)
	}
	seen := map[string]bool{}
	for _, s := range list {
		if s == "" || len(s) > MaxEntryBytes {
			return nil, fmt.Errorf("entries must be 1..%d bytes", MaxEntryBytes)
		}
		if seen[s] {
			return nil, fmt.Errorf("repeated entry %q", s)
		}
		seen[s] = true
	}
	return list, nil
}

func validName(s string) bool {
	if s == "" || len(s) > 64 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func validMethod(s string) bool {
	if s == "" || len(s) > maxMethodBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'A' && c <= 'Z' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// Load parses and validates a component file over pack. A failure refuses the whole file.
func Load(data []byte, pack *content.Pack, opts Options) (*Set, error) {
	if pack == nil {
		return nil, invalid("no content pack")
	}
	if len(data) > MaxFileBytes {
		return nil, invalid("file exceeds %d bytes", MaxFileBytes)
	}
	top, err := object(data, []string{"schema", "release", "children"}, "schema", "release", "children")
	if err != nil {
		return nil, invalid("%v", err)
	}
	if string(bytes.TrimSpace(top["schema"])) != "1" {
		return nil, invalid("unsupported schema")
	}
	rel, err := object(top["release"], []string{"version", "note", "review"}, "version", "note", "review")
	if err != nil {
		return nil, invalid("release: %v", err)
	}
	s := &Set{Digest: digestOf(data), pack: pack, byName: map[string]*Child{}, exact: map[string][]int{},
		suffix: map[string][]int{}, opts: normalize(opts)}
	for key, target := range map[string]*string{"version": &s.Release.Version, "note": &s.Release.Note, "review": &s.Release.Review} {
		if *target, err = str(rel[key]); err != nil || *target == "" || len(*target) > 512 {
			return nil, invalid("release %s must be a string of 1..512 bytes", key)
		}
	}
	if !validVersion(s.Release.Version) {
		return nil, invalid("release version must be YYYY.MM.N")
	}
	var children []json.RawMessage
	if err := json.Unmarshal(top["children"], &children); err != nil || children == nil {
		return nil, invalid("children must be a list")
	}
	if len(children) > MaxChildren {
		return nil, invalid("at most %d children", MaxChildren)
	}
	for i, raw := range children {
		if err := s.addChild(i, raw); err != nil {
			return nil, err
		}
	}
	for host, l := range s.exact {
		s.exact[host] = sortedUnique(l)
	}
	for host, l := range s.suffix {
		s.suffix[host] = sortedUnique(l)
	}
	return s, nil
}

func validVersion(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 || len(parts[0]) != 4 || len(parts[1]) != 2 || len(parts[2]) != 1 {
		return false
	}
	for _, p := range parts {
		if strings.Trim(p, "0123456789") != "" {
			return false
		}
	}
	return parts[1] >= "01" && parts[1] <= "12"
}

var childKeys = []string{"name", "container", "description", "risk", "characteristics", "depends_on", "evidence", "rules"}
var ruleKeys = []string{"hosts", "host_suffixes", "methods", "path_prefixes", "path_patterns", "content_types",
	"direction", "min_bytes", "websocket"}

func (s *Set) addChild(i int, raw json.RawMessage) error {
	doc, err := object(raw, childKeys, "name", "container", "description", "evidence", "rules")
	if err != nil {
		return invalid("child %d: %v", i, err)
	}
	c := &Child{}
	if c.Name, err = str(doc["name"]); err != nil || !validName(c.Name) {
		return invalid("child %d: name must be 1..64 of a-z, 0-9 and '-'", i)
	}
	fail := func(format string, a ...interface{}) error {
		return invalid("child '%s': %s", c.Name, fmt.Sprintf(format, a...))
	}
	if _, taken := s.byName[c.Name]; taken {
		return fail("repeated name")
	}
	if _, taken := s.pack.Applications[c.Name]; taken || s.pack.Outcomes[c.Name] {
		return fail("name is already a catalog application")
	}
	if _, taken := s.pack.Aliases[c.Name]; taken {
		return fail("name is already a catalog alias")
	}
	if c.Container, err = str(doc["container"]); err != nil {
		return fail("container must be a string")
	}
	parent := s.pack.Applications[c.Container]
	if parent == nil || s.pack.Outcomes[c.Container] {
		return fail("container '%s' is not a catalog application", c.Container)
	}
	if !strings.HasPrefix(c.Name, c.Container+"-") {
		return fail("name must start with its container '%s-'", c.Container)
	}
	if c.Description, err = str(doc["description"]); err != nil || c.Description == "" || len(c.Description) > 512 {
		return fail("description must be 1..512 bytes")
	}
	c.Risk = parent.Risk
	if raw, ok := doc["risk"]; ok {
		if err := json.Unmarshal(raw, &c.Risk); err != nil || c.Risk < 1 || c.Risk > 5 || strings.ContainsAny(string(raw), ".eE") {
			return fail("risk must be an integer 1..5")
		}
	}
	c.Characteristics = append([]string{}, parent.Characteristics...)
	if raw, ok := doc["characteristics"]; ok {
		if c.Characteristics, err = strs(raw, MaxListEntries); err != nil {
			return fail("characteristics: %v", err)
		}
		for _, ch := range c.Characteristics {
			if !s.pack.Characteristics[ch] {
				return fail("unknown characteristic '%s'", ch)
			}
		}
	}
	c.DependsOn = []string{}
	if raw, ok := doc["depends_on"]; ok {
		if c.DependsOn, err = strs(raw, MaxListEntries); err != nil {
			return fail("depends_on: %v", err)
		}
		for _, d := range c.DependsOn {
			if s.pack.Applications[d] == nil || s.pack.Outcomes[d] || d == c.Container {
				return fail("depends_on '%s' must be another catalog application", d)
			}
		}
	}
	if c.Evidence, err = strs(doc["evidence"], MaxEvidence); err != nil {
		return fail("evidence: %v", err)
	}
	for _, e := range c.Evidence {
		if !strings.HasPrefix(e, "https://") || strings.ContainsAny(e, " \t\r\n") {
			return fail("evidence must be https:// links to the official documentation")
		}
	}
	c.ImplicitlyUses = []string{c.Container}
	for _, u := range parent.ImplicitlyUses {
		if u != c.Container {
			c.ImplicitlyUses = append(c.ImplicitlyUses, u)
		}
	}
	container := c.Container
	c.app = &content.Application{Name: c.Name, Category: parent.Category, Subcategory: parent.Subcategory,
		Technology: parent.Technology, Risk: c.Risk, Description: c.Description, Characteristics: c.Characteristics,
		StandardPorts: []string{}, SecurePorts: []string{}, ImplicitlyUses: c.ImplicitlyUses, DependsOn: c.DependsOn,
		Container: &container, Aliases: []string{}}
	var rules []json.RawMessage
	if err := json.Unmarshal(doc["rules"], &rules); err != nil || len(rules) == 0 || len(rules) > MaxRulesPerChild {
		return fail("rules must be a list of 1..%d rules", MaxRulesPerChild)
	}
	owners := map[string]bool{c.Container: true}
	for _, d := range c.DependsOn {
		owners[d] = true
	}
	for j, raw := range rules {
		if len(s.rules) >= MaxRules {
			return fail("the component has more than %d rules", MaxRules)
		}
		if err := s.addRule(c, j, raw, owners); err != nil {
			return fail("rule %d: %v", j, err)
		}
	}
	s.byName[c.Name] = c
	s.children = append(s.children, c)
	return nil
}

func (s *Set) addRule(c *Child, j int, raw json.RawMessage, owners map[string]bool) error {
	doc, err := object(raw, ruleKeys)
	if err != nil {
		return err
	}
	r := &rule{child: c, index: j, order: len(s.rules)}
	hosts, err := strs(doc["hosts"], MaxListEntries)
	if err != nil {
		return fmt.Errorf("hosts: %v", err)
	}
	suffixes, err := strs(doc["host_suffixes"], MaxListEntries)
	if err != nil {
		return fmt.Errorf("host_suffixes: %v", err)
	}
	if len(hosts)+len(suffixes) == 0 {
		return fmt.Errorf("a rule needs hosts or host_suffixes")
	}
	check := func(h string) error {
		n, ok := normalizeHost(h)
		if !ok || n != h || strings.Contains(h, ":") {
			return fmt.Errorf("host '%s' must be a lower-case DNS name without port", h)
		}
		owner, kind, attributed := s.pack.AttributionForHost(h)
		if !attributed || kind != "service" || !owners[owner] {
			return fmt.Errorf("host '%s' is not claimed by '%s' or its depends_on in the server-name catalog", h, c.Container)
		}
		return nil
	}
	for _, h := range hosts {
		if err := check(h); err != nil {
			return err
		}
	}
	for _, h := range suffixes {
		if err := check(h); err != nil {
			return err
		}
	}
	functional := false
	if raw, ok := doc["methods"]; ok {
		list, err := strs(raw, MaxListEntries)
		if err != nil {
			return fmt.Errorf("methods: %v", err)
		}
		r.methods = map[string]bool{}
		for _, m := range list {
			if !validMethod(m) {
				return fmt.Errorf("method '%s' must be an upper-case token", m)
			}
			r.methods[m] = true
		}
		functional = true
	}
	if raw, ok := doc["path_prefixes"]; ok {
		if r.pathPrefixes, err = strs(raw, MaxListEntries); err != nil {
			return fmt.Errorf("path_prefixes: %v", err)
		}
		for _, p := range r.pathPrefixes {
			if c, ok := canonicalPath(p); !ok || c != p || len(p) < 2 {
				return fmt.Errorf("path prefix '%s' must be a canonical path longer than '/'", p)
			}
		}
		functional = true
	}
	if raw, ok := doc["path_patterns"]; ok {
		list, err := strs(raw, MaxListEntries)
		if err != nil {
			return fmt.Errorf("path_patterns: %v", err)
		}
		for _, p := range list {
			segments, err := parsePattern(p)
			if err != nil {
				return err
			}
			r.pathPatterns = append(r.pathPatterns, segments)
		}
		functional = true
	}
	if raw, ok := doc["content_types"]; ok {
		if r.contentTypes, err = strs(raw, MaxListEntries); err != nil {
			return fmt.Errorf("content_types: %v", err)
		}
		for _, ct := range r.contentTypes {
			if mediaType(ct) != ct || strings.HasPrefix(ct, "*/") || strings.Contains(strings.TrimSuffix(ct, "/*"), "*") {
				return fmt.Errorf("content type '%s' must be a lower-case type/subtype or type/*", ct)
			}
		}
		functional = true
	}
	r.minBytes = 1
	if raw, ok := doc["direction"]; ok {
		if r.direction, err = str(raw); err != nil || (r.direction != "upload" && r.direction != "download") {
			return fmt.Errorf("direction must be upload or download")
		}
		functional = true
	}
	if raw, ok := doc["min_bytes"]; ok {
		if r.direction == "" {
			return fmt.Errorf("min_bytes needs a direction")
		}
		if err := json.Unmarshal(raw, &r.minBytes); err != nil || r.minBytes < 1 || r.minBytes > 1<<40 || strings.ContainsAny(string(raw), ".eE") {
			return fmt.Errorf("min_bytes must be an integer 1..2^40")
		}
	}
	if raw, ok := doc["websocket"]; ok {
		if err := json.Unmarshal(raw, &r.websocket); err != nil || !r.websocket {
			return fmt.Errorf("websocket must be true when present")
		}
		functional = true
	}
	if !functional {
		return fmt.Errorf("a rule needs a function condition (methods, path, content type, direction or websocket)")
	}
	s.rules = append(s.rules, r)
	for _, h := range hosts {
		s.exact[h] = append(s.exact[h], r.order)
	}
	for _, h := range suffixes {
		s.suffix[h] = append(s.suffix[h], r.order)
	}
	return nil
}

// parsePattern splits a path pattern into segments: a literal segment, '*' for exactly one non-empty segment,
// or a final '**' for any rest (including none).
func parsePattern(p string) ([]string, error) {
	bad := fmt.Errorf("path pattern '%s' must be /-separated literal, '*' or final '**' segments", p)
	if !strings.HasPrefix(p, "/") || len(p) < 2 {
		return nil, bad
	}
	segments := strings.Split(p[1:], "/")
	if len(segments) > MaxPatternSegment {
		return nil, bad
	}
	for i, seg := range segments {
		switch {
		case seg == "**" && i == len(segments)-1 && i > 0:
		case seg == "*":
		case seg == "" || strings.Contains(seg, "*"):
			return nil, bad
		default:
			if c, ok := canonicalPath("/" + seg); !ok || c != "/"+seg {
				return nil, bad
			}
		}
	}
	return segments, nil
}

// sortedNames is used by tests and the catalog listing.
func (s *Set) sortedNames() []string {
	out := make([]string, 0, len(s.byName))
	for n := range s.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
