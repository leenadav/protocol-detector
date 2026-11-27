// Package policy ports protocol_engine/policy.py: an ordered list of rules over session verdicts, in the
// vocabulary of application firewalls. The first rule whose conditions all match decides (allow, deny or
// alert), otherwise the policy default applies. It never inspects payload, never changes a verdict and takes
// no network action: the decision is a label the host acts on. Policy files are operator input and are
// validated strictly (unknown keys, unknown names and malformed ports are errors).
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/content"
)

// Error is PolicyError: an invalid policy document.
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

func fail(format string, a ...interface{}) *Error { return &Error{fmt.Sprintf(format, a...)} }

var (
	actions   = []string{"allow", "deny", "alert"}
	portUsage = []string{"standard", "nonstandard", "unknown"}
	matchKeys = set("apps", "categories", "subcategories", "technologies", "characteristics", "risks", "port_usage",
		"transports", "server_ports", "encryption", "shifted_from", "risk_min", "risk_max",
		"identity_basis", "activity", "affiliation", "decryption", "capture_quality", "engine_status", "directions", "observation")
	// childMatchKeys adds "containers" (Go only, PRO-492) when the policy is parsed with child applications.
	childMatchKeys = func() map[string]bool {
		keys := set("containers")
		for k := range matchKeys {
			keys[k] = true
		}
		return keys
	}()
	ruleKeys = set("name", "action", "match", "application_default", "description")
	// Closed vocabularies of the D04 predicates; there is deliberately no ordering among identity bases.
	predicateVocabularies = map[string][]string{
		"identity_basis":  {"authenticated_plaintext", "structural", "configured_rule", "client_assertion", "none"},
		"activity":        {"unobserved", "http-request", "authenticated-plaintext", "none"},
		"affiliation":     {"service", "provider-web", "none"},
		"decryption":      {"none", "awaiting_hello", "awaiting_keys", "decrypting", "complete", "failed"},
		"capture_quality": {"intact", "degraded", "provisional"},
		"engine_status": {"identified", "correlated", "detecting", "incomplete", "unknown", "malformed", "budget_exhausted",
			"invalidated", "no_handshake", "no_payload"},
		"directions":  {"consistent", "conflicting", "one-direction"},
		"observation": {"handshake", "asymmetric", "midstream", "datagram"},
	}
	// predicateOrder is the order the reference evaluates and stores the predicates in.
	predicateOrder = []string{"identity_basis", "activity", "affiliation", "decryption", "capture_quality", "engine_status", "directions", "observation"}
)

const (
	maxRules = 1024
	maxFile  = 4 * 1024 * 1024
)

func set(names ...string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		out[n] = true
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

type portTable struct {
	exact   map[int]bool
	ranges  [][2]int
	dynamic bool
}

// Rule is one ordered policy rule with pre-resolved condition sets (nil: the condition is absent).
type Rule struct {
	Name, Action       string
	Description        string
	ApplicationDefault bool
	apps, containers, categories, subcategories, technologies, characteristics, risks,
	portUsage, transports, encryption, shiftedFrom map[string]bool
	serverPorts      map[string]*portTable
	predicates       map[string]map[string]bool
	riskMin, riskMax int // 0: absent
}

// Policy is the parsed document.
type Policy struct {
	Rules       []*Rule
	Default     string
	Description string
}

// Decision is the outcome of one evaluation.
type Decision struct {
	Action     string
	Rule       *string
	Reasons    []string
	Predicates map[string]string
}

// Fields is Decision.fields(): the JSON-friendly record entry.
func (d Decision) Fields() map[string]interface{} {
	var rule interface{}
	if d.Rule != nil {
		rule = *d.Rule
	}
	out := map[string]interface{}{"action": d.Action, "rule": rule, "reasons": d.Reasons}
	if d.Predicates != nil {
		predicates := map[string]interface{}{}
		for k, v := range d.Predicates {
			predicates[k] = v
		}
		out["predicates"] = predicates
	}
	return out
}

func isInt(v interface{}) (int, bool) { // Python `type(value) is int`
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(string(n), ".eE") {
		return 0, false
	}
	i, err := strconv.Atoi(string(n))
	if err != nil {
		return 1 << 40, true // an integer outside every accepted range
	}
	return i, true
}

func sortedKeys(m map[string]interface{}, known map[string]bool) []string {
	var unknown []string
	for k := range m {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	return unknown
}

func isPrintable(s string) bool { // str.isprintable()
	for _, r := range s {
		if r != ' ' && !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func names(value interface{}, label string, allowed func(string) bool, resolve func(string) (string, *Error)) (map[string]bool, *Error) {
	list, ok := value.([]interface{})
	if !ok || len(list) == 0 || len(list) > 256 {
		return nil, fail("'%s' must be a non-empty list of at most 256 strings", label)
	}
	out := map[string]bool{}
	for _, item := range list {
		name, ok := item.(string)
		if !ok || name == "" {
			return nil, fail("'%s' entries must be strings", label)
		}
		if resolve != nil {
			resolved, err := resolve(name)
			if err != nil {
				return nil, err
			}
			name = resolved
		}
		if allowed != nil && !allowed(name) {
			return nil, fail("Unknown %s name: %s", label, name)
		}
		out[name] = true
	}
	return out, nil
}

func in(list []string) func(string) bool { return func(v string) bool { return contains(list, v) } }

// pyInt is Python's int(text) for the ASCII forms: surrounding whitespace, a sign, digits with single underscores.
func pyInt(text string) (int, bool) {
	t := strings.TrimFunc(text, unicode.IsSpace)
	digits := t
	if strings.HasPrefix(t, "+") || strings.HasPrefix(t, "-") {
		digits = t[1:]
	}
	if digits == "" || strings.HasPrefix(digits, "_") || strings.HasSuffix(digits, "_") || strings.Contains(digits, "__") {
		return 0, false
	}
	for _, r := range digits {
		if r != '_' && (r < '0' || r > '9') {
			return 0, false
		}
	}
	digits = strings.ReplaceAll(digits, "_", "")
	if len(digits) > 12 {
		return 1 << 40, true
	}
	v, _ := strconv.Atoi(digits)
	if strings.HasPrefix(t, "-") {
		v = -v
	}
	return v, true
}

// ports parses ["tcp/443", "udp/53-60", "tcp/dynamic"].
func ports(value interface{}) (map[string]*portTable, *Error) {
	list, ok := value.([]interface{})
	if !ok || len(list) == 0 || len(list) > 256 {
		return nil, fail("'server_ports' must be a non-empty list of at most 256 entries")
	}
	table := map[string]*portTable{}
	for _, item := range list {
		entry, ok := item.(string)
		if !ok || strings.Count(entry, "/") != 1 {
			return nil, fail("Port entries look like tcp/443, udp/53-60 or tcp/dynamic")
		}
		transport, spec, _ := strings.Cut(entry, "/")
		if transport != "tcp" && transport != "udp" {
			return nil, fail("Port transport must be tcp or udp")
		}
		t := table[transport]
		if t == nil {
			t = &portTable{exact: map[int]bool{}}
		}
		if spec == "dynamic" {
			t.dynamic = true
		} else {
			low, high, _ := strings.Cut(spec, "-")
			upper := high
			if upper == "" {
				upper = low
			}
			lowValue, ok1 := pyInt(low)
			highValue, ok2 := pyInt(upper)
			if !ok1 || !ok2 {
				return nil, fail("Port numbers must be integers: %s", entry)
			}
			if !(1 <= lowValue && lowValue <= highValue && highValue <= 65535) {
				return nil, fail("Port range outside 1..65535: %s", entry)
			}
			if high != "" {
				t.ranges = append(t.ranges, [2]int{lowValue, highValue})
			} else {
				t.exact[lowValue] = true
			}
		}
		table[transport] = t
	}
	return table, nil
}

// Children names the child applications (internal/childapp) a policy may name; nil keeps the reference's
// vocabulary, where "containers" is an unknown key and child names are unknown applications.
type Children interface{ Has(name string) bool }

func newRule(document interface{}, index int, pack *content.Pack, children Children) (*Rule, *Error) {
	doc, ok := document.(map[string]interface{})
	if !ok {
		return nil, fail("Rule %d must be an object", index)
	}
	if unknown := sortedKeys(doc, ruleKeys); len(unknown) > 0 {
		return nil, fail("Rule %d has unknown keys: %s", index, strings.Join(unknown, ", "))
	}
	name := fmt.Sprintf("rule-%d", index)
	if v, present := doc["name"]; present {
		text, isString := v.(string)
		if !isString {
			return nil, fail("Rule %d name must be 1..64 printable characters", index)
		}
		name = text
	}
	if n := utf8.RuneCountInString(name); n < 1 || n > 64 || !isPrintable(name) {
		return nil, fail("Rule %d name must be 1..64 printable characters", index)
	}
	action, _ := doc["action"].(string)
	if !contains(actions, action) {
		return nil, fail("Rule '%s' action must be one of %s", name, strings.Join(actions, ", "))
	}
	match := map[string]interface{}{}
	if v, present := doc["match"]; present {
		m, isMap := v.(map[string]interface{})
		if !isMap {
			return nil, fail("Rule '%s' match must be an object", name)
		}
		match = m
	}
	keys := matchKeys
	if children != nil {
		keys = childMatchKeys
	}
	if unknown := sortedKeys(match, keys); len(unknown) > 0 {
		return nil, fail("Rule '%s' has unknown match keys: %s", name, strings.Join(unknown, ", "))
	}
	r := &Rule{Name: name, Action: action}
	if v, present := doc["description"]; present {
		text, isString := v.(string)
		if !isString || utf8.RuneCountInString(text) > 512 {
			return nil, fail("Rule '%s' description must be a string of at most 512 characters", name)
		}
		r.Description = text
	}
	if v, present := doc["application_default"]; present {
		flag, isBool := v.(bool)
		if !isBool {
			return nil, fail("Rule '%s' application_default must be a boolean", name)
		}
		r.ApplicationDefault = flag
	}
	resolveApp := func(name string) (string, *Error) {
		if pack.Outcomes[name] {
			return name, nil
		}
		if _, ok := pack.Applications[name]; ok {
			return name, nil
		}
		if canonical, ok := pack.Aliases[name]; ok {
			return canonical, nil
		}
		if children != nil && children.Has(name) {
			return name, nil
		}
		return "", fail("Unknown application: %s", name)
	}
	subcategory := func(v string) bool {
		for _, subs := range pack.Categories {
			if contains(subs, v) {
				return true
			}
		}
		return false
	}
	var err *Error
	load := func(key string, target *map[string]bool, allowed func(string) bool, resolve func(string) (string, *Error)) {
		if v, present := match[key]; present && err == nil {
			*target, err = names(v, key, allowed, resolve)
		}
	}
	// The reference evaluates the conditions in this order; the first invalid one is reported.
	load("apps", &r.apps, nil, resolveApp)
	load("containers", &r.containers, nil, resolveApp)
	load("categories", &r.categories, func(v string) bool { _, ok := pack.Categories[v]; return ok }, nil)
	load("subcategories", &r.subcategories, subcategory, nil)
	load("technologies", &r.technologies, func(v string) bool { return pack.Technologies[v] }, nil)
	load("characteristics", &r.characteristics, func(v string) bool { return pack.Characteristics[v] }, nil)
	load("risks", &r.risks, func(v string) bool { _, ok := pack.Risks[v]; return ok }, nil)
	load("port_usage", &r.portUsage, in(portUsage), nil)
	load("transports", &r.transports, in([]string{"tcp", "udp"}), nil)
	if v, present := match["server_ports"]; present && err == nil {
		r.serverPorts, err = ports(v)
	}
	load("encryption", &r.encryption, in([]string{"none", "tls", "dtls", "quic", "wireguard", "openvpn"}), nil)
	load("shifted_from", &r.shiftedFrom, nil, resolveApp)
	r.predicates = map[string]map[string]bool{}
	for _, key := range predicateOrder {
		if v, present := match[key]; present && err == nil {
			r.predicates[key], err = names(v, key, in(predicateVocabularies[key]), nil)
		}
	}
	if err != nil {
		return nil, err
	}
	for _, bound := range []struct {
		key    string
		target *int
	}{{"risk_min", &r.riskMin}, {"risk_max", &r.riskMax}} {
		if v, present := match[bound.key]; present {
			n, isInteger := isInt(v)
			if !isInteger || n < 1 || n > 5 {
				return nil, fail("Rule '%s' %s must be an integer 1..5", name, bound.key)
			}
			*bound.target = n
		}
	}
	if r.riskMin != 0 && r.riskMax != 0 && r.riskMin > r.riskMax {
		return nil, fail("Rule '%s' risk_min exceeds risk_max", name)
	}
	return r, nil
}

func anyIn(set map[string]bool, values []string) bool {
	for _, v := range values {
		if set[v] {
			return true
		}
	}
	return false
}

// matches: all present conditions must hold; list conditions hold when any entry matches. D04 predicates are
// evaluated against context; skipPredicates is the reference's "would match if its evidence requirements were
// met" probe.
func (r *Rule) matches(v *appid.Verdict, portUsageValue, transport string, serverPort int, hasPort bool, context map[string]string, skipPredicates bool) bool {
	if r.apps != nil && !r.apps[v.App] {
		return false
	}
	// containers holds for the named application itself, for every child whose container it is, and for every
	// child matched on a host it owns in the catalog (graph.microsoft.com is ms-base's, so containers:[ms-base]
	// covers outlook-sending there; SEC-CHILD-2).
	if r.containers != nil && !r.containers[v.App] && (v.BaseApp == nil || !r.containers[*v.BaseApp]) &&
		(v.HostOwner == nil || !r.containers[*v.HostOwner]) {
		return false
	}
	if len(r.predicates) > 0 && !skipPredicates {
		if context == nil {
			return false
		}
		for key, allowed := range r.predicates {
			if !allowed[context[key]] {
				return false
			}
		}
	}
	if r.categories != nil && !r.categories[v.Category] {
		return false
	}
	if r.subcategories != nil && !r.subcategories[v.Subcategory] {
		return false
	}
	if r.technologies != nil && !r.technologies[v.Technology] {
		return false
	}
	if r.riskMin != 0 && v.Risk < r.riskMin {
		return false
	}
	if r.riskMax != 0 && v.Risk > r.riskMax {
		return false
	}
	if r.characteristics != nil && !anyIn(r.characteristics, v.Characteristics) {
		return false
	}
	if r.risks != nil && !anyIn(r.risks, v.Risks) {
		return false
	}
	if r.portUsage != nil && !r.portUsage[portUsageValue] {
		return false
	}
	if r.encryption != nil {
		encryption := "none"
		if v.Encryption != nil && *v.Encryption != "" {
			encryption = *v.Encryption
		}
		if !r.encryption[encryption] {
			return false
		}
	}
	if r.shiftedFrom != nil && (v.ShiftedFrom == nil || !r.shiftedFrom[*v.ShiftedFrom]) {
		return false
	}
	if r.transports != nil && !r.transports[transport] {
		return false
	}
	if r.serverPorts != nil {
		t := r.serverPorts[transport]
		if transport == "" || !hasPort || t == nil {
			return false
		}
		inRange := false
		for _, rg := range t.ranges {
			if rg[0] <= serverPort && serverPort <= rg[1] {
				inRange = true
			}
		}
		if !(t.dynamic || t.exact[serverPort] || inRange) {
			return false
		}
	}
	if r.ApplicationDefault && portUsageValue == "nonstandard" {
		return false
	}
	return true
}

// FromJSON is Policy.from_json over the content pack's vocabularies.
func FromJSON(text []byte, pack *content.Pack) (*Policy, error) {
	return FromJSONWithChildren(text, pack, nil)
}

// FromJSONWithChildren is FromJSON over the pack plus child applications: rules may name a child in apps and
// match a parent with its children through containers (Go only, PRO-492).
func FromJSONWithChildren(text []byte, pack *content.Pack, children Children) (*Policy, error) {
	decoder := json.NewDecoder(bytes.NewReader(text))
	decoder.UseNumber()
	var document interface{}
	if err := decoder.Decode(&document); err != nil {
		return nil, fail("Invalid JSON: %v", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fail("Invalid JSON: extra data")
	}
	doc, ok := document.(map[string]interface{})
	if !ok {
		return nil, fail("Policy document must be an object")
	}
	if unknown := sortedKeys(doc, set("version", "default", "rules", "description")); len(unknown) > 0 {
		return nil, fail("Policy has unknown keys: %s", strings.Join(unknown, ", "))
	}
	if v, present := doc["version"]; present && !equalsOne(v) {
		return nil, fail("Unsupported policy version")
	}
	p := &Policy{Default: "allow"}
	if v, present := doc["default"]; present {
		text, _ := v.(string)
		if !contains(actions, text) {
			return nil, fail("Policy default must be one of %s", strings.Join(actions, ", "))
		}
		p.Default = text
	}
	var rules []interface{}
	if v, present := doc["rules"]; present {
		list, isList := v.([]interface{})
		if !isList || len(list) > maxRules {
			return nil, fail("Policy rules must be a list of at most %d rules", maxRules)
		}
		rules = list
	}
	if v, present := doc["description"]; present {
		text, isString := v.(string)
		if !isString || utf8.RuneCountInString(text) > 512 {
			return nil, fail("Policy description must be a string of at most 512 characters")
		}
		p.Description = text
	}
	seen := map[string]bool{}
	duplicate := false
	for index, raw := range rules {
		rule, err := newRule(raw, index, pack, children)
		if err != nil {
			return nil, err
		}
		if seen[rule.Name] {
			duplicate = true
		}
		seen[rule.Name] = true
		p.Rules = append(p.Rules, rule)
	}
	if duplicate {
		return nil, fail("Rule names must be unique")
	}
	return p, nil
}

// equalsOne is Python's `value == 1` for a JSON value: 1, 1.0 and true compare equal.
func equalsOne(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case json.Number:
		f, err := x.Float64()
		return err == nil && f == 1
	}
	return false
}

// FromPath is Policy.from_path: at most 4 MiB of UTF-8 JSON.
func FromPath(path string, pack *content.Pack) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFile {
		return nil, fail("Policy file exceeds 4 MiB")
	}
	if !utf8.Valid(data) {
		return nil, fail("Policy file is not UTF-8")
	}
	return FromJSON(data, pack)
}

func text(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Context is policy_context: the D04 predicate values for one session, from its verdict and (when present) its
// layered view. Every value is a closed label; nothing here is a confidence score.
func Context(v *appid.Verdict, layers map[string]interface{}, captureQuality, observation string) map[string]string {
	application, _ := layers["application"].(map[string]interface{})
	decryptionLayer, _ := layers["decryption"].(map[string]interface{})
	attribution := v.Attribution
	basis := text(application, "basis")
	if _, present := application["basis"]; !present || application["basis"] == nil {
		switch {
		case v.Status != "identified" && v.Status != "correlated":
			basis = "none"
		case v.BaseApp != nil && v.Category == "custom":
			basis = "configured_rule"
		case text(attribution, "kind") == "service":
			basis = "client_assertion"
		default:
			basis = "structural"
		}
	}
	directions := "consistent"
	if v.ClientProtocol == nil || v.ServerProtocol == nil {
		directions = "one-direction"
	}
	for _, reason := range v.Reasons {
		if strings.HasPrefix(reason, "Server direction identified as") {
			directions = "conflicting"
			break
		}
	}
	return map[string]string{
		"identity_basis":  basis,
		"activity":        first(text(application, "activity"), text(attribution, "activity"), "none"),
		"affiliation":     first(text(application, "affiliation"), text(attribution, "kind"), "none"),
		"decryption":      first(text(decryptionLayer, "state"), "none"),
		"capture_quality": first(captureQuality, text(layers, "capture_quality"), "intact"),
		"engine_status":   v.Status,
		"directions":      directions,
		"observation":     first(observation, "handshake"),
	}
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedPredicates(r *Rule) []string {
	keys := make([]string, 0, len(r.predicates))
	for k := range r.predicates {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Evaluate ports Policy.evaluate: the first matching rule decides, otherwise the default. hasPort false is the
// reference's server_port None; transport "" its transport None.
func (p *Policy) Evaluate(v *appid.Verdict, transport string, serverPort int, hasPort bool, layers map[string]interface{}, observation string) Decision {
	context := Context(v, layers, "", observation)
	for _, rule := range p.Rules {
		if rule.matches(v, v.PortUsage, transport, serverPort, hasPort, context, false) {
			reasons := []string{fmt.Sprintf("rule '%s' matched %s", rule.Name, v.App)}
			if rule.ApplicationDefault {
				reasons = append(reasons, "application-default: port usage "+v.PortUsage)
			}
			if len(rule.predicates) > 0 {
				var parts []string
				for _, key := range sortedPredicates(rule) {
					parts = append(parts, key+"="+context[key])
				}
				reasons = append(reasons, "predicates: "+strings.Join(parts, ", "))
			}
			name := rule.Name
			return Decision{rule.Action, &name, reasons, context}
		}
	}
	reasons := []string{fmt.Sprintf("no rule matched %s; policy default", v.App)}
	for _, rule := range p.Rules {
		if rule.ApplicationDefault && rule.Action == "allow" && v.PortUsage == "nonstandard" &&
			rule.matches(v, "standard", transport, serverPort, hasPort, context, false) {
			reasons = append(reasons, fmt.Sprintf("rule '%s' would allow %s on its application-default ports only", rule.Name, v.App))
			break
		}
	}
	for _, rule := range p.Rules {
		if len(rule.predicates) > 0 && rule.matches(v, v.PortUsage, transport, serverPort, hasPort, context, true) {
			var missing []string
			for _, key := range sortedPredicates(rule) {
				if !rule.predicates[key][context[key]] {
					missing = append(missing, fmt.Sprintf("%s is %s (needs %s)", key, context[key], strings.Join(sortedSet(rule.predicates[key]), "|")))
				}
			}
			reasons = append(reasons, fmt.Sprintf("rule '%s' would match but its evidence requirements are not met: %s", rule.Name, strings.Join(missing, ", ")))
			break
		}
	}
	return Decision{p.Default, nil, reasons, context}
}
