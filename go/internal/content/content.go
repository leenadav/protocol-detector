// Package content loads the versioned detection content pack (migration/fixtures/content.json, exported
// from the Python catalogs by tools/export_content.py) and validates it exactly like
// protocol_engine/applications._validate and host_apps.build_tables: duplicates, unknown categories,
// technologies, characteristics, port specifications and unresolved references refuse the pack.
// Content is administrative metadata looked up by name once a structural identification exists; nothing
// here parses bytes.
package content

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/errs"
)

// MaxPackBytes bounds the pack file.
const MaxPackBytes = 16 << 20

// Application mirrors applications.Application.
type Application struct {
	Name            string   `json:"name"`
	Category        string   `json:"category"`
	Subcategory     string   `json:"subcategory"`
	Technology      string   `json:"technology"`
	Risk            int      `json:"risk"`
	Description     string   `json:"description"`
	Characteristics []string `json:"characteristics"`
	StandardPorts   []string `json:"standard_ports"`
	SecurePorts     []string `json:"secure_ports"`
	ImplicitlyUses  []string `json:"implicitly_uses"`
	DependsOn       []string `json:"depends_on"`
	Container       *string  `json:"container"`
	Aliases         []string `json:"aliases"`

	ports map[string]portTable
}

type portTable struct {
	exact   map[int]bool
	ranges  [][2]int
	dynamic bool
}

// HasPorts reports whether the entry documents any port.
func (a *Application) HasPorts() bool { return len(a.StandardPorts)+len(a.SecurePorts) > 0 }

// UsesPort reports whether transport/port is a documented standard or secure port.
func (a *Application) UsesPort(transport string, port int) bool {
	t, ok := a.ports[transport]
	if !ok {
		return false
	}
	if t.dynamic || t.exact[port] {
		return true
	}
	for _, r := range t.ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

// Release is the content release the pack was exported from.
type Release struct {
	Version    string            `json:"version"`
	Digest     string            `json:"digest"`
	Released   string            `json:"released"`
	Reviewed   string            `json:"reviewed"`
	Components map[string]string `json:"components"`
}

// Risk is one flow-risk table entry.
type Risk struct {
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type hostEntry struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	WebFronts []string `json:"web_fronts"`
}

type packJSON struct {
	Schema     int     `json:"schema"`
	Release    Release `json:"release"`
	Vocabulary struct {
		Categories      map[string][]string `json:"categories"`
		Technologies    []string            `json:"technologies"`
		Characteristics []string            `json:"characteristics"`
		Outcomes        []string            `json:"outcomes"`
	} `json:"vocabulary"`
	ProtocolNames map[string]string `json:"protocol_names"`
	Applications  []*Application    `json:"applications"`
	HostCatalog   struct {
		Entries []hostEntry `json:"entries"`
	} `json:"host_catalog"`
	Risks map[string]Risk `json:"risks"`
}

// Pack is the validated content.
type Pack struct {
	Release       Release
	Applications  map[string]*Application
	Aliases       map[string]string
	ProtocolNames map[string]string
	Outcomes      map[string]bool
	Risks         map[string]Risk
	// The catalog vocabularies (applications.CATEGORIES, TECHNOLOGIES, CHARACTERISTICS) custom signatures validate against.
	Categories      map[string][]string
	Technologies    map[string]bool
	Characteristics map[string]bool
	AppDomains      map[string][]string
	webFronts       map[string]string
	suffixes        map[string]string
	// Digests are the pack digest and the verified release digest (migration/CONTENT-DIGEST.md).
	Digests Digests
}

func invalid(msg string) error { return errs.New(errs.Invalid, errs.ScopeProcess, msg) }

// Load reads and validates a pack file.
func Load(path string) (*Pack, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, invalid("content pack cannot be opened")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxPackBytes+1))
	if err != nil || len(data) > MaxPackBytes {
		return nil, invalid("content pack cannot be read or exceeds the size limit")
	}
	return Parse(data)
}

// Parse validates pack bytes.
func Parse(data []byte) (*Pack, error) { return parse(data, false) }

func parse(data []byte, earlier bool) (*Pack, error) {
	var raw packJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, invalid("content pack is not the expected JSON shape")
	}
	// SEC-CONTENT-1: encoding/json matches field names case-insensitively, but the digest verification and the
	// Python reference read exact keys. The pack is therefore decoded again from the strict tree with every key
	// that names a field only up to case removed, so the tables used are the ones the exact keys hold. When the
	// strict parse fails, computeDigests below refuses the pack with that error.
	if tree, err := parseStrict(data); err == nil {
		var b strings.Builder
		writeCanonical(&b, exactFields(tree, reflect.TypeOf(raw)))
		raw = packJSON{}
		if err := json.Unmarshal([]byte(b.String()), &raw); err != nil {
			return nil, invalid("content pack is not the expected JSON shape")
		}
	}
	if raw.Schema != 1 {
		return nil, errs.New(errs.Unsupported, errs.ScopeProcess, fmt.Sprintf("content pack schema %d", raw.Schema))
	}
	if raw.Release.Version == "" || raw.Release.Digest == "" {
		return nil, invalid("content pack release needs a version and a digest")
	}
	technologies := set(raw.Vocabulary.Technologies)
	characteristics := set(raw.Vocabulary.Characteristics)
	if len(raw.Vocabulary.Categories) == 0 || len(technologies) == 0 || len(characteristics) == 0 {
		return nil, invalid("content pack vocabulary is empty")
	}
	p := &Pack{Release: raw.Release, Applications: map[string]*Application{}, Aliases: map[string]string{},
		ProtocolNames: raw.ProtocolNames, Outcomes: set(raw.Vocabulary.Outcomes), Risks: raw.Risks,
		AppDomains: map[string][]string{}, webFronts: map[string]string{}, suffixes: map[string]string{}}
	for _, app := range raw.Applications {
		if app == nil || app.Name == "" {
			return nil, invalid("application entry without a name")
		}
		if _, dup := p.Applications[app.Name]; dup {
			return nil, invalid("Duplicate application name")
		}
		subs, ok := raw.Vocabulary.Categories[app.Category]
		if !ok || !contains(subs, app.Subcategory) {
			return nil, invalid("Unknown category for " + app.Name)
		}
		if !technologies[app.Technology] || app.Risk < 1 || app.Risk > 5 {
			return nil, invalid("Invalid technology or risk for " + app.Name)
		}
		for _, c := range app.Characteristics {
			if !characteristics[c] {
				return nil, invalid("Unknown characteristic for " + app.Name)
			}
		}
		app.ports = map[string]portTable{}
		for _, spec := range append(append([]string{}, app.StandardPorts...), app.SecurePorts...) {
			if err := addPort(app.ports, spec); err != nil {
				return nil, invalid("Invalid port specification for " + app.Name)
			}
		}
		nilToEmpty(app)
		p.Applications[app.Name] = app
	}
	for _, app := range p.Applications {
		refs := append(append([]string{}, app.ImplicitlyUses...), app.DependsOn...)
		if app.Container != nil {
			refs = append(refs, *app.Container)
		}
		for _, r := range refs {
			if _, ok := p.Applications[r]; !ok {
				return nil, invalid("Unresolved application reference in " + app.Name)
			}
		}
		for _, alias := range app.Aliases {
			if _, isApp := p.Applications[alias]; isApp {
				return nil, invalid("Alias collides with an application name")
			}
			if _, dup := p.Aliases[alias]; dup {
				return nil, invalid("Alias collides with an application name")
			}
			p.Aliases[alias] = app.Name
		}
	}
	for name := range p.Outcomes {
		if _, ok := p.Applications[name]; !ok {
			return nil, invalid("session outcome without a catalog entry: " + name)
		}
	}
	for _, e := range raw.HostCatalog.Entries {
		if _, dup := p.AppDomains[e.Name]; dup {
			return nil, invalid("Duplicate host-catalog entry " + e.Name)
		}
		if _, ok := p.Applications[e.Name]; !ok {
			return nil, invalid("host-catalog entry without an application: " + e.Name)
		}
		p.AppDomains[e.Name] = append([]string{}, e.Domains...)
		for _, front := range e.WebFronts {
			if _, dup := p.webFronts[front]; dup {
				return nil, invalid("Duplicate host-catalog web front " + front)
			}
			p.webFronts[front] = e.Name
		}
		for _, domain := range e.Domains {
			if _, dup := p.suffixes[domain]; dup {
				return nil, invalid("Duplicate host-catalog domain " + domain)
			}
			p.suffixes[domain] = e.Name
		}
	}
	for name, risk := range p.Risks {
		if name == "" || (risk.Severity != "low" && risk.Severity != "medium" && risk.Severity != "high") {
			return nil, invalid("risk entry with an unknown severity: " + name)
		}
	}
	p.Categories, p.Technologies, p.Characteristics = raw.Vocabulary.Categories, technologies, characteristics
	// The digests come last, so a malformed pack keeps its structural error: the three components the tables
	// determine and the release digest must be the ones the pack states (migration/CONTENT-DIGEST.md).
	digests, err := computeDigests(data, earlier)
	if err != nil {
		return nil, err
	}
	if p.Release.Digest != digests.Release { // the reported digest is the verified one (SEC-CONTENT-1)
		return nil, invalid("content pack digest mismatch: release digest")
	}
	p.Digests = *digests
	return p, nil
}

// exactFields returns the strict tree with every object key removed that encoding/json would match to a field
// of t only case-insensitively (strings.EqualFold is the same Unicode simple folding). Exact keys are kept and
// followed into the field's type; keys that name no field are kept, since encoding/json ignores them as the
// reference does.
func exactFields(value interface{}, t reflect.Type) interface{} {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]interface{})
		if !ok {
			return value
		}
		out := make(map[string]interface{}, len(object))
		for key, item := range object {
			field, exact, known := jsonField(t, key)
			switch {
			case !known:
				out[key] = item
			case exact:
				out[key] = exactFields(item, field.Type)
			}
		}
		return out
	case reflect.Map:
		object, ok := value.(map[string]interface{})
		if !ok {
			return value
		}
		out := make(map[string]interface{}, len(object))
		for key, item := range object {
			out[key] = exactFields(item, t.Elem())
		}
		return out
	case reflect.Slice:
		list, ok := value.([]interface{})
		if !ok {
			return value
		}
		out := make([]interface{}, len(list))
		for i, item := range list {
			out[i] = exactFields(item, t.Elem())
		}
		return out
	}
	return value
}

// jsonField finds the field of struct t that encoding/json would decode key into, and whether the key is exact.
func jsonField(t reflect.Type, key string) (reflect.StructField, bool, bool) {
	var folded reflect.StructField
	found := false
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		name := field.Name
		if tag, _, _ := strings.Cut(field.Tag.Get("json"), ","); tag == "-" {
			continue
		} else if tag != "" {
			name = tag
		}
		if name == key {
			return field, true, true
		}
		if !found && strings.EqualFold(name, key) {
			folded, found = field, true
		}
	}
	return folded, false, found
}

func nilToEmpty(app *Application) {
	if app.Characteristics == nil {
		app.Characteristics = []string{}
	}
	if app.StandardPorts == nil {
		app.StandardPorts = []string{}
	}
	if app.SecurePorts == nil {
		app.SecurePorts = []string{}
	}
	if app.ImplicitlyUses == nil {
		app.ImplicitlyUses = []string{}
	}
	if app.DependsOn == nil {
		app.DependsOn = []string{}
	}
	if app.Aliases == nil {
		app.Aliases = []string{}
	}
}

func addPort(tables map[string]portTable, spec string) error {
	kind, rest, ok := strings.Cut(spec, "/")
	if !ok || (kind != "tcp" && kind != "udp") {
		return fmt.Errorf("bad port")
	}
	t := tables[kind]
	if t.exact == nil {
		t.exact = map[int]bool{}
	}
	if rest == "dynamic" {
		t.dynamic = true
	} else {
		parts := strings.Split(rest, "-")
		if len(parts) > 2 {
			return fmt.Errorf("bad port")
		}
		var values []int
		for _, part := range parts {
			n, err := strconv.Atoi(part)
			if err != nil || n < 1 || n > 65535 || strings.TrimLeft(part, "0123456789") != "" {
				return fmt.Errorf("bad port")
			}
			values = append(values, n)
		}
		if len(values) == 2 {
			t.ranges = append(t.ranges, [2]int{values[0], values[1]})
		} else {
			t.exact[values[0]] = true
		}
	}
	tables[kind] = t
	return nil
}

func set(items []string) map[string]bool {
	out := map[string]bool{}
	for _, s := range items {
		out[s] = true
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

// ApplicationName maps an engine protocol/encryption label to a catalog name ("" when none).
func (p *Pack) ApplicationName(protocol, encryption string) string {
	label := encryption
	if label == "" {
		label = protocol
	}
	if label == "" {
		return ""
	}
	base, _, _ := strings.Cut(label, "/")
	name := base
	if mapped, ok := p.ProtocolNames[base]; ok {
		name = mapped
	}
	if _, ok := p.Applications[name]; ok {
		return name
	}
	return ""
}

// HostApplication is the server-name catalog entry carried over a container (ssl, quic, web-browsing).
func (p *Pack) HostApplication(name, container string) *Application {
	entry, base := p.Applications[name], p.Applications[container]
	c := container
	return &Application{Name: entry.Name, Category: entry.Category, Subcategory: entry.Subcategory, Technology: entry.Technology,
		Risk: entry.Risk, Description: entry.Description, Characteristics: entry.Characteristics, StandardPorts: base.StandardPorts,
		SecurePorts: base.SecurePorts, ImplicitlyUses: []string{container}, DependsOn: []string{}, Container: &c, Aliases: []string{}, ports: base.ports}
}

// CustomApplication is a configured mapping presented as an application of its own.
func (p *Pack) CustomApplication(name, container string) *Application {
	base := p.Applications[container]
	c := container
	return &Application{Name: name, Category: "custom", Subcategory: "configured-mapping", Technology: base.Technology, Risk: base.Risk,
		Description: "Configured mapping carried over " + container, Characteristics: base.Characteristics, StandardPorts: base.StandardPorts,
		SecurePorts: base.SecurePorts, ImplicitlyUses: []string{container}, DependsOn: []string{}, Container: &c, Aliases: []string{}, ports: base.ports}
}

// SignatureApplication is a custom signature's application carried over container: the signature's own
// metadata (an empty description names the carrier), the carrier's ports, and its parent when the catalog has it.
func (p *Pack) SignatureApplication(sig Application, parent, container string) *Application {
	carrier := p.Applications[container]
	if sig.Description == "" {
		sig.Description = "Custom signature carried over " + container
	}
	uses := parent
	if uses == "" {
		uses = container
	}
	if _, ok := p.Applications[uses]; !ok {
		uses = container
	}
	c := container
	if _, ok := p.Applications[parent]; ok && parent != "" {
		c = parent
	}
	characteristics := sig.Characteristics
	if characteristics == nil {
		characteristics = []string{}
	}
	return &Application{Name: sig.Name, Category: sig.Category, Subcategory: sig.Subcategory, Technology: sig.Technology, Risk: sig.Risk,
		Description: sig.Description, Characteristics: characteristics, StandardPorts: carrier.StandardPorts, SecurePorts: carrier.SecurePorts,
		ImplicitlyUses: []string{uses}, DependsOn: []string{}, Container: &c, Aliases: []string{}, ports: carrier.ports}
}

// AttributionForHost returns (provider, kind) for a normalized server name; kind is "provider-web" for an
// exact web front and "service" for a name under a service domain (longest label-boundary suffix).
func (p *Pack) AttributionForHost(hostname string) (string, string, bool) {
	if provider, ok := p.webFronts[hostname]; ok {
		return provider, "provider-web", true
	}
	position := 0
	for {
		if name, ok := p.suffixes[hostname[position:]]; ok {
			return name, "service", true
		}
		dot := strings.IndexByte(hostname[position:], '.')
		if dot < 0 {
			return "", "", false
		}
		position += dot + 1
	}
}

// ApplicationForHost is the service a normalized server name affiliates with ("" for a web front or none).
func (p *Pack) ApplicationForHost(hostname string) string {
	name, kind, ok := p.AttributionForHost(hostname)
	if ok && kind == "service" {
		return name
	}
	return ""
}

// pack.json is a byte-for-byte copy of migration/fixtures/content.json (TestEmbeddedPackIsTheSharedPack), so
// the binary carries the detection content of the release it was built from and needs no file at run time.
//
//go:embed pack.json
var embedded []byte

// Embedded parses the content pack built into the binary.
func Embedded() (*Pack, error) { return Parse(embedded) }

//go:embed history.json
var embeddedHistory []byte

// Releases lists the content releases this binary can run, oldest first: the earlier ones in history.json
// (migration/content_history.py) and the current one of pack.json.
func Releases() []string { return releasesOf(embeddedHistory) }

func releasesOf(history []byte) []string {
	var doc struct {
		Current  string                     `json:"current"`
		Releases map[string]json.RawMessage `json:"releases"`
	}
	if err := json.Unmarshal(history, &doc); err != nil {
		return nil
	}
	out := make([]string, 0, len(doc.Releases)+1)
	for v := range doc.Releases {
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return CompareVersions(out[i], out[j]) < 0 })
	return append(out, doc.Current)
}

// CompareVersions orders content release versions (YYYY.MM.N) by their numeric components, so 2026.11.9 comes
// before 2026.11.10; lexical order holds only while every component has the same width. It returns -1, 0 or 1.
// Versions are compared component by component as decimal integers; a component that is not one falls back
// to byte order for that component, and a version with fewer components sorts first when the rest are equal.
func CompareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for k := 0; k < len(pa) && k < len(pb); k++ {
		x, errx := strconv.ParseUint(pa[k], 10, 64)
		y, erry := strconv.ParseUint(pb[k], 10, 64)
		switch {
		case errx == nil && erry == nil && x != y:
			if x < y {
				return -1
			}
			return 1
		case errx == nil && erry == nil:
			continue
		case pa[k] != pb[k]:
			return strings.Compare(pa[k], pb[k])
		}
	}
	switch {
	case len(pa) < len(pb):
		return -1
	case len(pa) > len(pb):
		return 1
	}
	return strings.Compare(a, b) // numerically equal spellings ("09", "9") still get a fixed order
}

// EmbeddedRelease is the pack as of an earlier content release (content.select in the reference): the current
// pack with that release's block and server-name catalog laid over it. Its server-name catalog must reproduce the
// release's host component and its release digest is recomputed from the stated components, which are the ones
// it was published with (C11). The current release is Embedded().
func EmbeddedRelease(version string) (*Pack, error) {
	var doc struct {
		Current  string `json:"current"`
		Releases map[string]struct {
			Release     json.RawMessage `json:"release"`
			HostCatalog json.RawMessage `json:"host_catalog"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(embeddedHistory, &doc); err != nil {
		return nil, invalid("content history is not the expected JSON shape")
	}
	if version == doc.Current {
		return Embedded()
	}
	earlier, ok := doc.Releases[version]
	if !ok {
		return nil, invalid("unknown content version " + version)
	}
	var pack map[string]json.RawMessage
	if err := json.Unmarshal(embedded, &pack); err != nil {
		return nil, invalid("content pack is not the expected JSON shape")
	}
	pack["release"], pack["host_catalog"] = earlier.Release, earlier.HostCatalog
	data, err := json.Marshal(pack)
	if err != nil {
		return nil, invalid("content pack cannot be composed")
	}
	return parse(data, true)
}
