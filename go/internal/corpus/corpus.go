// Package corpus evaluates the engine against an independently labelled capture corpus (D09, SR-67).
//
// It is the Go port of the removed reference's tools/evaluate_corpus.py. The corpus is a directory holding
// manifest.json and the capture files it names. Labels come from outside this engine (the generating client,
// the test-bed configuration, a human analyst); the manifest must say who labelled the flows and on what
// basis, and the report repeats it. Every capture's SHA-256 is verified, capture files must sit directly in
// the corpus directory, and only whitelisted analyzer options are accepted. Nothing about the corpus is read
// beyond what analyze reads, and the report holds endpoints, labels, counts and digests only: never payload,
// hostnames or captured bytes. Scoring is per labelled flow:
//
//   - correct: the session record names the labelled family (and the labelled application, when given);
//   - wrong-application: the family is right and the application is not;
//   - wrong: the record names another family (a false identification, the serious case);
//   - unidentified: the record exists but ends without an identification;
//   - missing: no session record was produced for the labelled flow;
//   - unlabelled: flows the engine reported that the manifest does not label (not scored).
package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/analyze"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/engine"
)

// Bounds on what a manifest may make the harness do.
const (
	MaxManifestBytes = 8 << 20 // manifest.json is read whole, so its size is bounded first
	MaxCaptures      = 4096
	MaxFlows         = 1 << 20 // labelled flows over the whole manifest
	maxRowBytes      = 4 << 20 // one analyze output row; longer rows are refused, not buffered
)

// analyzerOptions are the only capture options a manifest may set (SR-67: whitelisted Analyzer options).
var analyzerOptions = []string{"observation", "checksums", "continuation", "tcp_hint", "udp_hint", "fingerprints", "certificates"}

// Error is a refused corpus: missing provenance, a digest mismatch, a capture outside the directory, an
// unsupported option or a malformed label. A refused corpus produces no report.
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

func refuse(format string, args ...interface{}) error {
	return &Error{Message: fmt.Sprintf(format, args...)}
}

// Flow is one labelled flow.
type Flow struct {
	Transport   string
	Client      Endpoint
	Server      Endpoint
	Family      string
	Application string
}

// Endpoint is an IPv4 address and a port.
type Endpoint struct {
	Addr string
	Port int
}

func (e Endpoint) MarshalJSON() ([]byte, error) { return json.Marshal([]interface{}{e.Addr, e.Port}) }

// Capture is one capture entry of the manifest.
type Capture struct {
	File    string
	SHA256  string
	Options map[string]interface{}
	Flows   []Flow
	raw     json.RawMessage
}

// Manifest is a validated manifest.json.
type Manifest struct {
	Corpus, Version, Source, LabelledBy, LabelBasis string
	Independent                                     bool
	Captures                                        []Capture
	dir                                             string
	labelSet                                        string
}

// familyOf is the family part of a label ("tls/1.3" -> "tls").
func familyOf(label string) string {
	family, _, _ := strings.Cut(label, "/")
	return family
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // read-only handle; the hash is already complete or the copy failed
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func text(m map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := m[key]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func endpointOf(raw json.RawMessage) (Endpoint, bool) {
	var pair []json.RawMessage
	if json.Unmarshal(raw, &pair) != nil || len(pair) != 2 {
		return Endpoint{}, false
	}
	var addr string
	var port json.Number
	if json.Unmarshal(pair[0], &addr) != nil || json.Unmarshal(pair[1], &port) != nil {
		return Endpoint{}, false
	}
	ip := net.ParseIP(addr)
	n, err := strconv.Atoi(port.String())
	if ip == nil || ip.To4() == nil || err != nil || n < 0 || n > 65535 {
		return Endpoint{}, false
	}
	return Endpoint{Addr: ip.To4().String(), Port: n}, true
}

// checkOption validates one whitelisted option's type and value, so a manifest cannot reach the analyzer
// with a value it would treat differently from what the label assumed.
func checkOption(name string, raw interface{}) error {
	switch name {
	case "observation":
		if s, ok := raw.(string); !ok || (s != "handshake" && s != "asymmetric" && s != "midstream") {
			return refuse("capture option observation must be handshake, asymmetric or midstream")
		}
	case "checksums":
		if s, ok := raw.(string); !ok || (s != "ignore" && s != "audit" && s != "verify") {
			return refuse("capture option checksums must be ignore, audit or verify")
		}
	case "continuation":
		n, ok := raw.(float64)
		if !ok || n < 0 || n != float64(int(n)) || n > 1<<20 {
			return refuse("capture option continuation must be a byte count from 0 to 1048576")
		}
	case "tcp_hint", "udp_hint":
		s, ok := raw.(string)
		if !ok || !declared(s) {
			return refuse("capture option %s must name a family the engine declares", name)
		}
	case "fingerprints", "certificates":
		if _, ok := raw.(bool); !ok {
			return refuse("capture option %s must be true or false", name)
		}
	}
	return nil
}

func declared(family string) bool {
	for _, f := range engine.Families() {
		if f == family {
			return true
		}
	}
	return false
}

// Load reads and validates dir/manifest.json: provenance and labelling must be stated, every capture must be a
// regular file directly in dir whose SHA-256 matches the manifest, every flow label must be well formed and
// name a declared family, and only whitelisted options are accepted.
func Load(dir string) (*Manifest, error) {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, refuse("corpus directory unreadable: %v", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, refuse("corpus directory unreadable: %v", err)
	}
	f, err := os.Open(filepath.Join(root, "manifest.json"))
	if err != nil {
		return nil, refuse("manifest.json unreadable: %v", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	_ = f.Close()
	if err != nil {
		return nil, refuse("manifest.json unreadable: %v", err)
	}
	if len(data) > MaxManifestBytes {
		return nil, refuse("manifest.json is larger than %d bytes", MaxManifestBytes)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, refuse("manifest.json is not a JSON object: %v", err)
	}
	m := &Manifest{dir: root}
	missing := []string{}
	for _, field := range []struct {
		key string
		dst *string
	}{{"corpus", &m.Corpus}, {"source", &m.Source}, {"labelled_by", &m.LabelledBy}, {"label_basis", &m.LabelBasis}} {
		s, _ := text(top, field.key)
		if strings.TrimSpace(s) == "" {
			missing = append(missing, field.key)
		}
		*field.dst = s
	}
	var captures []json.RawMessage
	if raw, ok := top["captures"]; !ok || json.Unmarshal(raw, &captures) != nil || len(captures) == 0 {
		missing = append(missing, "captures")
	}
	if len(missing) > 0 {
		return nil, refuse("manifest lacks %s (provenance and labelling must be stated)", strings.Join(missing, ", "))
	}
	if len(captures) > MaxCaptures {
		return nil, refuse("manifest names more than %d captures", MaxCaptures)
	}
	m.Version, _ = text(top, "version")
	if raw, ok := top["independent"]; ok {
		_ = json.Unmarshal(raw, &m.Independent) // anything but JSON true is "not stated"
	}
	flows := 0
	for _, raw := range captures {
		c, err := loadCapture(root, raw)
		if err != nil {
			return nil, err
		}
		if flows += len(c.Flows); flows > MaxFlows {
			return nil, refuse("manifest labels more than %d flows", MaxFlows)
		}
		m.Captures = append(m.Captures, *c)
	}
	// The label-set digest pins exactly which labels were scored (compacted, so whitespace does not change it).
	var compact bytes.Buffer
	if raw, ok := top["captures"]; ok && json.Compact(&compact, raw) == nil {
		sum := sha256.Sum256(compact.Bytes())
		m.labelSet = hex.EncodeToString(sum[:])[:16]
	}
	return m, nil
}

func loadCapture(root string, raw json.RawMessage) (*Capture, error) {
	var entry map[string]json.RawMessage
	if json.Unmarshal(raw, &entry) != nil {
		return nil, refuse("capture entry is not a JSON object")
	}
	for _, key := range []string{"file", "sha256", "flows"} {
		if _, ok := entry[key]; !ok {
			return nil, refuse("capture entry lacks %s", key)
		}
	}
	c := &Capture{raw: raw, Options: map[string]interface{}{}}
	var ok bool
	if c.File, ok = text(entry, "file"); !ok || c.File == "" {
		return nil, refuse("capture entry file must be a file name")
	}
	if c.SHA256, ok = text(entry, "sha256"); !ok {
		return nil, refuse("capture entry sha256 must be a hex digest")
	}
	// Confinement: the file must resolve (symbolic links followed) to a regular file directly in the corpus
	// directory, so a manifest cannot make the harness read anything else on the host.
	path, err := filepath.EvalSymlinks(filepath.Join(root, c.File))
	if err == nil {
		path, err = filepath.Abs(path)
	}
	if err != nil || filepath.Dir(path) != root {
		return nil, refuse("capture file outside the corpus directory or missing: %s", c.File)
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return nil, refuse("capture file outside the corpus directory or missing: %s", c.File)
	}
	digest, err := sha256File(path)
	if err != nil {
		return nil, refuse("capture file unreadable: %s", c.File)
	}
	if !strings.EqualFold(digest, c.SHA256) {
		return nil, refuse("sha256 mismatch for %s: manifest %.12s file %.12s", c.File, c.SHA256, digest)
	}
	c.SHA256 = digest
	if rawOptions, present := entry["options"]; present {
		if json.Unmarshal(rawOptions, &c.Options) != nil {
			return nil, refuse("capture options must be a JSON object")
		}
	}
	unknown := []string{}
	for name := range c.Options {
		if !whitelisted(name) {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, refuse("unsupported capture options: %s", strings.Join(unknown, ", "))
	}
	for _, name := range analyzerOptions {
		if v, present := c.Options[name]; present {
			if err := checkOption(name, v); err != nil {
				return nil, err
			}
		}
	}
	var flows []map[string]json.RawMessage
	if json.Unmarshal(entry["flows"], &flows) != nil {
		return nil, refuse("capture flows must be a list of flow labels")
	}
	for _, flow := range flows {
		f := Flow{}
		f.Transport, _ = text(flow, "transport")
		client, okClient := endpointOf(flow["client"])
		server, okServer := endpointOf(flow["server"])
		if (f.Transport != "tcp" && f.Transport != "udp") || !okClient || !okServer {
			return nil, refuse("flow label needs transport, client [ip, port] and server [ip, port]")
		}
		f.Client, f.Server = client, server
		f.Family, _ = text(flow, "family")
		if !declared(familyOf(f.Family)) {
			return nil, refuse("flow labelled with a family the engine does not declare: %q", f.Family)
		}
		if raw, present := flow["application"]; present && string(raw) != "null" {
			if f.Application, ok = text(flow, "application"); !ok {
				return nil, refuse("flow application must be a string")
			}
		}
		c.Flows = append(c.Flows, f)
	}
	return c, nil
}

func whitelisted(name string) bool {
	for _, allowed := range analyzerOptions {
		if allowed == name {
			return true
		}
	}
	return false
}

// analyzeOptions maps the validated manifest options onto analyze.Options. Hostnames stay off: the report
// never carries one.
func analyzeOptions(options map[string]interface{}) analyze.Options {
	o := analyze.Options{JSON: true, Sessions: true, EventsOnly: true, CRC32CByteLimit: 4096}
	str := func(name string) string { s, _ := options[name].(string); return s }
	flag := func(name string) bool { b, _ := options[name].(bool); return b }
	o.Observation, o.Checksums = str("observation"), str("checksums")
	o.TCPHint, o.UDPHint = str("tcp_hint"), str("udp_hint")
	o.Fingerprints, o.Certificates = flag("fingerprints"), flag("certificates")
	if n, ok := options["continuation"].(float64); ok {
		o.Continuation = int(n)
	}
	return o
}

// record is the part of a session record the score reads; nothing else of the analyzer output is kept.
type record struct {
	key, family, app string
}

func flowKey(transport string, client, server Endpoint) string {
	return fmt.Sprintf("%s %s:%d %s:%d", transport, client.Addr, client.Port, server.Addr, server.Port)
}

// sessionSink parses analyze's JSON rows line by line as they are written and keeps only the scored fields of
// session records and the input-quality counters of the summary.
type sessionSink struct {
	pending  []byte
	records  []record
	quality  map[string]int
	overflow bool
}

func (s *sessionSink) Write(p []byte) (int, error) {
	s.pending = append(s.pending, p...)
	for {
		i := bytes.IndexByte(s.pending, '\n')
		if i < 0 {
			break
		}
		s.line(s.pending[:i])
		s.pending = s.pending[i+1:]
	}
	if len(s.pending) > maxRowBytes {
		s.overflow = true
		return 0, errors.New("analyze row longer than the corpus harness accepts")
	}
	return len(p), nil
}

func (s *sessionSink) line(line []byte) {
	var row struct {
		Type           string          `json:"type"`
		Transport      string          `json:"transport"`
		Client         json.RawMessage `json:"client"`
		Server         json.RawMessage `json:"server"`
		Encryption     *string         `json:"encryption"`
		ClientProtocol *string         `json:"client_protocol"`
		ServerProtocol *string         `json:"server_protocol"`
		App            *string         `json:"app"`
		Summary        map[string]int  `json:"summary"`
		InputQuality   struct {
			Rejected map[string]int `json:"rejected"`
		} `json:"input_quality"`
	}
	if json.Unmarshal(line, &row) != nil {
		return
	}
	if row.Summary != nil {
		for kind, n := range row.InputQuality.Rejected {
			if n > 0 {
				s.quality[kind] += n
			}
		}
		if n := row.Summary["truncated"]; n > 0 {
			s.quality["truncated"] += n
		}
		return
	}
	if row.Type != "session" {
		return
	}
	client, okClient := endpointOf(row.Client)
	server, okServer := endpointOf(row.Server)
	if !okClient || !okServer {
		return
	}
	family := ""
	for _, label := range []*string{row.Encryption, row.ClientProtocol, row.ServerProtocol} {
		if label != nil && *label != "" {
			family = familyOf(*label)
			break
		}
	}
	app := ""
	if row.App != nil {
		app = *row.App
	}
	s.records = append(s.records, record{key: flowKey(row.Transport, client, server), family: family, app: app})
}

// Outcomes counts the scored outcomes of a set of labelled flows.
type Outcomes struct {
	Correct          int `json:"correct"`
	WrongApplication int `json:"wrong_application"`
	Wrong            int `json:"wrong"`
	Unidentified     int `json:"unidentified"`
	Missing          int `json:"missing"`
}

func (o Outcomes) labelled() int {
	return o.Correct + o.WrongApplication + o.Wrong + o.Unidentified + o.Missing
}

// FamilyRow is one family of the report.
type FamilyRow struct {
	Family   string `json:"family"`
	Labelled int    `json:"labelled"`
	Outcomes
	FalsePositive int      `json:"false_positive"`
	Recall        *float64 `json:"recall"`
	Precision     *float64 `json:"precision"`
}

// Confusion is one expected -> found pair and its count.
type Confusion struct {
	Expected string `json:"expected"`
	Found    string `json:"found"`
	Count    int    `json:"count"`
}

// CaptureRow is one capture of the report: its name and digest, counts and outcomes, no content.
type CaptureRow struct {
	File         string                 `json:"file"`
	SHA256       string                 `json:"sha256"`
	Options      map[string]interface{} `json:"options"`
	Records      int                    `json:"records"`
	InputQuality map[string]int         `json:"input_quality"`
	Outcomes     Outcomes               `json:"outcomes"`
	Unlabelled   int                    `json:"unlabelled"`
}

// Report is the evaluation result. It holds provenance, endpoints, labels, counts and digests only.
type Report struct {
	Corpus struct {
		Corpus      string `json:"corpus"`
		Version     string `json:"version"`
		Independent bool   `json:"independent"`
		Source      string `json:"source"`
		LabelledBy  string `json:"labelled_by"`
		LabelBasis  string `json:"label_basis"`
	} `json:"corpus"`
	Engine struct {
		Content        []string `json:"content"`
		LabelSetDigest string   `json:"label_set_digest"`
	} `json:"engine"`
	Totals struct {
		LabelledFlows int `json:"labelled_flows"`
		Outcomes
		UnlabelledFlows int      `json:"unlabelled_flows"`
		FamilyAccuracy  *float64 `json:"family_accuracy"`
	} `json:"totals"`
	Families  []FamilyRow  `json:"families"`
	Confusion []Confusion  `json:"confusion"`
	Captures  []CaptureRow `json:"captures"`
}

func ratio(num, den int) *float64 {
	if den == 0 {
		return nil
	}
	v := float64(num) / float64(den)
	return &v
}

// Evaluate runs every capture of a validated manifest through analyze and scores the labelled flows.
func Evaluate(m *Manifest, pack *content.Pack) (*Report, error) {
	type familyCounts struct {
		Outcomes
		falsePositive int
	}
	perFamily := map[string]*familyCounts{}
	family := func(name string) *familyCounts {
		if perFamily[name] == nil {
			perFamily[name] = &familyCounts{}
		}
		return perFamily[name]
	}
	confusion := map[[2]string]int{}
	r := &Report{}
	r.Corpus.Corpus, r.Corpus.Version, r.Corpus.Independent = m.Corpus, m.Version, m.Independent
	r.Corpus.Source, r.Corpus.LabelledBy, r.Corpus.LabelBasis = m.Source, m.LabelledBy, m.LabelBasis
	r.Engine.Content = []string{pack.Release.Version + "@" + pack.Digests.Release}
	r.Engine.LabelSetDigest = m.labelSet
	for _, c := range m.Captures {
		sink := &sessionSink{quality: map[string]int{}}
		if _, err := analyze.Run(filepath.Join(m.dir, c.File), pack, analyzeOptions(c.Options), sink); err != nil {
			if sink.overflow {
				return nil, refuse("capture %s: %v", c.File, err)
			}
			return nil, refuse("capture %s could not be analyzed: %v", c.File, err)
		}
		byKey := map[string]record{}
		for _, rec := range sink.records {
			byKey[rec.key] = rec // the last record of a flow is scored
		}
		labelled := map[string]bool{}
		row := CaptureRow{File: c.File, SHA256: c.SHA256, Options: c.Options, Records: len(sink.records), InputQuality: sink.quality}
		for _, flow := range c.Flows {
			key := flowKey(flow.Transport, flow.Client, flow.Server)
			labelled[key] = true
			expected := familyOf(flow.Family)
			counts := family(expected)
			rec, seen := byKey[key]
			switch {
			case !seen:
				counts.Missing++
				row.Outcomes.Missing++
			case rec.family == "":
				counts.Unidentified++
				row.Outcomes.Unidentified++
			case rec.family == expected && flow.Application != "" && rec.app != flow.Application:
				counts.WrongApplication++
				row.Outcomes.WrongApplication++
				confusion[[2]string{expected + ":" + flow.Application, rec.app}]++
			case rec.family == expected:
				counts.Correct++
				row.Outcomes.Correct++
			default:
				counts.Wrong++
				row.Outcomes.Wrong++
				confusion[[2]string{expected, rec.family}]++
				family(rec.family).falsePositive++
			}
		}
		for key := range byKey {
			if !labelled[key] {
				row.Unlabelled++
			}
		}
		r.Totals.Correct += row.Outcomes.Correct
		r.Totals.WrongApplication += row.Outcomes.WrongApplication
		r.Totals.Wrong += row.Outcomes.Wrong
		r.Totals.Unidentified += row.Outcomes.Unidentified
		r.Totals.Missing += row.Outcomes.Missing
		r.Totals.UnlabelledFlows += row.Unlabelled
		r.Captures = append(r.Captures, row)
	}
	names := make([]string, 0, len(perFamily))
	for name := range perFamily {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		counts := perFamily[name]
		tp := counts.Correct + counts.WrongApplication
		r.Families = append(r.Families, FamilyRow{Family: name, Labelled: counts.labelled(), Outcomes: counts.Outcomes,
			FalsePositive: counts.falsePositive, Recall: ratio(tp, counts.labelled()), Precision: ratio(tp, tp+counts.falsePositive)})
	}
	pairs := make([][2]string, 0, len(confusion))
	for pair := range confusion {
		pairs = append(pairs, pair)
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i][0] < pairs[j][0] || (pairs[i][0] == pairs[j][0] && pairs[i][1] < pairs[j][1])
	})
	r.Confusion = []Confusion{}
	for _, pair := range pairs {
		r.Confusion = append(r.Confusion, Confusion{Expected: pair[0], Found: pair[1], Count: confusion[pair]})
	}
	r.Totals.LabelledFlows = r.Totals.labelled()
	r.Totals.FamilyAccuracy = ratio(r.Totals.Correct+r.Totals.WrongApplication, r.Totals.LabelledFlows)
	return r, nil
}

func pct(v *float64) string {
	if v == nil {
		return "—"
	}
	return strconv.FormatFloat(100**v, 'f', 1, 64) + "%"
}

func counted(m map[string]int, empty string) string {
	keys := make([]string, 0, len(m))
	for k, n := range m {
		if n > 0 {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return empty
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, m[k])
	}
	return strings.Join(parts, ", ")
}

// IndependenceLine is the report line that states whether the corpus is an independent evaluation.
func IndependenceLine(r *Report) string {
	if r.Corpus.Independent {
		return "Independent of the engine: yes"
	}
	return "Independent of the engine: NOT STATED — this is a self-check, not an independent evaluation"
}

// Render is the Markdown report.
func Render(r *Report) string {
	var b strings.Builder
	c := r.Corpus
	fmt.Fprintf(&b, "# Corpus evaluation: %s %s\n\n", c.Corpus, c.Version)
	fmt.Fprintf(&b, "Source: %s  \nLabelled by: %s (%s)  \n%s  \n", c.Source, c.LabelledBy, c.LabelBasis, IndependenceLine(r))
	fmt.Fprintf(&b, "Engine content: %s; label set %s\n\n", strings.Join(r.Engine.Content, ", "), r.Engine.LabelSetDigest)
	t := r.Totals
	b.WriteString("| labelled flows | correct | wrong application | wrong family | unidentified | missing | unlabelled | family accuracy |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d | %d | %d | %s |\n\n", t.LabelledFlows, t.Correct, t.WrongApplication, t.Wrong,
		t.Unidentified, t.Missing, t.UnlabelledFlows, pct(t.FamilyAccuracy))
	b.WriteString("| family | labelled | correct | wrong app | wrong | unidentified | missing | false positive | recall | precision |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|\n")
	for _, f := range r.Families {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %d | %d | %s | %s |\n", f.Family, f.Labelled, f.Correct, f.WrongApplication,
			f.Wrong, f.Unidentified, f.Missing, f.FalsePositive, pct(f.Recall), pct(f.Precision))
	}
	if len(r.Confusion) > 0 {
		parts := make([]string, len(r.Confusion))
		for i, item := range r.Confusion {
			parts[i] = fmt.Sprintf("%s → %s ×%d", item.Expected, item.Found, item.Count)
		}
		b.WriteString("\nConfusions (expected → found): " + strings.Join(parts, "; ") + "\n")
	}
	b.WriteString("\n| capture | records | outcomes | input quality |\n|---|---|---|---|\n")
	for _, row := range r.Captures {
		o := row.Outcomes
		outcomes := counted(map[string]int{"correct": o.Correct, "wrong-application": o.WrongApplication, "wrong": o.Wrong,
			"unidentified": o.Unidentified, "missing": o.Missing, "unlabelled": row.Unlabelled}, "—")
		fmt.Fprintf(&b, "| %s (%.12s) | %d | %s | %s |\n", row.File, row.SHA256, row.Records, outcomes, counted(row.InputQuality, "clean"))
	}
	b.WriteString("\nScores are per labelled flow of this corpus and say nothing about traffic it does not contain. No payload was stored.\n")
	return b.String()
}
