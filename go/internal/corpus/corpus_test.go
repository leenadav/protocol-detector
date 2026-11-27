package corpus

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// distinctive is a DNS query name that must never reach a report: the corpus harness reports endpoints,
// labels, counts and digests, not what the captured bytes say.
const distinctive = "zq7corpuslabel"

func dnsQuery(id uint16, name string) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(append(q, byte(len(label))), label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func stunBinding() []byte {
	return []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
}

func pcap(frames ...[]byte) []byte {
	out := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}
	for i, frame := range frames {
		header := make([]byte, 16)
		binary.LittleEndian.PutUint32(header[0:], 1700000000)
		binary.LittleEndian.PutUint32(header[4:], uint32(i*1000))
		binary.LittleEndian.PutUint32(header[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(header[12:], uint32(len(frame)))
		out = append(append(out, header...), frame...)
	}
	return out
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func flow(transport, client string, cport int, server string, sport int, family string) map[string]interface{} {
	return map[string]interface{}{"transport": transport, "client": []interface{}{client, cport}, "server": []interface{}{server, sport}, "family": family}
}

// sample is a capture with one flow per outcome class and one unlabelled flow.
func sample() ([]byte, []interface{}) {
	data := pcap(
		testframes.UDP("192.0.2.10", 52000, "198.51.100.20", 53, dnsQuery(1, distinctive+".example")),   // correct
		testframes.UDP("192.0.2.11", 52001, "198.51.100.20", 3478, stunBinding()),                       // wrong: labelled dns, is stun
		testframes.UDP("192.0.2.12", 52002, "198.51.100.20", 53, dnsQuery(2, "example.com")),            // wrong application
		testframes.UDP("192.0.2.13", 52003, "198.51.100.20", 53, dnsQuery(3, "unlabelled.example.com")), // unlabelled
	)
	wrongApp := flow("udp", "192.0.2.12", 52002, "198.51.100.20", 53, "dns")
	wrongApp["application"] = "not-the-dns-application"
	flows := []interface{}{
		flow("udp", "192.0.2.10", 52000, "198.51.100.20", 53, "dns"),
		flow("udp", "192.0.2.11", 52001, "198.51.100.20", 3478, "dns"),
		wrongApp,
		flow("udp", "192.0.2.99", 52099, "198.51.100.20", 53, "dns"), // missing: no traffic
	}
	return data, flows
}

// corpusDir writes a corpus with the sample capture; edit adjusts the manifest before it is written.
func corpusDir(t *testing.T, edit func(m map[string]interface{}, capture map[string]interface{})) string {
	t.Helper()
	dir := t.TempDir()
	data, flows := sample()
	if err := os.WriteFile(filepath.Join(dir, "sample.pcap"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	capture := map[string]interface{}{"file": "sample.pcap", "sha256": digest(data), "options": map[string]interface{}{"observation": "handshake"}, "flows": flows}
	m := map[string]interface{}{"corpus": "synthetic", "version": "2026.11", "independent": true,
		"source": "synthetic frames built by the test", "labelled_by": "the test author", "label_basis": "generating client configuration",
		"captures": []interface{}{capture}}
	if edit != nil {
		edit(m, capture)
	}
	text, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), text, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func evaluate(t *testing.T, dir string) *Report {
	t.Helper()
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Evaluate(m, pack)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func refused(t *testing.T, dir, want string) {
	t.Helper()
	_, err := Load(dir)
	var corpusErr *Error
	if !errors.As(err, &corpusErr) {
		t.Fatalf("Load accepted the corpus (err %v); want a refusal containing %q", err, want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal %q does not contain %q", err, want)
	}
}

func TestCorpusScoresEveryOutcomeClass(t *testing.T) {
	r := evaluate(t, corpusDir(t, nil))
	got := r.Totals
	if got.LabelledFlows != 4 || got.Correct != 1 || got.Wrong != 1 || got.WrongApplication != 1 || got.Missing != 1 || got.UnlabelledFlows != 1 {
		t.Fatalf("totals %+v", got)
	}
	if got.FamilyAccuracy == nil || *got.FamilyAccuracy != 0.5 {
		t.Fatalf("family accuracy %v, want 0.5 (correct and wrong-application of 4)", got.FamilyAccuracy)
	}
	if len(r.Confusion) != 2 || r.Confusion[0].Expected != "dns" || r.Confusion[0].Found != "stun" {
		t.Fatalf("confusion %+v", r.Confusion)
	}
	var stun *FamilyRow
	for i := range r.Families {
		if r.Families[i].Family == "stun" {
			stun = &r.Families[i]
		}
	}
	if stun == nil || stun.FalsePositive != 1 || stun.Labelled != 0 {
		t.Fatalf("a wrong identification is a false positive of the family found: %+v", r.Families)
	}
}

func TestCorpusUnidentifiedFlowIsNotCorrect(t *testing.T) {
	dir := t.TempDir()
	data := pcap(testframes.UDP("192.0.2.20", 40000, "198.51.100.30", 40001, []byte("no protocol this engine knows, just text")))
	if err := os.WriteFile(filepath.Join(dir, "u.pcap"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	m := map[string]interface{}{"corpus": "u", "source": "s", "labelled_by": "l", "label_basis": "b", "independent": true,
		"captures": []interface{}{map[string]interface{}{"file": "u.pcap", "sha256": digest(data),
			"flows": []interface{}{flow("udp", "192.0.2.20", 40000, "198.51.100.30", 40001, "dns")}}}}
	text, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), text, 0o600); err != nil {
		t.Fatal(err)
	}
	r := evaluate(t, dir)
	if r.Totals.Correct != 0 || r.Totals.Unidentified != 1 {
		t.Fatalf("an unidentified flow scored as %+v", r.Totals)
	}
}

// SR-67: a corpus without stated provenance and labelling basis is refused.
func TestSecurityCorpusRefusesUnstatedProvenance(t *testing.T) {
	for _, key := range []string{"corpus", "source", "labelled_by", "label_basis", "captures"} {
		t.Run(key, func(t *testing.T) {
			refused(t, corpusDir(t, func(m, _ map[string]interface{}) { delete(m, key) }), key)
			refused(t, corpusDir(t, func(m, _ map[string]interface{}) { m[key] = "" }), key)
		})
	}
	refused(t, corpusDir(t, func(m, _ map[string]interface{}) { m["labelled_by"] = "   " }), "labelled_by")
	refused(t, corpusDir(t, func(m, _ map[string]interface{}) { m["captures"] = []interface{}{} }), "captures")
}

// SR-67: every capture's SHA-256 is verified against the manifest before it is analyzed.
func TestSecurityCorpusVerifiesEveryCaptureDigest(t *testing.T) {
	refused(t, corpusDir(t, func(_, c map[string]interface{}) { c["sha256"] = strings.Repeat("0", 64) }), "sha256 mismatch")
	refused(t, corpusDir(t, func(_, c map[string]interface{}) { delete(c, "sha256") }), "lacks sha256")
	dir := corpusDir(t, nil)
	f, err := os.OpenFile(filepath.Join(dir, "sample.pcap"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	refused(t, dir, "sha256 mismatch") // the file changed after the manifest was written
}

// SR-67: capture files are confined to the corpus directory.
func TestSecurityCorpusConfinesCapturesToTheDirectory(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.pcap")
	data, _ := sample()
	if err := os.WriteFile(outside, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, file := range map[string]string{"parent": "../outside.pcap", "absolute": outside, "missing": "absent.pcap"} {
		t.Run(name, func(t *testing.T) {
			refused(t, corpusDir(t, func(_, c map[string]interface{}) { c["file"], c["sha256"] = file, digest(data) }), "outside the corpus directory")
		})
	}
	t.Run("symlink", func(t *testing.T) {
		dir := corpusDir(t, func(_, c map[string]interface{}) { c["file"] = "link.pcap" })
		if err := os.Symlink(outside, filepath.Join(dir, "link.pcap")); err != nil {
			t.Fatal(err)
		}
		refused(t, dir, "outside the corpus directory")
	})
	t.Run("subdirectory", func(t *testing.T) {
		dir := corpusDir(t, func(_, c map[string]interface{}) { c["file"] = "sub/sample.pcap" })
		if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "sub", "sample.pcap"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, dir, "outside the corpus directory")
	})
	t.Run("directory", func(t *testing.T) {
		dir := corpusDir(t, func(_, c map[string]interface{}) { c["file"] = "." })
		refused(t, dir, "outside the corpus directory")
	})
}

// SR-67: only whitelisted Analyzer options are accepted, with values of the expected type.
func TestSecurityCorpusAcceptsOnlyWhitelistedOptions(t *testing.T) {
	refused(t, corpusDir(t, func(_, c map[string]interface{}) {
		c["options"] = map[string]interface{}{"include_hostnames": true, "observation": "handshake"}
	}), "unsupported capture options: include_hostnames")
	refused(t, corpusDir(t, func(_, c map[string]interface{}) { c["options"] = map[string]interface{}{"policy": "/etc/passwd"} }), "unsupported capture options: policy")
	for option, value := range map[string]interface{}{"observation": "everything", "checksums": true, "continuation": -1,
		"tcp_hint": "not-a-family", "fingerprints": "yes"} {
		t.Run(option, func(t *testing.T) {
			refused(t, corpusDir(t, func(_, c map[string]interface{}) { c["options"] = map[string]interface{}{option: value} }), option)
		})
	}
	r := evaluate(t, corpusDir(t, func(_, c map[string]interface{}) {
		c["options"] = map[string]interface{}{"observation": "handshake", "checksums": "audit", "continuation": 0, "udp_hint": "dns",
			"fingerprints": false, "certificates": false}
	}))
	if r.Totals.LabelledFlows != 4 {
		t.Fatalf("every whitelisted option is accepted: %+v", r.Totals)
	}
}

// SR-67: flow labels are well formed and name a family the engine declares.
func TestSecurityCorpusRefusesMalformedLabels(t *testing.T) {
	refused(t, corpusDir(t, func(_, c map[string]interface{}) {
		c["flows"] = []interface{}{flow("udp", "192.0.2.10", 52000, "198.51.100.20", 53, "not-a-family")}
	}), "does not declare")
	refused(t, corpusDir(t, func(_, c map[string]interface{}) {
		c["flows"] = []interface{}{flow("sctp", "192.0.2.10", 52000, "198.51.100.20", 53, "dns")}
	}), "flow label needs")
	refused(t, corpusDir(t, func(_, c map[string]interface{}) {
		c["flows"] = []interface{}{flow("udp", "2001:db8::1", 52000, "198.51.100.20", 53, "dns")}
	}), "flow label needs")
	refused(t, corpusDir(t, func(_, c map[string]interface{}) {
		c["flows"] = []interface{}{flow("udp", "192.0.2.10", 70000, "198.51.100.20", 53, "dns")}
	}), "flow label needs")
}

// SR-67: reports carry endpoints, labels, counts and digests only: no payload, hostname or captured bytes.
func TestSecurityCorpusReportCarriesNoPayloadOrHostname(t *testing.T) {
	dir := corpusDir(t, func(_, c map[string]interface{}) {
		c["options"] = map[string]interface{}{"fingerprints": true, "certificates": true}
	})
	if analyzeOptions(map[string]interface{}{"fingerprints": true, "certificates": true}).IncludeHostnames {
		t.Fatal("the harness asks analyze for hostnames")
	}
	r := evaluate(t, dir)
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := sample()
	for _, out := range []string{string(encoded), Render(r)} {
		if strings.Contains(out, distinctive) {
			t.Fatalf("the report carries the queried hostname %q:\n%s", distinctive, out)
		}
		if strings.Contains(out, hex.EncodeToString(data[40:60])) || strings.Contains(out, string(data[40:60])) {
			t.Fatal("the report carries captured bytes")
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for key := range fields {
		switch key {
		case "corpus", "engine", "totals", "families", "confusion", "captures":
		default:
			t.Fatalf("unexpected report section %q", key)
		}
	}
	if len(r.Engine.Content) != 1 || !strings.Contains(r.Engine.Content[0], "@") || len(r.Engine.LabelSetDigest) != 16 {
		t.Fatalf("the report pins the content release and the label set: %+v", r.Engine)
	}
}

// SR-67: a corpus not declared independent is reported as a self-check.
func TestSecurityCorpusNotDeclaredIndependentIsASelfCheck(t *testing.T) {
	for name, edit := range map[string]func(m, _ map[string]interface{}){
		"absent": func(m, _ map[string]interface{}) { delete(m, "independent") },
		"false":  func(m, _ map[string]interface{}) { m["independent"] = false },
		"string": func(m, _ map[string]interface{}) { m["independent"] = "yes" },
	} {
		t.Run(name, func(t *testing.T) {
			r := evaluate(t, corpusDir(t, edit))
			if r.Corpus.Independent || !strings.Contains(Render(r), "NOT STATED — this is a self-check, not an independent evaluation") {
				t.Fatalf("a corpus not declared independent must read as a self-check:\n%s", Render(r))
			}
		})
	}
	r := evaluate(t, corpusDir(t, nil))
	if !strings.Contains(Render(r), "Independent of the engine: yes") {
		t.Fatal("a corpus declared independent says so")
	}
}

// The manifest is read under a byte bound before it is parsed.
func TestSecurityCorpusBoundsTheManifest(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, MaxManifestBytes+1)
	for i := range big {
		big[i] = ' '
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	refused(t, dir, "larger than")
}
