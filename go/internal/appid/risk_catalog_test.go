package appid

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
)

// SR-30: every flow risk the engine can raise is a content-pack risk with a severity, and every pack risk is
// documented in RISKS.md's risk table with the same severity; a risk name never carries a payload value because the
// names are literals of the risk code.
func TestEveryRiskIsCatalogedAndDocumented(t *testing.T) {
	source, err := os.ReadFile("risks.go")
	if err != nil {
		t.Fatal(err)
	}
	raised := map[string]bool{}
	for _, m := range regexp.MustCompile(`append\((?:found|out), "([a-z0-9-]+)"\)`).FindAllSubmatch(source, -1) {
		raised[string(m[1])] = true
	}
	if len(raised) < 30 {
		t.Fatalf("found %d raised risk names in risks.go; the pattern no longer reads the code", len(raised))
	}
	if regexp.MustCompile(`append\(found, [^"]`).Match(source) {
		t.Fatalf("risks.go appends a found risk that is not a literal name")
	}
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../../RISKS.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]string{}
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z0-9-]+)` \\| (low|medium|high) \\|").FindAllStringSubmatch(string(doc), -1) {
		documented[m[1]] = m[2]
	}
	for name := range raised {
		if _, ok := pack.Risks[name]; !ok {
			t.Errorf("risk %q is raised but not in the content pack", name)
		}
	}
	for name, risk := range pack.Risks {
		if !raised[name] {
			t.Errorf("pack risk %q is never raised by risks.go", name)
		}
		severity, ok := documented[name]
		if !ok {
			t.Errorf("pack risk %q is not documented in RISKS.md", name)
			continue
		}
		if !strings.EqualFold(severity, risk.Severity) {
			t.Errorf("risk %q: RISKS.md says %s, the pack %s", name, severity, risk.Severity)
		}
	}
}
