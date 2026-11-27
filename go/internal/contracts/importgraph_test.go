package contracts

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The import-graph rule of ADR 0002 (PRO-107, Culvert's plan item #19, answer (a)): no non-standard package is
// compiled into the detection path. golang.org/x/crypto stays a requirement of go/go.mod, used only by key-log
// decryption (internal/decrypt); the rule is checked here on the import graph, not on the require lines.
var detectionPath = []string{"./internal/engine/...", "./internal/analyzer/...", "./internal/session/...",
	"./internal/reassembly/...", "./internal/protocols/...", "./internal/content/...", "./internal/appid/...", "./internal/childapp/...",
	"./internal/contracts/..."}

const module = "github.com/leenadav/protocol-detector/go/"

// foreign lists the non-standard packages outside this module that the patterns import, transitively.
func foreign(t *testing.T, patterns ...string) []string {
	t.Helper()
	root, err := filepath.Abs("../..") // go/, the module root
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}"}, patterns...)
	// go test puts its own GOROOT/bin first on the test's PATH, so this is the toolchain running the test
	// (runtime.GOROOT is deprecated since Go 1.24, staticcheck SA1019).
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goBin, args...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, module) {
			seen[line] = true
		}
	}
	list := make([]string, 0, len(seen))
	for pkg := range seen {
		list = append(list, pkg)
	}
	sort.Strings(list)
	return list
}

func TestDetectionPathImportsOnlyTheStandardLibrary(t *testing.T) {
	patterns := append([]string{}, detectionPath...)
	if _, err := os.Stat("../../detector"); err == nil { // the public package Culvert imports, once it exists
		patterns = append(patterns, "./detector/...")
	}
	if got := foreign(t, patterns...); len(got) > 0 {
		t.Fatalf("non-standard packages in the detection path (ADR 0002 import-graph rule): %v", got)
	}
	// The check sees a dependency where one is imported: key-log decryption is the one user of x/crypto.
	if got := foreign(t, "./internal/decrypt"); len(got) == 0 || !strings.HasPrefix(got[0], "golang.org/x/crypto/") {
		t.Fatalf("internal/decrypt should import golang.org/x/crypto, got %v", got)
	}
}
