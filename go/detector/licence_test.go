package detector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// Working plan item #1: the repository is licensed under Apache-2.0. A Go module is published as its own
// zip, without the files above go/, so the module carries its own LICENSE and NOTICE; they must stay equal to
// the repository's, and LICENSE must stay the unmodified Apache text.
func TestModuleCarriesTheRepositoryLicence(t *testing.T) {
	// SHA-256 of https://www.apache.org/licenses/LICENSE-2.0.txt, the unmodified licence text.
	const apache20 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
	for _, name := range []string{"LICENSE", "NOTICE"} {
		module, err := os.ReadFile("../" + name)
		if err != nil {
			t.Fatal(err)
		}
		repository, err := os.ReadFile("../../" + name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(module, repository) {
			t.Errorf("go/%s differs from the repository's %s", name, name)
		}
		if name == "LICENSE" {
			if sum := sha256.Sum256(module); hex.EncodeToString(sum[:]) != apache20 {
				t.Errorf("LICENSE is not the unmodified Apache License 2.0 text (sha256 %x)", sum)
			}
		} else if !strings.Contains(string(module), "Apache License, Version 2.0") || !strings.Contains(string(module), "content.json") {
			t.Errorf("NOTICE does not name the licence and the content pack it covers")
		}
	}
}
