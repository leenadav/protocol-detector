package content

import _ "embed"

// packJSONBytes is the content pack built into the module (integration work item #16): a byte-for-byte copy
// of migration/fixtures/content.json, the pack the Python reference exports. A host that links the module
// needs no file on disk. TestEmbeddedPackEqualsTheFixture fails when the copy drifts from the fixture.
//
//go:embed pack.json
var packJSONBytes []byte

// Embedded parses the built-in pack. It goes through Parse, so the built-in bytes get the same size and
// structural validation as bytes a host supplies.
//
// The pack's Release.Digest is the identifier the Python exporter wrote into it. This package does not
// recompute or verify it: it is a carried source identifier, not proof of integrity, authenticity or
// equality. A digest both runtimes compute from a language-neutral definition is a separate follow-up.
func Embedded() (*Pack, error) { return Parse(packJSONBytes) }

// EmbeddedBytes returns a copy of the built-in pack bytes.
func EmbeddedBytes() []byte { return append([]byte(nil), packJSONBytes...) }

// ParseSupplied validates pack bytes a host supplies in place of the built-in pack: the size bound of
// MaxPackBytes, then everything Parse checks. A non-empty digest inside the bytes proves nothing about
// them; see Embedded.
func ParseSupplied(data []byte) (*Pack, error) {
	if len(data) == 0 || len(data) > MaxPackBytes {
		return nil, invalid("content pack is empty or exceeds the size limit")
	}
	return Parse(data)
}
