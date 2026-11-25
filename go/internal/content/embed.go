//go:build !frozencontent

package content

import _ "embed"

// pack.json is a byte-for-byte copy of migration/fixtures/content.json (TestEmbeddedPackIsTheSharedPack), so
// the binary carries the detection content of the release it was built from and needs no file at run time.
//
//go:embed pack.json
var embedded []byte

//go:embed history.json
var embeddedHistory []byte

// Frozen reports whether this binary was built with the frozen content of FrozenVersion (embed_frozen.go).
const Frozen = false
