//go:build frozencontent

package content

import _ "embed"

// A frozencontent build (PRO-428) carries the content pack and release history exactly as they were at
// FrozenVersion, the release every frozen answer was recorded at: migration/fixtures/cases.json and the golden
// files of `make go-check-parity`. Only those gates use it (`make go-build-golden`); the product binary is the
// default build, which embeds the current pack (embed.go). The frozen copies are checked byte for byte against
// the release ledger by TestFrozenReleaseIsTheLockedRelease.
//
//go:embed frozen/pack-2026.11.9.json
var embedded []byte

//go:embed frozen/history-2026.11.9.json
var embeddedHistory []byte

// Frozen reports whether this binary was built with the frozen content of FrozenVersion.
const Frozen = true
