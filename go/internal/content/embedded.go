package content

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
)

// packJSONBytes is the content pack built into the module (integration work item #16): a byte-for-byte copy
// of migration/fixtures/content.json, the pack the Python reference exports. A host that links the module
// needs no file on disk. TestEmbeddedPackEqualsTheFixture fails when the copy drifts from the fixture.
//
//go:embed pack.json
var packJSONBytes []byte

// EmbeddedPackDigest is the pack digest (migration/CONTENT-DIGEST.md) this build pins for the built-in pack:
// a build constant, so it is trusted exactly as far as the build is. Replacing pack.json requires replacing
// this value in the same change; Embedded refuses the pack otherwise.
//
// The pin is an integrity check: the pack in use has exactly the pinned contents. It does not show that the
// contents are true, that they match what the engine implements, who published them, what they cover, or
// that they are not an older release.
const EmbeddedPackDigest = "02620ad2606202de99beac0035ded3a2983824eaeb268a1a0c747fc6d34f7f17"

// Embedded parses the built-in pack and refuses it unless its pack digest is EmbeddedPackDigest.
func Embedded() (*Pack, error) { return ParsePinned(packJSONBytes, EmbeddedPackDigest) }

// EmbeddedBytes returns a copy of the built-in pack bytes.
func EmbeddedBytes() []byte { return append([]byte(nil), packJSONBytes...) }

// ParsePinned is how a host loads pack bytes it supplies in place of the built-in pack. expected is the pack
// digest the host pinned out of band (a build constant, its configuration, a signed catalog): 64 lowercase
// hexadecimal digits. The digest of data is computed and compared before anything else reads the document;
// on a mismatch no Pack is built or returned. The matching pack then gets everything Parse checks.
//
// The returned Pack holds no reference to data. Nothing in this module changes a Pack after it is returned;
// its tables are exported maps, so a holder that writes to them voids the pin for itself.
func ParsePinned(data []byte, expected string) (*Pack, error) {
	if len(data) == 0 || len(data) > MaxPackBytes {
		return nil, invalid("content pack is empty or exceeds the size limit")
	}
	if !hex64.MatchString(expected) {
		return nil, invalid("the pinned content pack digest is not 64 lowercase hexadecimal digits")
	}
	canonical, err := Canonical(data)
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	hasher.Write([]byte(PackDigestPrefix))
	hasher.Write(canonical)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hasher.Sum(nil))), []byte(expected)) != 1 {
		return nil, invalid("content pack does not have the pinned digest")
	}
	p, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if p.Digests.Pack != expected { // one definition of the digest: the loader's must be the one compared above
		return nil, invalid("content pack does not have the pinned digest")
	}
	return p, nil
}

// ParseSupplied validates pack bytes without a pin: the size bound of MaxPackBytes, then everything Parse
// checks, which includes that the pack's tables are the ones its stated digests describe. That is
// self-consistency, not integrity against a trusted value: a host that needs to know it loaded the pack it
// meant to load uses ParsePinned.
func ParseSupplied(data []byte) (*Pack, error) {
	if len(data) == 0 || len(data) > MaxPackBytes {
		return nil, invalid("content pack is empty or exceeds the size limit")
	}
	return Parse(data)
}
