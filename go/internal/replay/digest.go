package replay

import (
	"crypto/sha256"
	"encoding/hex"
)

func digest(prefix []byte) string {
	sum := sha256.Sum256(prefix)
	return hex.EncodeToString(sum[:])[:16]
}
