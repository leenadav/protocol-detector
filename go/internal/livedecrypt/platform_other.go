//go:build !unix

package livedecrypt

// The live key-log reader needs Unix file semantics (O_NOFOLLOW, the owner check, positional reads), as the
// reference live.py does. The release also builds for Windows, where live decryption is not available: opening
// a key log fails with the sanitized key_log code, and no CPU limit is set.

// KeyLog is the append-only key-log reader; on this platform it cannot be opened.
type KeyLog struct{}

// OpenKeyLog always fails on this platform.
func OpenKeyLog(path string) (*KeyLog, error) {
	return nil, keyLogError("Key log could not be opened.")
}

// Read is never reached: OpenKeyLog does not return a KeyLog here.
func (k *KeyLog) Read() (string, error) { return "", keyLogError("Key log could not be read.") }

// Close releases nothing.
func (k *KeyLog) Close() {}

// limitCPU: no RLIMIT_CPU on this platform.
func limitCPU(seconds uint64) {}
