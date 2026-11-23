// Package livedecrypt is the bounded live decryption worker (presentation/poc_decryption/live.py): tcpdump
// supplies packets, the live monitor's retained tier reassembles each connection once, the decryptor
// authenticates each record once in bounded slices between pipe reads, and the key log is read append-only.
// A failure is reported as a fixed code and sentence: never key-file contents, paths or parser input.
package livedecrypt

// Budgets of one live sample (live.py LIMIT, MAX_FRAMES, MAX_KEYLOG, MAX_CONNECTIONS, WORK_QUANTUM).
const (
	Limit          = 2 * 1024 * 1024
	MaxFrames      = 20000
	MaxKeyLog      = 262144
	MaxConnections = 64
	WorkQuantum    = 64
)

// errorCodes are the sanitized failures: the only text a failure may publish.
var errorCodes = map[string]string{
	"capture_failed": "Capture failed; check tcpdump permission and selected interface.",
	"capture_loss":   "Capture loss reported; decrypted results invalidated.",
	"key_log":        "Key log unreadable, rotated, truncated or outside the POC format; decrypted results invalidated.",
	"budget":         "Live decryption reached a POC budget (bytes, frames, connections or key-log size); restart for a new sample.",
	"internal":       "Live decryption stopped on an internal error; results invalidated.",
}

// KeyLogError is a failure with its code (key_log unless stated).
type KeyLogError struct{ Message, Code string }

func (e *KeyLogError) Error() string { return e.Message }

func keyLogError(message string) *KeyLogError { return &KeyLogError{message, "key_log"} }
