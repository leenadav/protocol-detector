//go:build unix

package livedecrypt

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"syscall"
)

// KeyLog is an append-only reader of an NSS key-log file: each read returns only the new complete lines.
// Truncation and rotation are errors, never a silent re-read from the start.
type KeyLog struct {
	path     string
	fd       int
	dev, ino uint64
	offset   int64
	partial  []byte
	consumed hash.Hash // SHA-256 of the bytes before offset: a rewrite in place is a truncation
}

// getuid is the calling user's id; a test replaces it to check that another user's file is refused (SR-59).
var getuid = syscall.Getuid

// OpenKeyLog opens a regular file owned by the calling user, without following a symbolic link.
func OpenKeyLog(path string) (*KeyLog, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, keyLogError("Key log could not be opened.")
	}
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil || info.Mode&syscall.S_IFMT != syscall.S_IFREG || int(info.Uid) != getuid() {
		_ = syscall.Close(fd)
		return nil, keyLogError("Choose a regular key-log file owned by your user.")
	}
	return &KeyLog{path: path, fd: fd, dev: uint64(info.Dev), ino: uint64(info.Ino), consumed: sha256.New()}, nil
}

// Read returns the complete lines appended since the last read ("" when there are none).
func (k *KeyLog) Read() (string, error) {
	var info, current syscall.Stat_t
	if err := syscall.Fstat(k.fd, &info); err != nil {
		return "", keyLogError("Key log could not be read.")
	}
	if err := syscall.Stat(k.path, &current); err != nil || uint64(current.Dev) != k.dev || uint64(current.Ino) != k.ino {
		return "", keyLogError("Key log was rotated or removed.")
	}
	switch {
	case info.Size < k.offset:
		return "", keyLogError("Key log was truncated.")
	case info.Size > MaxKeyLog:
		return "", &KeyLogError{"Live key log exceeds 256 KiB.", "budget"}
	}
	// The inode and size alone miss a truncation that regrew, between two polls, to at least the bytes
	// already read: the bytes before the offset must still be the ones consumed, or the reader would keep
	// stale secrets and join an old partial line to new bytes (Go-only; live.py checks the size only;
	// Codex PRO-18 P2). The log is at most 256 KiB, read once per poll.
	if k.offset > 0 {
		prefix := make([]byte, k.offset)
		n, err := syscall.Pread(k.fd, prefix, 0)
		if err != nil {
			return "", keyLogError("Key log could not be read.")
		}
		if digest := sha256.Sum256(prefix[:n]); int64(n) != k.offset || !bytes.Equal(digest[:], k.consumed.Sum(nil)) {
			return "", keyLogError("Key log was truncated.")
		}
	}
	if info.Size == k.offset {
		return "", nil
	}
	buffer := make([]byte, MaxKeyLog+1-k.offset)
	n, err := syscall.Pread(k.fd, buffer, k.offset)
	if err != nil {
		return "", keyLogError("Key log could not be read.")
	}
	k.offset += int64(n)
	k.consumed.Write(buffer[:n])
	data := append(k.partial, buffer[:n]...)
	// Browsers append asynchronously; never parse a partly written line.
	cut := bytes.LastIndexByte(data, '\n') + 1
	k.partial = append([]byte{}, data[cut:]...)
	if len(k.partial) > 4096 {
		return "", keyLogError("Key log line is too long.")
	}
	for _, b := range data[:cut] {
		if b > 0x7f {
			return "", keyLogError("Key log is not ASCII.")
		}
	}
	return string(data[:cut]), nil
}

// Close releases the file.
func (k *KeyLog) Close() { _ = syscall.Close(k.fd) }
