//go:build unix

package livedecrypt

import (
	"bytes"
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
}

// OpenKeyLog opens a regular file owned by the calling user, without following a symbolic link.
func OpenKeyLog(path string) (*KeyLog, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, keyLogError("Key log could not be opened.")
	}
	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil || info.Mode&syscall.S_IFMT != syscall.S_IFREG || int(info.Uid) != syscall.Getuid() {
		_ = syscall.Close(fd)
		return nil, keyLogError("Choose a regular key-log file owned by your user.")
	}
	return &KeyLog{path: path, fd: fd, dev: uint64(info.Dev), ino: uint64(info.Ino)}, nil
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
	case info.Size == k.offset:
		return "", nil
	}
	buffer := make([]byte, MaxKeyLog+1-k.offset)
	n, err := syscall.Pread(k.fd, buffer, k.offset)
	if err != nil {
		return "", keyLogError("Key log could not be read.")
	}
	k.offset += int64(n)
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
