package jobs

import (
	"bytes"
	"io"
	"sync"
)

// maxWorkerOutput bounds what a worker may write: an analysis result of the service limits is a few MB, a
// decryption report less. The reference keeps everything communicate() returns; a worker that writes more than
// this is answered as one that returned no readable result.
const maxWorkerOutput = 64 << 20

type limitedBuffer struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len()+len(p) > maxWorkerOutput {
		b.overflow = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

// Bytes is the output, or nothing when it overflowed (which then does not decode).
func (b *limitedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.overflow {
		return nil
	}
	return b.buf.Bytes()
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
