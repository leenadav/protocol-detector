//go:build unix

package livedecrypt

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A key log truncated and rewritten in place (same inode) to at least the bytes already read between two
// polls is a truncation, not new lines: the bytes before the read offset changed (Codex PRO-18 P2).
func TestKeyLogRefusesATruncationThatRegrewBetweenPolls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.log")
	if err := os.WriteFile(path, []byte("CLIENT_RANDOM aa bb\npart"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := OpenKeyLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	if text, err := keys.Read(); err != nil || text != "CLIENT_RANDOM aa bb\n" {
		t.Fatalf("first read %q %v", text, err)
	}
	for _, regrown := range []string{"CLIENT_RANDOM cc dd\npart", "CLIENT_RANDOM cc dd\npart of a new line\n"} {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600) // same inode
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(regrown); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		text, err := keys.Read()
		if typed, ok := err.(*KeyLogError); !ok || typed.Message != "Key log was truncated." || typed.Code != "key_log" {
			t.Errorf("regrown to %d bytes: %q %#v", len(regrown), text, err)
		}
	}
}

// openKeyLogWithin opens path in a goroutine and fails the test when the open does not return in time: a
// FIFO opened without O_NONBLOCK would block until a writer appears (SR-59, SEC-PYRM-3).
func openKeyLogWithin(t *testing.T, path string, limit time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		keys, err := OpenKeyLog(path)
		if keys != nil {
			keys.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		// Unblock the stuck open with a writer so the goroutine ends, then fail.
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close() // only releases the stuck open; the test fails next either way
		}
		t.Fatalf("OpenKeyLog(%s) did not return within %s", path, limit)
		return nil
	}
}

func wantRefusedAsNotARegularOwnedFile(t *testing.T, what string, err error) {
	t.Helper()
	typed, ok := err.(*KeyLogError)
	if !ok || typed.Message != "Choose a regular key-log file owned by your user." || typed.Code != "key_log" {
		t.Errorf("%s: got %#v, want the regular-file refusal", what, err)
	}
}

// SR-59: a FIFO is refused, and refused at once, not after a writer appears.
func TestKeyLogRefusesAFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	wantRefusedAsNotARegularOwnedFile(t, "FIFO", openKeyLogWithin(t, path, 5*time.Second))
}

// SR-59: a device file is refused.
func TestKeyLogRefusesADeviceFile(t *testing.T) {
	wantRefusedAsNotARegularOwnedFile(t, os.DevNull, openKeyLogWithin(t, os.DevNull, 5*time.Second))
}

// SR-59: a regular file owned by another user is refused; the file is the caller's, the seen user id is not.
func TestKeyLogRefusesAFileOwnedByAnotherUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.log")
	if err := os.WriteFile(path, []byte("CLIENT_RANDOM aa bb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := OpenKeyLog(path)
	if err != nil {
		t.Fatalf("the caller's own file was refused: %v", err)
	}
	keys.Close()
	real := getuid
	t.Cleanup(func() { getuid = real })
	getuid = func() int { return real() + 1 }
	_, err = OpenKeyLog(path)
	wantRefusedAsNotARegularOwnedFile(t, "another user's file", err)
}
