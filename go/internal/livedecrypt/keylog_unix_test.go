//go:build unix

package livedecrypt

import (
	"os"
	"path/filepath"
	"testing"
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
		f.Close()
		text, err := keys.Read()
		if typed, ok := err.(*KeyLogError); !ok || typed.Message != "Key log was truncated." || typed.Code != "key_log" {
			t.Errorf("regrown to %d bytes: %q %#v", len(regrown), text, err)
		}
	}
}
