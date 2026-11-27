//go:build unix

package livedecrypt

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// SR-59: a key-log path is authorized when it is opened: a FIFO, a device, a directory and a symbolic link to a
// regular file are refused with the typed key-log error; a regular file of the calling user is accepted.
func TestSecurityKeyLogOpenRefusesEverythingButARegularFile(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "keys.log")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := OpenKeyLog(regular)
	if err != nil {
		t.Fatalf("a regular file of the user was refused: %v", err)
	}
	k.Close()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"FIFO": fifo, "device": os.DevNull, "directory": dir, "symbolic link": link} {
		k, err := OpenKeyLog(path)
		if err == nil {
			k.Close()
			t.Fatalf("%s accepted as a key log", name)
		}
		if _, typed := err.(*KeyLogError); !typed {
			t.Fatalf("%s: untyped error %T %v", name, err, err)
		}
	}
}
