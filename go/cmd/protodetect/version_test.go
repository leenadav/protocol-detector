package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// TestVersionIsSettableAtBuildTime pins PRO-195: the release build stamps the
// binary with `-ldflags "-X main.version=<release>"`, which the linker silently
// ignores for a constant. Assigning to version only compiles while it is a
// package-level string variable, and the default stays "0.0.0-m4".
func TestVersionIsSettableAtBuildTime(t *testing.T) {
	if version != "0.0.0-m4" {
		t.Fatalf("default version = %q, want 0.0.0-m4", version)
	}
	saved := version
	t.Cleanup(func() { version = saved })
	version = "9.9.9-pro195"

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	code := run([]string{"version"})
	os.Stdout = stdout
	w.Close()
	out, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || !strings.HasPrefix(string(out), "protodetect 9.9.9-pro195 (go backend;") {
		t.Fatalf("version output = %q (exit %d), want the stamped version", out, code)
	}
}
