//go:build unix

package livedecrypt

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
)

// A capture child that closes its output and then never exits (it ignores the interrupt) makes Run wait for
// it and give up. The child is reaped by one owner only: the cleanup never reads its state concurrently with
// the pending Wait, nor waits a second time (go test -race reports the former).
func TestRunReapsAChildThatOutlivesTheExitWaitOnce(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\ntrap '' INT TERM\nexec sleep 30 >&- 2>&-\n"
	if err := os.WriteFile(filepath.Join(dir, "tcpdump"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	keylog := filepath.Join(dir, "keys.log")
	if err := os.WriteFile(keylog, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	request := `{"keylog_path": "` + keylog + `"}` + "\n"
	if status := Run(strings.NewReader(request), "lo", "tcp", 1, false, pack, &out); status != 1 {
		t.Fatalf("status %d: %s", status, out.String())
	}
	if !strings.Contains(out.String(), `"code": "internal"`) {
		t.Fatalf("expected the internal failure, got %s", out.String())
	}
}
