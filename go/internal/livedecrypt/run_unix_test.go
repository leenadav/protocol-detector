//go:build unix

package livedecrypt

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
)

// A capture child that closes its pipes but ignores SIGINT (sent after the one-second duration) outlives the
// 3-second exit wait. Run must then reap it through the one goroutine already waiting on it: a second Wait or
// a read of ProcessState from the deferred cleanup races with that goroutine (go test -race reports it), and
// Run must not return before the child is reaped.
func TestRunTimeoutReapsTheCaptureChildThroughOneWaiter(t *testing.T) {
	folder := t.TempDir()
	pidFile := filepath.Join(folder, "pid")
	script := "#!/bin/sh\ntrap '' INT\necho $$ > '" + pidFile + "'\nexec >&- 2>&-\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(filepath.Join(folder, "tcpdump"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", folder+string(os.PathListSeparator)+os.Getenv("PATH"))
	keylog := filepath.Join(folder, "keys.log")
	if err := os.WriteFile(keylog, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(map[string]string{"keylog_path": keylog})
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if status := Run(bytes.NewReader(append(request, '\n')), "lo", "tcp", 1, false, pack, &out); status != 1 {
		t.Fatalf("status %d, want 1 after the exit wait timed out\n%s", status, out.String())
	}
	if !strings.Contains(out.String(), `"code": "internal"`) {
		t.Errorf("want the internal failure code\n%s", out.String())
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	// Reaped: neither running nor a zombie, so the pid no longer exists for this process.
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Errorf("capture child %d still exists after Run returned (kill 0: %v)", pid, err)
	}
}
