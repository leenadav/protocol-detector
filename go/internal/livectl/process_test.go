package livectl

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

// A stand-in worker: writes two events, starts a child in its process group, waits to be interrupted.
const holdWorker = `read line
printf '%s\n' "$line" > "$DIR/stdin"
echo '{"type": "classification", "client": ["10.0.0.1", 5], "server": ["10.0.0.2", 80], "status": "identified"}'
echo '{"type": "progress", "packets": 1}'
sleep 300 >/dev/null 2>&1 &
echo $! > "$DIR/child"
if [ -n "$IGNORE_INT" ]; then trap '' INT; else trap 'exit 0' INT; fi
while :; do sleep 0.05; done
`

func manager(t *testing.T, dir string) *Manager {
	t.Helper()
	script := filepath.Join(dir, "worker.sh")
	if err := os.WriteFile(script, []byte(holdWorker), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DIR", dir)
	m := NewManager(func(iface, filter string, duration int64, decrypt bool) []string { return []string{"/bin/sh", script} })
	m.ifaces = func() []string { return []string{"lo"} }
	m.lookTcp = func() bool { return true }
	return m
}

func runID(t *testing.T, snapshot *ojson.Object) string {
	t.Helper()
	v, _ := snapshot.Get("run_id")
	id, ok := v.(string)
	if !ok {
		t.Fatalf("no run id: %s", ojson.MustDumps(snapshot))
	}
	return id
}

func until(t *testing.T, what string, done func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if done() {
			return
		}
	}
	t.Fatal("timed out waiting for " + what)
}

func phase(m *Manager) string {
	v, _ := m.StateView().Get("state")
	s, _ := v.(string)
	return s
}

// C15: stop ends the run's whole process group, the key log is never written, and only the named run stops.
func TestStopReleasesTheProcessGroupAndLeavesTheKeyLog(t *testing.T) {
	dir := t.TempDir()
	m := manager(t, dir)
	keylog := filepath.Join(dir, "keys.log")
	if err := os.WriteFile(keylog, []byte("CLIENT_RANDOM 00 11\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(keylog)
	snap, err := m.Start("lo", ojson.FromInt(30), "synthetic", keylog)
	if err != nil {
		t.Fatal(err)
	}
	id := runID(t, snap)
	if _, err := m.Start("lo", ojson.FromInt(30), "synthetic", nil); err == nil || err.Error() != "A live capture is already running." {
		t.Fatalf("second start: %v", err)
	}
	until(t, "the worker's events", func() bool { return strings.Contains(ojson.MustDumps(m.StateView()), `"events_total": 1`) })
	if line, _ := os.ReadFile(filepath.Join(dir, "stdin")); strings.TrimSpace(string(line)) != `{"keylog_path": "`+keylog+`"}` {
		t.Fatalf("the key-log path did not arrive on standard input: %q", line)
	}
	if m.Heartbeat("stale") || !m.Heartbeat(id) {
		t.Fatal("heartbeat is not scoped to the run")
	}
	m.Stop(nil, "stale")
	if phase(m) != "running" {
		t.Fatal("a stale stop stopped the run")
	}
	m.Stop(nil, id)
	until(t, "the stopped state", func() bool { return phase(m) == "stopped" })
	after, _ := os.Stat(keylog)
	if !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Fatal("the key log was modified")
	}
	if got := ojson.MustDumps(m.Reset("stale")); !strings.Contains(got, `"reason": "stale"`) {
		t.Fatal(got)
	}
	if got := ojson.MustDumps(m.Reset(id)); got != `{"reset": true, "reason": "cleared", "run_id": null}` {
		t.Fatal(got)
	}
	if got := ojson.MustDumps(m.Snapshot()); !strings.Contains(got, `"events": [], "sessions": []`) || !strings.Contains(got, `"run_id": null`) {
		t.Fatal(got)
	}
}

// A worker that ignores the interrupt is killed with its whole process group after five seconds (the
// reference's stop: SIGINT, wait, then SIGKILL to the run's own group).
func TestStopKillsTheProcessGroupOfAWorkerThatIgnoresTheInterrupt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("IGNORE_INT", "1")
	m := manager(t, dir)
	snap, err := m.Start("lo", ojson.FromInt(30), "synthetic", nil)
	if err != nil {
		t.Fatal(err)
	}
	until(t, "the worker's child", func() bool { _, err := os.Stat(filepath.Join(dir, "child")); return err == nil })
	childText, _ := os.ReadFile(filepath.Join(dir, "child"))
	child, _ := strconv.Atoi(strings.TrimSpace(string(childText)))
	m.Stop(nil, runID(t, snap))
	// Killed by signal 9, the worker's status is -9: the reference reports that and the run fails.
	until(t, "the failed state", func() bool { return phase(m) == "failed" })
	if got := ojson.MustDumps(m.StateView()); !strings.Contains(got, `"error": "Capture process exited unexpectedly (-9)."`) {
		t.Fatal(got)
	}
	until(t, "the worker's child to be killed with its group", func() bool { return syscall.Kill(child, 0) == syscall.ESRCH })
}

// A run nobody renews is stopped by the lease, and the worker is killed if it ignores the interrupt.
func TestLeaseExpiryStopsAnUnwatchedRun(t *testing.T) {
	dir := t.TempDir()
	m := manager(t, dir)
	if _, err := m.Start("lo", ojson.FromInt(30), "synthetic", nil); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.lease = time.Now().Add(-time.Minute)
	m.mu.Unlock()
	until(t, "the lease to stop the run", func() bool { return phase(m) == "stopped" })
}

func TestStartRefusalsAreTheReferences(t *testing.T) {
	m := manager(t, t.TempDir())
	cases := []struct {
		iface, duration, scope, keylog ojson.Value
		want                           string
	}{
		{"eth9", ojson.FromInt(30), "all", nil, "Select an available network interface."},
		{"lo", true, "all", nil, "Duration must be 5–600 seconds."},
		{"lo", 30.0, "all", nil, "Duration must be 5–600 seconds."},
		{"lo", ojson.Int("1000000000000000000000"), "all", nil, "Duration must be 5–600 seconds."},
		{"lo", ojson.FromInt(30), "x", nil, "Invalid capture scope."},
		{"lo", ojson.FromInt(30), "all", "relative", "Enter the absolute path of the browser key log."},
		{"lo", ojson.FromInt(121), "all", "/abs", "Live decryption is limited to 120 seconds per sample."},
	}
	for _, c := range cases {
		if _, err := m.Start(c.iface, c.duration, c.scope, c.keylog); err == nil || err.Error() != c.want {
			t.Errorf("%v %v %v %v: %v", c.iface, c.duration, c.scope, c.keylog, err)
		}
	}
	m.lookTcp = func() bool { return false }
	if _, err := m.Start("lo", ojson.FromInt(30), "all", nil); err == nil || err.Error() != "tcpdump is not installed on this computer." {
		t.Fatal(err)
	}
}
