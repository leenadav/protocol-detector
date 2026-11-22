package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Contract C15 (the Go part): an interrupt stops the capture child, finalizes what is tracked exactly once,
// publishes the final report and exits cleanly, within a bound; a key-log file is read, never changed.
// The command runs in a child copy of this test binary so a real SIGINT can be delivered to it.

func TestMain(m *testing.M) {
	if args := os.Getenv("PROTODETECT_TEST_RUN"); args != "" {
		var argv []string
		_ = json.Unmarshal([]byte(args), &argv)
		os.Exit(run(argv))
	}
	os.Exit(m.Run())
}

// interrupted starts the command in a child, waits for its first output line, sends SIGINT and returns its
// output, exit status and how long it took to stop after the signal.
func interrupted(t *testing.T, argv []string, stdin []byte) (string, int, time.Duration) {
	t.Helper()
	encoded, _ := json.Marshal(argv)
	child := exec.Command(os.Args[0], "-test.run=NONE")
	child.Env = append(os.Environ(), "PROTODETECT_TEST_RUN="+string(encoded))
	child.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	child.Stderr = &stderr
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	first := make(chan struct{})
	done := make(chan struct{})
	go func() {
		buffer := make([]byte, 4096)
		signalled := false
		for {
			n, err := stdout.Read(buffer)
			output.Write(buffer[:n])
			if !signalled && bytes.Contains(output.Bytes(), []byte("\n")) {
				signalled = true
				close(first)
			}
			if err != nil {
				close(done)
				return
			}
		}
	}()
	select {
	case <-first:
	case <-time.After(10 * time.Second):
		_ = child.Process.Kill()
		t.Fatalf("no output before the interrupt; stderr: %s", stderr.String())
	}
	time.Sleep(300 * time.Millisecond) // let the capture loop run
	sent := time.Now()
	if err := child.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- child.Wait() }()
	var waitErr error
	select {
	case waitErr = <-exited:
	case <-time.After(10 * time.Second):
		_ = child.Process.Kill()
		t.Fatalf("the command did not stop within 10 s of SIGINT; output so far:\n%s", output.String())
	}
	elapsed := time.Since(sent)
	<-done
	status := 0
	if exit, ok := waitErr.(*exec.ExitError); ok {
		status = exit.ExitCode()
	} else if waitErr != nil {
		t.Fatal(waitErr)
	}
	return output.String(), status, elapsed
}

func lastEvent(t *testing.T, output string) map[string]interface{} {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &event); err != nil {
		t.Fatalf("last line is not an event: %v\n%s", err, output)
	}
	return event
}

func TestLiveStopsOnInterrupt(t *testing.T) {
	standIn(t, exchange(), "4 packets captured\\n4 packets received by filter\\n0 packets dropped by kernel\\n", 0)
	output, status, elapsed := interrupted(t, []string{"live", "--interface", "lo0", "--duration", "0", "--stats-interval", "0", "--json"}, nil)
	summary := lastEvent(t, output)
	if status != 0 || summary["type"] != "summary" || summary["stop_reason"] != "limit_or_interrupt" ||
		summary["capture_quality"] != "no_kernel_drops_reported" {
		t.Fatalf("status %d, final event %v", status, summary)
	}
	if strings.Count(output, `"type": "session"`) != 1 || !strings.Contains(output, "Capture stopped before initial message completed") {
		t.Errorf("the tracked connection was not finalized exactly once:\n%s", output)
	}
	if elapsed > 5*time.Second {
		t.Errorf("stopping took %s", elapsed)
	}
}

func TestLiveDecryptStopsOnInterruptAndLeavesTheKeyLogAlone(t *testing.T) {
	client, server, keylog, _ := tlsExchange()
	capture := pcapOf(conversationFrames(51001, 443, client, server)...)
	standIn(t, capture, "6 packets captured\\n6 packets received by filter\\n0 packets dropped by kernel\\n", 0)
	path := filepath.Join(t.TempDir(), "keys.log")
	if err := os.WriteFile(path, []byte(keylog), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	request, _ := json.Marshal(map[string]string{"keylog_path": path})
	output, status, elapsed := interrupted(t, []string{"live-decrypt", "--interface", "lo0", "--filter", "tcp", "--duration", "60", "--no-limits"},
		append(request, '\n'))
	summary := lastEvent(t, output)
	if status != 0 || summary["type"] != "summary" {
		t.Fatalf("status %d, final event %v\n%s", status, summary, output)
	}
	if !strings.Contains(output, `"provisional": false`) || !strings.Contains(output, `"status": "decrypted"`) {
		t.Errorf("no final decrypted report:\n%.800s", output)
	}
	after, err := os.Stat(path)
	content, _ := os.ReadFile(path)
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) ||
		sha256.Sum256(content) != sha256.Sum256([]byte(keylog)) {
		t.Errorf("the key-log file changed")
	}
	if elapsed > 8*time.Second {
		t.Errorf("stopping took %s", elapsed)
	}
}
