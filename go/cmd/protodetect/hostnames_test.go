package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// SR-9: live output and session records omit hostnames unless explicitly enabled (--hostnames); with it the
// asserted name appears, so the check can never pass because the capture has no name.
func TestHostnamesAreOptIn(t *testing.T) {
	const capture, name = "../../../sample.pcap", "example.com"
	sessions := func(args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		if status := runAnalyze(append(append([]string{"--json", "--sessions"}, args...), capture), &stdout, &stderr); status != 0 {
			t.Fatalf("analyze %v: status %d: %s", args, status, stderr.String())
		}
		count, named := 0, ""
		for _, line := range strings.Split(stdout.String(), "\n") {
			var row map[string]interface{}
			if json.Unmarshal([]byte(line), &row) != nil || row["type"] != "session" {
				continue
			}
			count++
			if strings.Contains(line, name) {
				named += line
			}
		}
		return count, named
	}
	if count, named := sessions(); count == 0 || named != "" {
		t.Fatalf("without --hostnames: %d session records, named: %s", count, named)
	}
	if count, named := sessions("--hostnames"); count == 0 || named == "" {
		t.Fatalf("with --hostnames: %d session records and none names %s", count, name)
	}

	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	live := func(args ...string) string {
		var stdout, stderr bytes.Buffer
		base := []string{"--stdin", "--replay-clock", "--duration", "0", "--stats-interval", "0", "--all-events", "--json"}
		if status := runLive(append(base, args...), bytes.NewReader(data), &stdout, &stderr); status != 0 {
			t.Fatalf("live %v: status %d: %s", args, status, stderr.String())
		}
		return stdout.String()
	}
	if out := live(); out == "" || strings.Contains(out, name) {
		t.Fatalf("live output without --hostnames names the host:\n%s", out)
	}
	if out := live("--hostnames"); !strings.Contains(out, name) {
		t.Fatalf("live output with --hostnames lacks the host:\n%s", out)
	}
}
