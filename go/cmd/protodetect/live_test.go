package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// frame is an Ethernet/IPv4/TCP frame of a synthetic conversation (checksums are not verified by default).
func frame(client bool, sequence, acknowledgement uint32, flags byte, payload string) []byte {
	out := make([]byte, 54, 54+len(payload))
	out[12], out[13] = 8, 0
	ip := out[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:], uint16(40+len(payload)))
	a, b := []byte{192, 0, 2, 10}, []byte{198, 51, 100, 20}
	tcp := out[34:54]
	if client {
		copy(ip[12:], a)
		copy(ip[16:], b)
		binary.BigEndian.PutUint16(tcp[0:], 51000)
		binary.BigEndian.PutUint16(tcp[2:], 80)
	} else {
		copy(ip[12:], b)
		copy(ip[16:], a)
		binary.BigEndian.PutUint16(tcp[0:], 80)
		binary.BigEndian.PutUint16(tcp[2:], 51000)
	}
	binary.BigEndian.PutUint32(tcp[4:], sequence)
	binary.BigEndian.PutUint32(tcp[8:], acknowledgement)
	tcp[12], tcp[13] = 5<<4, flags
	return append(out, payload...)
}

func stream(frames ...[]byte) []byte {
	out := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}
	for i, f := range frames {
		header := make([]byte, 16)
		binary.LittleEndian.PutUint32(header[0:], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(header[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(header[12:], uint32(len(f)))
		out = append(append(out, header...), f...)
	}
	return out
}

func exchange() []byte {
	return stream(frame(true, 999, 0, 2, ""), frame(false, 8999, 1000, 18, ""),
		frame(true, 1000, 9000, 24, "GET /private HTTP/1.1\r\nHost: example.test\r\n\r\n"), frame(false, 9000, 1047, 24, "HTTP/1.1 204 No Content\r\n\r\n"))
}

// standIn installs a stand-in `tcpdump` on PATH: it writes the stream, prints the given statistics and waits
// for the interrupt the adapter sends (or exits at once with the given status).
func standIn(t *testing.T, capture []byte, statistics string, status int) {
	t.Helper()
	folder := t.TempDir()
	data := filepath.Join(folder, "stream.pcap")
	if err := os.WriteFile(data, capture, 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncat '" + data + "'\n"
	if status != 0 {
		script += "echo 'tcpdump: stand-in failure' >&2\nexit " + string(rune('0'+status)) + "\n"
	} else {
		script += "trap 'printf \"" + statistics + "\" >&2; exit 0' INT\nwhile :; do sleep 0.05; done\n"
	}
	if err := os.WriteFile(filepath.Join(folder, "tcpdump"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", folder+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func events(t *testing.T, output string) []map[string]interface{} {
	t.Helper()
	var out []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("%v in %q", err, line)
		}
		out = append(out, event)
	}
	return out
}

func kinds(list []map[string]interface{}) string {
	var names []string
	for _, e := range list {
		names = append(names, e["type"].(string))
	}
	return strings.Join(names, " ")
}

func TestLiveCaptureProcessLifecycle(t *testing.T) {
	standIn(t, exchange(), "4 packets captured\\n9 packets received by filter\\n0 packets dropped by kernel\\n", 0)
	var stdout, stderr bytes.Buffer
	status := runLive([]string{"--interface", "lo0", "--duration", "0.6", "--stats-interval", "0", "--json", "--capture-id", "0123456789abcdef"},
		strings.NewReader(""), &stdout, &stderr)
	list := events(t, stdout.String())
	if status != 0 || kinds(list) != "started classification classification session summary" {
		t.Fatalf("status %d, events %s, stderr %s\n%s", status, kinds(list), stderr.String(), stdout.String())
	}
	if list[0]["filter"] != "ip and (tcp or udp)" || list[0]["interface"] != "lo0" {
		t.Errorf("started: %v", list[0])
	}
	session, summary := list[3], list[4]
	if session["app"] != "web-browsing" || session["capture_id"] != "0123456789abcdef" || session["generation"] != float64(0) ||
		session["end_reason"] != "Capture stopped before initial message completed" {
		t.Errorf("session: %v", session)
	}
	stats := summary["capture_stats"].(map[string]interface{})
	if summary["capture_quality"] != "no_kernel_drops_reported" || summary["stop_reason"] != "limit_or_interrupt" || stats["captured"] != float64(4) ||
		stats["received_by_filter"] != float64(9) {
		t.Errorf("summary: %v", summary)
	}
	// AGENTS.md: no payload, path or name leaves the adapter (hostnames only with --hostnames).
	for _, forbidden := range []string{"example.test", "/private"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Errorf("output carries %q", forbidden)
		}
	}
}

func TestLiveCaptureLossAndFailure(t *testing.T) {
	standIn(t, exchange()[:len(exchange())-60], "3 packets captured\\n7 packets dropped by kernel\\n", 0)
	var stdout, stderr bytes.Buffer
	status := runLive([]string{"-i", "lo0", "--duration", "0.6", "--stats-interval", "0", "--json"}, strings.NewReader(""), &stdout, &stderr)
	list := events(t, stdout.String())
	if status != 2 || !strings.Contains(kinds(list), "capture_gap") || list[len(list)-1]["capture_quality"] != "loss_reported" {
		t.Fatalf("loss: status %d, events %s\n%s", status, kinds(list), stdout.String())
	}
	for _, e := range list {
		if e["type"] == "capture_gap" && (e["scope"] != "all_observations_this_capture" || len(e["session_ids"].([]interface{})) != 1) {
			t.Errorf("gap: %v", e)
		}
		if e["type"] == "session" {
			t.Errorf("a retracted session was published: %v", e) // loss retracts, it never finalizes
		}
	}

	standIn(t, nil, "", 3)
	stdout.Reset()
	status = runLive([]string{"--interface", "lo0", "--duration", "5", "--json"}, strings.NewReader(""), &stdout, &stderr)
	list = events(t, stdout.String())
	last := list[len(list)-1]
	if status != 1 || kinds(list) != "started capture_gap error summary" || last["stop_reason"] != "error" || last["capture_quality"] != "failed" ||
		list[2]["reason"] != "tcpdump exited with status 3: tcpdump: stand-in failure" {
		t.Fatalf("failure: status %d, events %s\n%s", status, kinds(list), stdout.String())
	}
}

func TestLiveReplayOptionsAndRefusals(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := runLive([]string{"--stdin", "--replay-clock", "--duration", "0", "--stats-interval", "0"}, bytes.NewReader(exchange()), &stdout, &stderr)
	if status != 0 || !strings.Contains(stdout.String(), "IDENTIFIED   http/1.1      web-browsing") || !strings.Contains(stdout.String(), "SUMMARY ") {
		t.Fatalf("text replay: status %d\n%s", status, stdout.String())
	}
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"--stdin", "--interface", "lo0"}, 2},
		{[]string{"--stdin", "--max-connections", "0"}, 2},
		{[]string{"--stdin", "--idle-timeout", "nan"}, 2},
		{[]string{"--stdin", "--continuation", "99999999"}, 2},
		{[]string{"--stdin", "--no-such-option"}, 2},
		{[]string{"--stdin", "--check"}, 0},
		{[]string{"--stdin", "--check", "--content-version", "1999.1.0"}, exitNotPorted},
		{[]string{"--stdin", "--check", "--policy", "/nonexistent/policy.json"}, 1},
		{[]string{"--interface", "-evil", "--json"}, 1},
		{[]string{"--interface", "lo0", "--filter", "", "--json"}, 1},
	} {
		stdout.Reset()
		if got := runLive(c.args, strings.NewReader(""), &stdout, &stderr); got != c.want {
			t.Errorf("%v: status %d, want %d (%s)", c.args, got, c.want, stdout.String())
		}
	}
}
