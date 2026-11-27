package live

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/capture"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// SR-12: the operator's interface name and BPF filter become separate argv elements of tcpdump, never a shell
// command line: hostile interface names are refused, the filter is one argument after "--", and the executable is
// tcpdump itself. Ported from test_live.py test_command_arguments_are_not_shell_code.
func TestCaptureCommandArgumentsAreNotShellCode(t *testing.T) {
	dir := t.TempDir()
	stand := filepath.Join(dir, "tcpdump")
	if err := os.WriteFile(stand, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	for _, iface := range []string{"", "-w", "--help", "eth0;id", "eth0 lo", "$(id)", "`id`", "eth0|id", "eth0&&id", "a\nb", "é0", strings.Repeat("a", 129)} {
		if argv, err := CaptureCommand(iface, "tcp"); err == nil {
			t.Fatalf("interface %q accepted: %q", iface, argv)
		}
	}
	for _, bpf := range []string{"", "tcp\x00", strings.Repeat("a", 4097)} {
		if argv, err := CaptureCommand("eth0", bpf); err == nil {
			t.Fatalf("filter %q accepted: %q", bpf, argv)
		}
	}
	filter := "port 80; touch /tmp/pwned $(id) `id` | sh"
	argv, err := CaptureCommand("en0.1:2-x_y", filter)
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != stand {
		t.Fatalf("argv[0] %q is not the tcpdump executable", argv[0])
	}
	for _, shell := range []string{"sh", "bash", "-c"} {
		for _, a := range argv {
			if a == shell || filepath.Base(a) == shell {
				t.Fatalf("a shell appears in %q", argv)
			}
		}
	}
	index := func(s string) int {
		for i, a := range argv {
			if a == s {
				return i
			}
		}
		return -1
	}
	if i := index("-i"); i < 0 || argv[i+1] != "en0.1:2-x_y" {
		t.Fatalf("the interface is not its own argument: %q", argv)
	}
	if i := index("--"); i != len(argv)-2 || argv[i+1] != "ip and ("+filter+")" {
		t.Fatalf("the filter is not one argument after --: %q", argv)
	}
}

func hasKind(events []Event, kind string) bool {
	for _, e := range events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

// SR-7: a truncated capture record (captured length below the original length) cannot be attributed to one flow:
// every active observation is retracted with a capture_gap event, the tracking state is discarded, and a later
// data segment of the same connection is counted as a TCP segment without a start, never resumed. Ported from
// test_live.py test_truncation_discards_active_state_and_reports_gap.
func TestTruncatedRecordRetractsActiveStateAndReportsAGap(t *testing.T) {
	m, events := monitor(t)
	frames := closed(1000)
	feed(t, m, frames[:3], 10, 1)
	if !hasKind(*events, "classification") || len(m.an.Tracker.TrackedTCP()) != 1 {
		t.Fatalf("setup: events %v, tracked %d", *events, len(m.an.Tracker.TrackedTCP()))
	}
	data := frames[3]
	if err := m.Accept(capture.Record{Timestamp: 14, Data: data, OriginalLength: len(data) + 1, Linktype: 1}, 14); err != nil {
		t.Fatal(err)
	}
	if len(m.an.Tracker.TrackedTCP()) != 0 {
		t.Fatalf("a truncated record left %d connections tracked", len(m.an.Tracker.TrackedTCP()))
	}
	if !hasKind(*events, "capture_gap") {
		t.Fatalf("no capture_gap event among %v", *events)
	}
	if m.Truncated() != 1 {
		t.Fatalf("truncated count %d", m.Truncated())
	}
	late := testframes.TCP("192.0.2.10", 52000, "198.51.100.20", 80, 1001, 100001, 0x18, []byte("more"))
	if err := m.Accept(capture.Record{Timestamp: 15, Data: late, OriginalLength: len(late), Linktype: 1}, 15); err != nil {
		t.Fatal(err)
	}
	if got := m.counts.values["tcp_without_start"]; got != 1 {
		t.Fatalf("tcp_without_start %d: the retracted connection was resumed", got)
	}
	if err := m.End("stop"); err != nil {
		t.Fatal(err)
	}
	if gens, _ := generations(*events, "tcp"); len(gens) != 0 {
		t.Fatalf("a retracted connection was finalized as a session: generations %v", gens)
	}
}

// SR-7: a capture gap (reported loss) retracts the active observations; ending the capture afterwards never
// fabricates a clean end (no session record, no incomplete classification) for what the gap retracted. Ported
// from test_lifecycle.py test_capture_gap_retracts_instead_of_fabricating_eof.
func TestCaptureGapRetractsInsteadOfFabricatingAnEnd(t *testing.T) {
	m, events := monitor(t)
	frames := [][]byte{
		testframes.TCP("192.0.2.10", 52000, "198.51.100.20", 80, 999, 0, 0x02, nil),
		testframes.TCP("198.51.100.20", 80, "192.0.2.10", 52000, 8999, 1000, 0x12, nil),
		testframes.TCP("192.0.2.10", 52000, "198.51.100.20", 80, 1000, 9000, 0x18, []byte("GET ")),
	}
	feed(t, m, frames, 10, 1)
	before := len(*events)
	if err := m.InvalidateAll("Synthetic capture gap", "active_connections"); err != nil {
		t.Fatal(err)
	}
	if err := m.End("stop"); err != nil {
		t.Fatal(err)
	}
	if !hasKind((*events)[before:], "capture_gap") {
		t.Fatalf("no capture_gap event among %v", (*events)[before:])
	}
	for _, e := range (*events)[before:] {
		if e.Kind == "session" || e.Kind == "classification" || e.Fields["status"] == "incomplete" {
			t.Fatalf("the gap was turned into an end: %v", e)
		}
	}
}
