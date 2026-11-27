package live

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// SR-30: the live classification event of a Telnet negotiation on port 2323 carries its flow risks
// (cleartext-credential-protocol, nonstandard-port, obsolete-protocol), every session event carries a risks
// field, and no event carries payload.
func TestSecurityLiveEventsCarryRisks(t *testing.T) {
	m, events := monitor(t)
	telnet := []byte{0xff, 0xfd, 0x18, 0xff, 0xfb, 0x01}
	feed(t, m, [][]byte{
		testframes.TCP("192.0.2.10", 52000, "198.51.100.20", 2323, 999, 0, 0x02, nil),
		testframes.TCP("198.51.100.20", 2323, "192.0.2.10", 52000, 8999, 1000, 0x12, nil),
		testframes.TCP("192.0.2.10", 52000, "198.51.100.20", 2323, 1000, 9000, 0x18, telnet),
	}, 1, 0.01)
	want := []string{"cleartext-credential-protocol", "nonstandard-port", "obsolete-protocol"}
	found := false
	for _, e := range *events {
		if e.Kind == "classification" {
			found = true
			if risks, _ := e.Fields["risks"].([]string); !reflect.DeepEqual(risks, want) {
				t.Fatalf("classification risks %v, want %v", e.Fields["risks"], want)
			}
		}
		if _, ok := e.Fields["risks"]; e.Kind == "session" && !ok {
			t.Fatalf("a session event without risks: %v", e.Fields)
		}
	}
	if !found {
		t.Fatalf("no classification event: %v", *events)
	}
	text, _ := json.Marshal(*events)
	if strings.Contains(string(text), "payload") {
		t.Fatalf("events carry payload: %s", text)
	}
}

var securityPrivilege = regexp.MustCompile(`(?i)\bsudo\b|\bsetuid\b|\bseteuid\b|\bsetgid\b|\bsetegid\b|\bsetre[ug]id\b|\bsetres[ug]id\b|\bsetgroups\b|setcap|pkexec|osascript|\bdoas\b|Credential\s*:|AmbientCaps|CAP_NET_RAW`)

// SR-60: the product never changes privileges: no Go source of the module (vendored dependencies and tests
// aside) and no dashboard script calls setuid/setgid, sets process credentials or capabilities, or runs sudo,
// pkexec, doas, setcap or osascript.
func TestSecurityNoPrivilegeChangesAnywhereInTheProduct(t *testing.T) {
	var offenders []string
	scanned := 0
	scan := func(path string) {
		text, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for number, line := range strings.Split(string(text), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if securityPrivilege.MatchString(line) {
				offenders = append(offenders, fmt.Sprintf("%s:%d: %s", path, number+1, trimmed))
			}
		}
	}
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "vendor" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			scan(path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	scripts, _ := filepath.Glob("../../../presentation/web/*.js")
	for _, path := range scripts {
		scan(path)
	}
	if scanned < 100 {
		t.Fatalf("only %d files scanned; the layout moved", scanned)
	}
	if len(offenders) > 0 {
		t.Fatalf("privilege changes in the product:\n%s", strings.Join(offenders, "\n"))
	}
}

// SR-60: a missing tcpdump is reported, never worked around, and the capture command runs tcpdump itself with no
// privilege wrapper.
func TestSecurityCaptureFailureReportsWithoutEscalating(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if command, err := CaptureCommand("lo", "tcp"); err == nil || !strings.Contains(err.Error(), "tcpdump not found") {
		t.Fatalf("no tcpdump on PATH: %v %v", command, err)
	}
	dir := t.TempDir()
	tcpdump := filepath.Join(dir, "tcpdump")
	if err := os.WriteFile(tcpdump, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	command, err := CaptureCommand("lo", "tcp")
	if err != nil || len(command) == 0 || command[0] != tcpdump {
		t.Fatalf("capture command %v %v", command, err)
	}
	for _, part := range command {
		if securityPrivilege.MatchString(part) {
			t.Fatalf("a privilege wrapper in the capture command: %v", command)
		}
	}
}
