package livedecrypt

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
)

func op(kind byte, now float64, data []byte) []byte {
	out := []byte{kind}
	out = binary.BigEndian.AppendUint64(out, math.Float64bits(now))
	out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
	return append(out, data...)
}

func frame(client bool, sequence, acknowledgement uint32, flags byte, payload string) []byte {
	out := make([]byte, 54, 54+len(payload))
	out[12], out[13] = 8, 0
	ip := out[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:], uint16(40+len(payload)))
	a, b := []byte{192, 0, 2, 10}, []byte{198, 51, 100, 20}
	tcp := out[34:54]
	source, destination, from, to := a, b, uint16(51000), uint16(80)
	if !client {
		source, destination, from, to = b, a, 80, 51000
	}
	copy(ip[12:], source)
	copy(ip[16:], destination)
	binary.BigEndian.PutUint16(tcp[0:], from)
	binary.BigEndian.PutUint16(tcp[2:], to)
	binary.BigEndian.PutUint32(tcp[4:], sequence)
	binary.BigEndian.PutUint32(tcp[8:], acknowledgement)
	tcp[12], tcp[13] = 5<<4, flags
	return append(out, payload...)
}

func stream(frames ...[]byte) []byte {
	out := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}
	for _, f := range frames {
		header := make([]byte, 16)
		binary.LittleEndian.PutUint32(header[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(header[12:], uint32(len(f)))
		out = append(append(out, header...), f...)
	}
	return out
}

func replay(t *testing.T, script []byte) (int, []map[string]interface{}, string) {
	t.Helper()
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	status := Replay(bytes.NewReader(script), pack, "0123456789abcdef", &out)
	var events []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("%v in %q", err, line)
		}
		events = append(events, event)
	}
	return status, events, out.String()
}

func kinds(events []map[string]interface{}) string {
	var names []string
	for _, e := range events {
		names = append(names, e["type"].(string))
	}
	return strings.Join(names, " ")
}

func TestReplayOfACleartextExchangeReportsNoTLSRows(t *testing.T) {
	capture := stream(frame(true, 999, 0, 2, ""), frame(false, 8999, 1000, 18, ""),
		frame(true, 1000, 9000, 24, "GET /private HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	script := append(append(op('P', 100, capture), op('T', 101, nil)...), op('E', 102, nil)...)
	status, events, text := replay(t, script)
	if status != 0 || kinds(events) != "classification progress decryption classification session decryption summary" {
		t.Fatalf("status %d, events %s\n%s", status, kinds(events), text)
	}
	final := events[5]
	report := final["report"].(map[string]interface{})
	if final["provisional"] != false || final["capture_quality"] != "unverified" || len(report["connections"].([]interface{})) != 0 ||
		report["frames"] != float64(3) || !strings.HasPrefix(report["profile"].(string), "Live TLS 1.2/1.3 POC") {
		t.Errorf("final report: %v", final)
	}
	if strings.Contains(text, "example.test") || strings.Contains(text, "/private") {
		t.Errorf("a name or path left the worker:\n%s", text)
	}
}

func TestFailuresAreAFixedCodeAndSentence(t *testing.T) {
	secret := "CLIENT_RANDOM " + strings.Repeat("ab", 32) + " not-hex-and-must-never-be-echoed\n"
	for _, c := range []struct {
		name   string
		script []byte
		code   string
	}{
		{"malformed key log", op('K', 100, []byte(secret)), "key_log"},
		{"capture budget", op('P', 100, make([]byte, Limit+1)), "budget"},
		{"not a pcap stream", op('P', 100, []byte("definitely not a capture stream, long enough to fail the header check")), "internal"},
	} {
		status, events, text := replay(t, c.script)
		if status != 1 || kinds(events) != "capture_gap decryption error" || events[2]["code"] != c.code || events[2]["reason"] != ErrorCodes[c.code] {
			t.Errorf("%s: status %d, events %s\n%s", c.name, status, kinds(events), text)
		}
		if strings.Contains(text, "never-be-echoed") {
			t.Errorf("%s: key-log input was echoed", c.name)
		}
	}
}

func TestKeyLogReadsAppendOnlyAndRefusesRotationTruncationAndLinks(t *testing.T) {
	folder := t.TempDir()
	path := filepath.Join(folder, "keys.log")
	write := func(text string, flags int) {
		t.Helper()
		f, err := os.OpenFile(path, flags|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString(text); err != nil {
			t.Fatal(err)
		}
	}
	write("first line\nhalf", os.O_TRUNC)
	keys, err := OpenKeyLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	read := func() string {
		t.Helper()
		text, err := keys.Read()
		if err != nil {
			t.Fatal(err)
		}
		return text
	}
	if got := read(); got != "first line\n" { // never a partly written line
		t.Errorf("first read %q", got)
	}
	if got := read(); got != "" {
		t.Errorf("unchanged file read %q", got)
	}
	write(" of the second\nthird\n", os.O_APPEND)
	if got := read(); got != "half of the second\nthird\n" {
		t.Errorf("append read %q", got)
	}
	failure := func(want, code string) {
		t.Helper()
		_, err := keys.Read()
		typed, ok := err.(*KeyLogError)
		if !ok || typed.Message != want || typed.Code != code {
			t.Errorf("got %#v, want %q (%s)", err, want, code)
		}
	}
	write("caf\xc3\xa9\n", os.O_APPEND)
	failure("Key log is not ASCII.", "key_log")
	write(strings.Repeat("x", 5000), os.O_APPEND)
	failure("Key log line is too long.", "key_log")
	write("short\n", os.O_TRUNC)
	failure("Key log was truncated.", "key_log")
	write(strings.Repeat("y", MaxKeyLog+1), os.O_TRUNC)
	failure("Live key log exceeds 256 KiB.", "budget")
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	failure("Key log was rotated or removed.", "key_log")
	write("another file\n", os.O_TRUNC)
	failure("Key log was rotated or removed.", "key_log")

	link := filepath.Join(folder, "link.log")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("symbolic links are not available here")
	}
	if _, err := OpenKeyLog(link); err == nil {
		t.Error("a symbolic link was followed")
	}
	if _, err := OpenKeyLog(folder); err == nil {
		t.Error("a directory was accepted as a key log")
	}
}

func FuzzReplayNeverPanics(f *testing.F) {
	capture := stream(frame(true, 999, 0, 2, ""), frame(false, 8999, 1000, 18, ""), frame(true, 1000, 9000, 24, "\x16\x03\x01\x00\x05hello"))
	f.Add(append(append(op('K', 1, []byte("CLIENT_RANDOM 00 00\n")), op('P', 2, capture)...), op('E', 3, nil)...))
	f.Add(append(op('P', 1, capture[:40]), op('T', 70, nil)...))
	pack, _ := content.Embedded()
	f.Fuzz(func(t *testing.T, script []byte) {
		if len(script) > 1<<16 {
			return
		}
		var out bytes.Buffer
		Replay(bytes.NewReader(script), pack, "0123456789abcdef", &out)
		for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			if line != "" && !json.Valid([]byte(line)) {
				t.Fatalf("invalid JSON line: %s", line)
			}
		}
	})
}
