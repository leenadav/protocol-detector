package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// evaluateCorpusDir is a one-capture corpus: a DNS query labelled dns, and a STUN binding labelled dns
// (one correct, one wrong family).
func evaluateCorpusDir(t *testing.T, independent bool) string {
	t.Helper()
	query := []byte{0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	stun := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	data := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}
	for i, frame := range [][]byte{testframes.UDP("192.0.2.10", 52000, "198.51.100.20", 53, query),
		testframes.UDP("192.0.2.11", 52001, "198.51.100.20", 3478, stun)} {
		header := make([]byte, 16)
		binary.LittleEndian.PutUint32(header[0:], 1700000000)
		binary.LittleEndian.PutUint32(header[4:], uint32(i*1000))
		binary.LittleEndian.PutUint32(header[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(header[12:], uint32(len(frame)))
		data = append(append(data, header...), frame...)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "c.pcap"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	manifest := map[string]interface{}{"corpus": "cli", "source": "synthetic", "labelled_by": "test", "label_basis": "test-bed", "independent": independent,
		"captures": []interface{}{map[string]interface{}{"file": "c.pcap", "sha256": hex.EncodeToString(sum[:]), "flows": []interface{}{
			map[string]interface{}{"transport": "udp", "client": []interface{}{"192.0.2.10", 52000}, "server": []interface{}{"198.51.100.20", 53}, "family": "dns"},
			map[string]interface{}{"transport": "udp", "client": []interface{}{"192.0.2.11", 52001}, "server": []interface{}{"198.51.100.20", 3478}, "family": "dns"},
		}}}}
	text, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), text, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEvaluateCorpusCommand(t *testing.T) {
	dir := evaluateCorpusDir(t, true)
	var out, errOut bytes.Buffer
	if code := runEvaluateCorpus([]string{dir}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "| 2 | 1 | 0 | 1 | 0 | 0 | 0 | 50.0% |") {
		t.Fatalf("totals row missing:\n%s", out.String())
	}
	out.Reset()
	if code := runEvaluateCorpus([]string{dir, "--max-wrong", "0"}, &out, &errOut); code != 1 || !strings.Contains(out.String(), "FAILED thresholds") {
		t.Fatalf("--max-wrong 0 with one wrong identification: exit %d\n%s", code, out.String())
	}
	out.Reset()
	if code := runEvaluateCorpus([]string{dir, "--min-accuracy", "0.9"}, &out, &errOut); code != 1 {
		t.Fatalf("--min-accuracy 0.9 at 50%%: exit %d", code)
	}
	reportMD, reportJSON := filepath.Join(t.TempDir(), "r.md"), filepath.Join(t.TempDir(), "r.json")
	out.Reset()
	if code := runEvaluateCorpus([]string{dir, "--write", reportMD, "--json", reportJSON}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if strings.TrimSpace(out.String()) != "Independent of the engine: yes" {
		t.Fatalf("with report files, stdout is the independence line: %q", out.String())
	}
	var report map[string]interface{}
	data, err := os.ReadFile(reportJSON)
	if err != nil || json.Unmarshal(data, &report) != nil || report["totals"] == nil {
		t.Fatalf("JSON report: %v %s", err, data)
	}
	if md, err := os.ReadFile(reportMD); err != nil || !strings.HasPrefix(string(md), "# Corpus evaluation: cli") {
		t.Fatalf("Markdown report: %v %s", err, md)
	}
}

func TestEvaluateCorpusCommandRefusals(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runEvaluateCorpus(nil, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage: protodetect evaluate-corpus") {
		t.Fatalf("no corpus: exit %d %q", code, errOut.String())
	}
	dir := evaluateCorpusDir(t, false)
	if err := os.WriteFile(filepath.Join(dir, "c.pcap"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := runEvaluateCorpus([]string{dir}, &out, &errOut); code != 2 || !strings.Contains(out.String(), "corpus error: sha256 mismatch") {
		t.Fatalf("tampered capture: exit %d %q", code, out.String())
	}
	self := evaluateCorpusDir(t, false)
	out.Reset()
	if code := runEvaluateCorpus([]string{self}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "this is a self-check") {
		t.Fatalf("not independent: exit %d\n%s", code, out.String())
	}
}
