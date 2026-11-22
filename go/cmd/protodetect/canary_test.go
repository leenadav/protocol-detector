package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Contract C17: no payload, credential, name or key material leaves the Go binary as output. Every command is
// run in process on synthetic traffic that carries canary values in every place a leak could come from: a
// URL path, a Host header, credentials, a cookie, a body, a TLS server name, decrypted plaintext and the
// key-log secrets themselves. Names are published only on request (--hostnames): that is the one opt-in.

const (
	canaryPath   = "/canary-path-5d1c"
	canaryHost   = "canary-host-5d1c.example"
	canaryUser   = "Y2FuYXJ5LXVzZXI6cGFzcw==" // base64 credentials
	canaryCookie = "session=canary-cookie-5d1c"
	canaryBody   = "canary-body-5d1c"
	canarySNI    = "canary-sni-5d1c.example"
	canaryInner  = "/canary-inner-5d1c"
)

var canaryRequest = "POST " + canaryPath + " HTTP/1.1\r\nHost: " + canaryHost + "\r\nAuthorization: Basic " + canaryUser + "\r\nCookie: " +
	canaryCookie + "\r\nContent-Length: 16\r\n\r\n" + canaryBody

// canaries are the values no output may carry; names (canaryHost, canarySNI) are added where SR-9 applies.
func canaries(secrets []string, names bool) []string {
	out := []string{canaryPath, canaryUser, canaryCookie, canaryBody, canaryInner, "not-hex-canary"}
	if names {
		out = append(out, canaryHost, canarySNI)
	}
	for _, s := range secrets {
		out = append(out, s, strings.ToUpper(s))
	}
	return out
}

func tcpFrame(client bool, clientPort, port uint16, sequence, acknowledgement uint32, flags byte, payload []byte) []byte {
	out := make([]byte, 54, 54+len(payload))
	out[12], out[13] = 8, 0
	ip := out[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:], uint16(40+len(payload)))
	a, b := []byte{192, 0, 2, 10}, []byte{198, 51, 100, 20}
	from, to := clientPort, port
	if !client {
		a, b, from, to = b, a, to, from
	}
	copy(ip[12:], a)
	copy(ip[16:], b)
	tcp := out[34:54]
	binary.BigEndian.PutUint16(tcp[0:], from)
	binary.BigEndian.PutUint16(tcp[2:], to)
	binary.BigEndian.PutUint32(tcp[4:], sequence)
	binary.BigEndian.PutUint32(tcp[8:], acknowledgement)
	tcp[12], tcp[13] = 5<<4, flags
	return append(out, payload...)
}

// conversationFrames is a full TCP conversation carrying the two streams.
func conversationFrames(clientPort, port uint16, client, server []byte) [][]byte {
	c := uint32(len(client))
	s := uint32(len(server))
	return [][]byte{tcpFrame(true, clientPort, port, 999, 0, 2, nil), tcpFrame(false, clientPort, port, 8999, 1000, 18, nil),
		tcpFrame(true, clientPort, port, 1000, 9000, 24, client), tcpFrame(false, clientPort, port, 9000, 1000+c, 24, server),
		tcpFrame(true, clientPort, port, 1000+c, 9000+s, 17, nil), tcpFrame(false, clientPort, port, 9000+s, 1001+c, 17, nil)}
}

func pcapOf(frames ...[]byte) []byte {
	out := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}
	for i, f := range frames {
		header := make([]byte, 16)
		binary.LittleEndian.PutUint32(header[0:], 1700000000)
		binary.LittleEndian.PutUint32(header[4:], uint32(i))
		binary.LittleEndian.PutUint32(header[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(header[12:], uint32(len(f)))
		out = append(append(out, header...), f...)
	}
	return out
}

func expandLabel(secret []byte, name string, length int) []byte {
	full := "tls13 " + name
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(append(append(info, byte(len(full))), full...), 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

func seal(secret []byte, kind byte, content []byte) []byte {
	block, _ := aes.NewCipher(expandLabel(secret, "key", 16))
	aead, _ := cipher.NewGCM(block)
	inner := append(append([]byte{}, content...), kind)
	header := []byte{23, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(header[3:], uint16(len(inner)+16))
	return append(header, aead.Seal(nil, expandLabel(secret, "iv", 12), inner, header)...)
}

func hs(kind byte, body []byte) []byte {
	return append([]byte{kind, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func rec(kind byte, body []byte) []byte {
	return append([]byte{kind, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
}

// tlsExchange is a TLS 1.3 exchange whose ClientHello names canarySNI and whose plaintext is an HTTP request for
// canaryInner, with the key log that decrypts it and the secrets that must never be printed.
func tlsExchange() (client, server []byte, keylog string, secrets []string) {
	random := bytes.Repeat([]byte{0x5d}, 32)
	sni := []byte(canarySNI)
	ext := binary.BigEndian.AppendUint16(nil, 0)
	list := append(binary.BigEndian.AppendUint16([]byte{0}, uint16(len(sni))), sni...)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(list)+2))
	ext = append(binary.BigEndian.AppendUint16(ext, uint16(len(list))), list...)
	ext = append(ext, 0, 43, 0, 3, 2, 3, 4)
	hello := append(append([]byte{3, 3}, random...), 0, 0, 2, 0x13, 0x01, 1, 0)
	hello = append(binary.BigEndian.AppendUint16(hello, uint16(len(ext))), ext...)
	serverHello := append(append([]byte{3, 3}, bytes.Repeat([]byte{0x11}, 32)...), 0, 0x13, 0x01, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	keys := map[string][]byte{}
	names := []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"}
	for i, name := range names {
		keys[name] = bytes.Repeat([]byte{0xa0 + byte(i)}, 32)
		keylog += fmt.Sprintf("%s %s %s\n", name, hex.EncodeToString(random), hex.EncodeToString(keys[name]))
		secrets = append(secrets, hex.EncodeToString(keys[name]))
	}
	finished := hs(20, bytes.Repeat([]byte{9}, 32))
	server = append(rec(22, hs(2, serverHello)), rec(20, []byte{1})...)
	server = append(server, seal(keys[names[1]], 22, append(append(hs(8, []byte{0, 0}), hs(11, []byte("cert"))...), finished...))...)
	server = append(server, seal(keys[names[3]], 23, []byte("HTTP/1.1 200 OK\r\nSet-Cookie: "+canaryCookie+"\r\nContent-Length: 0\r\n\r\n"))...)
	client = append(rec(22, hs(1, hello)), seal(keys[names[0]], 22, finished)...)
	client = append(client, seal(keys[names[2]], 23, []byte("GET "+canaryInner+" HTTP/1.1\r\nHost: "+canaryHost+"\r\n\r\n"))...)
	return client, server, keylog, secrets
}

func assertNoCanary(t *testing.T, what, output string, values []string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(output, value) {
			t.Errorf("%s: output carries %q", what, value)
		}
	}
}

func TestNoPayloadCredentialNameOrKeyMaterialInAnyOutput(t *testing.T) {
	client, server, keylog, secrets := tlsExchange()
	strict, unnamed := canaries(secrets, true), canaries(secrets, false)
	frames := append(conversationFrames(51000, 80, []byte(canaryRequest), []byte("HTTP/1.1 204 No Content\r\n\r\n")),
		conversationFrames(51001, 443, client, server)...)
	capture := pcapOf(frames...)
	folder := t.TempDir()
	path := filepath.Join(folder, "capture.pcap")
	if err := os.WriteFile(path, capture, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(name string, f func(stdout, stderr *bytes.Buffer) int) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		status := f(&stdout, &stderr)
		if status != 0 {
			t.Fatalf("%s: status %d: %s", name, status, stderr.String())
		}
		assertNoCanary(t, name+" (stderr)", stderr.String(), strict)
		return stdout.String()
	}
	options := []string{"--sessions", "--fingerprints", "--heuristics", "--certificates", "--continuation", "4096"}
	for _, form := range [][]string{{"--json"}, nil} {
		output := run("analyze", func(o, e *bytes.Buffer) int {
			return runAnalyze(append(append([]string{path}, options...), form...), o, e)
		})
		// Frame rows carry the direction's observation, asserted name included (OUTPUT.md offline-row); nothing else.
		assertNoCanary(t, "analyze", output, unnamed)
		if !strings.Contains(output, "web-browsing") {
			t.Fatalf("analyze classified nothing:\n%s", output)
		}
	}
	output := run("present", func(o, e *bytes.Buffer) int { return runPresent(nil, bytes.NewReader(capture), o, e) })
	assertNoCanary(t, "present", output, unnamed)
	for _, form := range [][]string{{"--json"}, nil} {
		args := append([]string{"--stdin", "--replay-clock", "--duration", "0", "--stats-interval", "0", "--all-events", "--fingerprints",
			"--certificates"}, form...)
		output := run("live", func(o, e *bytes.Buffer) int { return runLive(args, bytes.NewReader(capture), o, e) })
		assertNoCanary(t, "live", output, strict) // SR-9: no names in live output
	}
	request := binary.BigEndian.AppendUint64(nil, uint64(len(capture)))
	request = append(append(request, capture...), keylog...)
	output = run("decrypt-capture", func(o, e *bytes.Buffer) int { return runDecrypt(nil, bytes.NewReader(request), o, e) })
	assertNoCanary(t, "decrypt-capture", output, strict)
	if !strings.Contains(output, `"decrypted": 1`) {
		t.Fatalf("decrypt-capture decrypted nothing:\n%.600s", output)
	}
	op := func(kind byte, now float64, data []byte) []byte {
		out := []byte{kind}
		out = binary.BigEndian.AppendUint64(out, math.Float64bits(now))
		out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
		return append(out, data...)
	}
	script := append(append(append(op('K', 1, []byte(keylog)), op('P', 2, capture)...), op('T', 3, nil)...), op('E', 4, nil)...)
	output = run("live-decrypt", func(o, e *bytes.Buffer) int {
		return runLiveDecrypt([]string{"--replay"}, bytes.NewReader(script), o, e)
	})
	assertNoCanary(t, "live-decrypt", output, strict)
	if !strings.Contains(output, `"status": "decrypted"`) {
		t.Fatalf("live-decrypt decrypted nothing:\n%.600s", output)
	}
	// A malformed key-log line that carries a secret-looking value is refused without echoing it.
	bad := append(binary.BigEndian.AppendUint64(nil, uint64(len(capture))), capture...)
	bad = append(bad, "CLIENT_RANDOM "+strings.Repeat("5d", 32)+" not-hex-canary-5d1c\n"...)
	var stdout, stderr bytes.Buffer
	if status := runDecrypt(nil, bytes.NewReader(bad), &stdout, &stderr); status != exitRefused {
		t.Fatalf("malformed key log: status %d", status)
	}
	assertNoCanary(t, "decrypt-capture refusal", stdout.String()+stderr.String(), strict)

	// Session records (SR-9): no name without --hostnames, the asserted names with it, and nothing else either way.
	output = run("analyze sessions", func(o, e *bytes.Buffer) int {
		return runAnalyze([]string{path, "--json", "--sessions", "--events-only"}, o, e)
	})
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, `{"type": "session"`) {
			assertNoCanary(t, "session record", line, strict)
		}
	}
	output = run("analyze --hostnames", func(o, e *bytes.Buffer) int {
		return runAnalyze([]string{path, "--json", "--sessions", "--events-only", "--hostnames"}, o, e)
	})
	if !strings.Contains(output, `"hostname": "`+canaryHost+`"`) {
		t.Errorf("--hostnames did not publish the asserted name in a session record")
	}
	assertNoCanary(t, "analyze --hostnames", output, unnamed)
}
