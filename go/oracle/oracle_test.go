package oracle

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// Pinned tools (README.md): the test refuses other versions, so a dissector or client change is a reviewed bump
// here, never a silent drift. Each is run as an external process only.
var pinned = map[string]struct{ flag, want string }{
	"tshark":  {"--version", "TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3)"},
	"openssl": {"version", "OpenSSL 3.0.13 30 Jan 2024"},
	"curl":    {"--version", "curl 8.5.0 "},
}

func tool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s is required (README.md, pinned tools): %v", name, err)
	}
	out, err := exec.Command(path, pinned[name].flag).CombinedOutput() // pinned tool
	if err != nil || !strings.Contains(string(out), pinned[name].want) {
		t.Fatalf("%s is not the pinned version %q: %s", name, pinned[name].want, firstLine(out))
	}
	return path
}

func firstLine(b []byte) string { return strings.SplitN(string(b), "\n", 2)[0] }

type scenario struct {
	name     string
	proto    string // "tcp" or "udp"
	dissect  string // tshark dissector for the relay port: "tls", "http" or "quic"
	shape    Shape
	target   string                                        // the server the relay forwards to
	client   func(ctx context.Context, relay string) error // the real client, connecting to the relay
	expect   Fields                                        // what the client was told to send (the oracle must see it)
	compared []string
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...) // pinned tools, arguments built by the test
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.CombinedOutput()
	if err != nil && ctx.Err() == nil && !strings.Contains(name, "openssl") {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, out)
	}
	return nil // s_client exits non-zero when stdin closes before the server's reply; its ClientHello is sent
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if c, err := net.Dial("tcp4", addr); err == nil {
			c.Close()
			return
		}
	}
	t.Fatalf("nothing listens on %s", addr)
}

// opensslServer starts `openssl s_server -www` with a fresh self-signed certificate in dir.
func opensslServer(t *testing.T, openssl, dir string) string {
	t.Helper()
	cert, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	gen := exec.Command(openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
		"-subj", "/CN=server.example.test", "-days", "1", "-keyout", keyFile, "-out", cert)
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %v: %s", err, out)
	}
	addr := "127.0.0.1:" + strconv.Itoa(freePort(t))
	// The server selects http/1.1 only: -www answers HTTP/1, and only the client's offer is compared.
	srv := exec.Command(openssl, "s_server", "-quiet", "-accept", addr, "-cert", cert, "-key", keyFile, "-www",
		"-alpn", "http/1.1")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	waitListening(t, addr)
	return addr
}

func goTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "quic.example.test"},
		DNSNames: []string{"quic.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h3"}}
}

// quicServer accepts QUIC v1 and v2 connections on loopback and holds each until the client closes it.
func quicServer(t *testing.T) string {
	t.Helper()
	ln, err := quic.ListenAddr("127.0.0.1:0", goTLSConfig(t), &quic.Config{Versions: []quic.Version{quic.Version1, quic.Version2}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { <-conn.Context().Done() }()
		}
	}()
	return ln.Addr().String()
}

func quicClient(name string, version quic.Version, alpn ...string) func(context.Context, string) error {
	return func(ctx context.Context, relay string) error {
		conf := &tls.Config{ServerName: name, NextProtos: alpn, InsecureSkipVerify: true} // test peer
		conn, err := quic.DialAddr(ctx, relay, conf, &quic.Config{Versions: []quic.Version{version}})
		if err != nil {
			return err
		}
		return conn.CloseWithError(0, "")
	}
}

type allowList map[string]string // "scenario/field" -> reason

func loadAllow(t *testing.T) allowList {
	t.Helper()
	data, err := os.ReadFile("allow.json")
	if err != nil {
		t.Fatal(err)
	}
	var a allowList
	if err := json.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	for k, reason := range a {
		if strings.TrimSpace(reason) == "" {
			t.Fatalf("allow.json: %s has no reason", k)
		}
	}
	return a
}

// TestEngineMatchesTshark runs every scenario's real client and server through a recording relay, then compares
// the engine's fields on each flow with tshark's. A mismatch fails unless allow.json lists it with a reason; a
// listed entry that no longer mismatches fails too, so the list cannot go stale.
func TestEngineMatchesTshark(t *testing.T) {
	tshark, openssl, curl := tool(t, "tshark"), tool(t, "openssl"), tool(t, "curl")
	dir := t.TempDir() // the pcaps, certificate and key live here only and are removed with it
	tlsServer := opensslServer(t, openssl, dir)
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) }))
	t.Cleanup(httpServer.Close)
	plain := strings.TrimPrefix(httpServer.URL, "http://")
	quicAddr := quicServer(t)
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + ".example.test"

	sclient := func(args ...string) func(context.Context, string) error {
		return func(ctx context.Context, relay string) error {
			return run(ctx, openssl, append([]string{"s_client", "-connect", relay}, args...)...)
		}
	}
	curlTo := func(scheme, host string, args ...string) func(context.Context, string) error {
		return func(ctx context.Context, relay string) error {
			port := relay[strings.LastIndexByte(relay, ':')+1:]
			url := fmt.Sprintf("%s://%s:%s/", scheme, host, port)
			// --noproxy: never a configured proxy; the request stays on 127.0.0.1 (no external network).
			base := []string{"-sk", "--noproxy", "*", "--max-time", "10", "-o", os.DevNull, "--resolve", host + ":" + port + ":127.0.0.1"}
			return run(ctx, curl, append(append(base, args...), url)...)
		}
	}
	tlsFields := []string{"sni", "alpn", "tls_version"}
	scenarios := []scenario{
		{name: "s_client tls1.3 sni alpn", proto: "tcp", dissect: "tls", target: tlsServer,
			client: sclient("-servername", "a.example.test", "-alpn", "h2,http/1.1", "-tls1_3"),
			expect: Fields{SNI: "a.example.test", ALPN: "h2,http/1.1", TLSVersion: "1.3"}, compared: tlsFields},
		{name: "s_client tls1.2 in 7-byte segments", proto: "tcp", dissect: "tls", target: tlsServer, shape: Shape{Segment: 7},
			client: sclient("-servername", "b.example.test", "-alpn", "http/1.1", "-tls1_2"),
			expect: Fields{SNI: "b.example.test", ALPN: "http/1.1", TLSVersion: "1.2"}, compared: tlsFields},
		{name: "s_client no sni out of order", proto: "tcp", dissect: "tls", target: tlsServer, shape: Shape{Segment: 50, Swap: true},
			client: sclient("-noservername"), expect: Fields{TLSVersion: "1.3"}, compared: tlsFields},
		{name: "s_client 253-byte sni", proto: "tcp", dissect: "tls", target: tlsServer,
			client: sclient("-servername", long), expect: Fields{SNI: long, TLSVersion: "1.3"}, compared: tlsFields},
		{name: "curl https h2", proto: "tcp", dissect: "tls", target: tlsServer,
			client: curlTo("https", "www.example.test"), expect: Fields{SNI: "www.example.test", ALPN: "h2,http/1.1", TLSVersion: "1.3"},
			compared: tlsFields},
		{name: "curl https http1.1 tls1.2", proto: "tcp", dissect: "tls", target: tlsServer, shape: Shape{Segment: 100},
			client: curlTo("https", "old.example.test", "--http1.1", "--tlsv1.2", "--tls-max", "1.2"),
			expect: Fields{SNI: "old.example.test", ALPN: "http/1.1", TLSVersion: "1.2"}, compared: tlsFields},
		{name: "curl http host", proto: "tcp", dissect: "http", target: plain,
			client: curlTo("http", "plain.example.test"), expect: Fields{HTTPHost: "plain.example.test"}, compared: []string{"http_host"}},
		{name: "curl http/1.0 host header in 5-byte segments", proto: "tcp", dissect: "http", target: plain, shape: Shape{Segment: 5},
			client: curlTo("http", "plain.example.test", "-0", "-H", "Host: Mixed.Example.TEST"),
			expect: Fields{HTTPHost: "mixed.example.test"}, compared: []string{"http_host"}},
		{name: "quic-go v1", proto: "udp", dissect: "quic", target: quicAddr,
			client: quicClient("quic.example.test", quic.Version1, "h3"),
			expect: Fields{SNI: "quic.example.test", ALPN: "h3", QUICVersion: "1"}, compared: []string{"sni", "alpn", "quic_version"}},
		{name: "quic-go v2", proto: "udp", dissect: "quic", target: quicAddr,
			client: quicClient("v2.example.test", quic.Version2, "h3", "hq-interop"),
			expect: Fields{SNI: "v2.example.test", ALPN: "h3,hq-interop", QUICVersion: "2"}, compared: []string{"sni", "alpn", "quic_version"}},
	}

	allow := loadAllow(t)
	used := map[string]bool{}
	var report []map[string]string
	for i, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			path := filepath.Join(dir, fmt.Sprintf("%02d.pcap", i))
			rec, err := NewRecorder(path)
			if err != nil {
				t.Fatal(err)
			}
			var relay string
			var stop func()
			if s.proto == "tcp" {
				r, err := StartTCPRelay(rec, s.target, s.shape)
				if err != nil {
					t.Fatal(err)
				}
				relay, stop = r.Addr().String(), r.Close
			} else {
				r, err := StartUDPRelay(rec, s.target)
				if err != nil {
					t.Fatal(err)
				}
				relay, stop = r.Addr().String(), r.Close
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err = s.client(ctx, relay)
			cancel()
			if s.proto == "udp" {
				time.Sleep(200 * time.Millisecond) // let the last datagrams pass the relay
			}
			stop()
			if cerr := rec.Close(); cerr != nil {
				t.Fatal(cerr)
			}
			if err != nil {
				t.Fatal(err)
			}
			flows, err := ReadFlows(path)
			if err != nil {
				t.Fatal(err)
			}
			clients := map[string]bool{}
			for _, f := range flows {
				clients[f.Key] = true
			}
			port := relay[strings.LastIndexByte(relay, ':')+1:]
			oracle, err := Tshark(tshark, path, map[string]string{s.proto + ".port==" + port: s.dissect}, clients)
			if err != nil {
				t.Fatal(err)
			}
			if len(flows) != 1 {
				t.Fatalf("want one client flow, gopacket found %d", len(flows))
			}
			flow := flows[0]
			got, status, err := Engine(flow)
			if err != nil {
				t.Fatal(err)
			}
			want, ok := oracle[flow.Key]
			if !ok {
				t.Fatalf("tshark dissected no client packet of %s", flow.Key)
			}
			if status != contracts.Identified {
				t.Errorf("engine status %s on %s", status, flow.Key)
			}
			for _, field := range s.compared {
				id := s.name + "/" + field
				if want.Get(field) != s.expect.Get(field) {
					t.Errorf("%s: the oracle saw %q, the client was told to send %q (the comparison would be blind)",
						field, want.Get(field), s.expect.Get(field))
				}
				match := got.Get(field) == want.Get(field)
				report = append(report, map[string]string{"case": id, "engine": got.Get(field), "tshark": want.Get(field),
					"match": strconv.FormatBool(match)})
				reason, listed := allow[id]
				used[id] = listed
				switch {
				case !match && listed:
					t.Logf("%s: allowed mismatch (%s): engine %q, tshark %q", field, reason, got.Get(field), want.Get(field))
				case !match:
					t.Errorf("%s: engine %q, tshark %q", field, got.Get(field), want.Get(field))
				case listed:
					t.Errorf("%s: allow.json lists %q but engine and tshark now agree (%q); remove the entry", field, id, want.Get(field))
				}
			}
		})
	}
	var unknown []string
	for id := range allow {
		if _, ok := used[id]; !ok {
			unknown = append(unknown, id)
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		t.Errorf("allow.json lists cases no scenario compares: %v", unknown)
	}
	if out := os.Getenv("ORACLE_REPORT"); out != "" {
		data, _ := json.MarshalIndent(report, "", " ")
		if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil { // a report
			t.Fatal(err)
		}
	}
	matched := 0
	for _, r := range report {
		if r["match"] == "true" {
			matched++
		}
	}
	t.Logf("oracle: %d scenarios, %d field comparisons, %d matched", len(scenarios), len(report), matched)
}
