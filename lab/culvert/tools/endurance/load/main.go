// Command endurance-load is the origin and the traffic driver of the Culvert lab endurance run (PRO-540,
// lab/culvert/ENDURANCE.md, working plan phase L6). Standard library only, lab tooling, never shipped.
//
//	endurance-load origin -addr 203.0.113.10 -certs <dir>
//	endurance-load drive  -proxy 127.0.0.1:18480 -duration 1800s -ca <dir>/ca.pem -inspect-ca <file>
//	                      -corpus <dir>[,<dir>...] -out <samples.jsonl>
//	endurance-load self-test
//
// Origin, on a loopback-bound RFC 5737 address (nothing leaves the host):
//
//	:443  HTTPS (HTTP/1.1), a leaf for origin.lab.test and the child-app hosts, signed by a throw-away lab CA
//	:80   HTTP/1.1
//	:2222 SSH-like: server-first banner, then reads the client banner and closes
//	:9001 never reads: a tunnel writing to it blocks the proxy's relay in Write (one direction blocked)
//	:9002 quiet: never writes, reads until the client closes (a silent peer held past the window)
//	:9003 discard: reads everything until EOF (adverse inputs)
//
// The driver opens one CONNECT tunnel per flow through the proxy at fixed rates per kind (see Kinds) and writes
// one JSON line per interval with the per-kind outcome counters. A flow's outcome is judged by the driver from the
// traffic only (status, body, banner, early close), never from the detector's output.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Hosts the origin's leaf covers: the bypass origin and the child-app mix (inspected by the lab rule).
var Hosts = []string{"origin.lab.test", "gmail.googleapis.com", "www.googleapis.com"}

var body = []byte("lab origin says hello: endurance\n")

const (
	sshBanner    = "SSH-2.0-LabOrigin_1.0\r\n"
	sshClient    = "SSH-2.0-LabClient_1.0\r\n"
	quietHold    = 15 * time.Second // past the 10 s observation window
	blockedHold  = 20 * time.Second
	flowDeadline = 10 * time.Second
)

// Kind is one traffic class of the mix.
type Kind struct {
	Name string
	Rate float64 // new flows per second
	Max  int     // concurrent flows of this kind; a tick beyond it is counted as "skipped", never queued
}

// Kinds is the mix of the manifest (ENDURANCE.md, section 1). About 128 new tunnels/s in total.
var Kinds = []Kind{
	{"tls", 60, 600},
	{"http1", 25, 300},
	{"ssh", 20, 300},
	{"inspect", 10, 200},
	{"adverse", 10, 300},
	{"quiet", 2, 100},
	{"blocked", 0.5, 40},
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) < 2 {
		log.Fatal("usage: endurance-load origin|drive|self-test ...")
	}
	switch os.Args[1] {
	case "origin":
		origin(os.Args[2:])
	case "drive":
		drive(os.Args[2:])
	case "self-test":
		if err := selfTest(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("endurance-load self-test: ok")
	default:
		log.Fatalf("unknown mode %q", os.Args[1])
	}
}

// ---------- origin ----------

func origin(args []string) {
	fs := flag.NewFlagSet("origin", flag.ExitOnError)
	addr := fs.String("addr", "203.0.113.10", "loopback-bound IPv4 address")
	dir := fs.String("certs", "", "directory for the lab CA and leaf (created if missing; ca.pem is the trust anchor)")
	_ = fs.Parse(args)
	if *dir == "" {
		log.Fatal("-certs is required")
	}
	leaf, err := labCerts(*dir)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	})
	// ReadHeaderTimeout also bounds the TLS handshake (lane brief, pitfalls): longer than the window.
	mk := func() *http.Server {
		return &http.Server{Handler: mux, ReadHeaderTimeout: 60 * time.Second, IdleTimeout: 5 * time.Second}
	}
	tlsSrv := mk()
	tlsSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"}}
	listen := func(port int) net.Listener {
		ln, err := net.Listen("tcp4", net.JoinHostPort(*addr, strconv.Itoa(port)))
		if err != nil {
			log.Fatal(err)
		}
		return ln
	}
	go func() { log.Fatal(tlsSrv.ServeTLS(listen(443), "", "")) }()
	go func() { log.Fatal(mk().Serve(listen(80))) }()
	go serveRaw(listen(2222), func(c net.Conn) {
		_, _ = c.Write([]byte(sshBanner))
		_ = c.SetReadDeadline(time.Now().Add(flowDeadline))
		_, _ = bufio.NewReader(c).ReadString('\n')
	})
	go serveRaw(listen(9001), func(c net.Conn) {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetReadBuffer(4096) // fill the window fast; never read
		}
		// Never read: the proxy's relay toward this origin stays blocked in Write until the client gives up.
		time.Sleep(blockedHold + 5*time.Second)
	})
	go serveRaw(listen(9002), func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(2 * quietHold))
		_, _ = io.Copy(io.Discard, c)
	})
	go serveRaw(listen(9003), func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(flowDeadline))
		_, _ = io.Copy(io.Discard, c)
	})
	log.Printf("origin on %s: 443 80 2222 9001 9002 9003", *addr)
	select {}
}

func serveRaw(ln net.Listener, h func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer c.Close()
			h(c)
		}()
	}
}

func labCerts(dir string) (tls.Certificate, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	leafPEM, keyPEM := filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "leaf.key")
	if c, err := tls.LoadX509KeyPair(leafPEM, keyPEM); err == nil {
		return c, nil
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "endurance lab CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: Hosts[0]}, DNSNames: Hosts,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	kDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	write := func(p, typ string, der []byte, mode os.FileMode) error {
		return os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
	}
	if err := write(filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := write(leafPEM, "CERTIFICATE", leafDER, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := write(keyPEM, "EC PRIVATE KEY", kDER, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(leafPEM, keyPEM)
}

// ---------- driver ----------

type counters struct {
	mu sync.Mutex
	m  map[string]map[string]int64 // kind -> outcome -> count
}

func (c *counters) add(kind, outcome string) {
	c.mu.Lock()
	if c.m[kind] == nil {
		c.m[kind] = map[string]int64{}
	}
	c.m[kind][outcome]++
	c.mu.Unlock()
}

func (c *counters) take() map[string]map[string]int64 {
	c.mu.Lock()
	out := c.m
	c.m = map[string]map[string]int64{}
	c.mu.Unlock()
	return out
}

type driver struct {
	proxy      string
	originCA   *x509.CertPool
	inspectCA  string // file; re-read when it changes (the lab CA is in memory and new after each restart)
	inspectMu  sync.Mutex
	inspectMod time.Time
	inspectCfg *tls.Config
	adverse    []adverseCase
	advNext    atomic.Uint64
	stats      counters
}

type adverseCase struct {
	Name    string
	Data    []byte
	OneByte bool // write one byte per write (1-byte fragmentation)
}

func drive(args []string) {
	fs := flag.NewFlagSet("drive", flag.ExitOnError)
	proxy := fs.String("proxy", "127.0.0.1:18480", "proxy address")
	duration := fs.Duration("duration", 30*time.Minute, "how long to drive")
	interval := fs.Duration("interval", 30*time.Second, "sample interval of the outcome counters")
	caFile := fs.String("ca", "", "origin lab CA (PEM)")
	inspectCA := fs.String("inspect-ca", "", "the proxy's inspection CA (PEM), re-read when it changes")
	corpus := fs.String("corpus", "", "comma list of Go fuzz corpus directories (go test fuzz v1 files)")
	seed := fs.Int64("seed", 540, "seed of the random-bytes cases")
	out := fs.String("out", "", "JSONL file of per-interval outcome counters")
	_ = fs.Parse(args)
	pemData, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		log.Fatal("no certificate in -ca")
	}
	d := &driver{proxy: *proxy, originCA: pool, inspectCA: *inspectCA, stats: counters{m: map[string]map[string]int64{}}}
	d.adverse, err = buildAdverse(strings.Split(*corpus, ","), *seed)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	names := make([]string, len(d.adverse))
	for i, a := range d.adverse {
		names[i] = a.Name
	}
	_ = enc.Encode(map[string]any{"start_unix": time.Now().Unix(), "kinds": Kinds, "adverse_cases": names})
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	var wg sync.WaitGroup
	for _, k := range Kinds {
		wg.Add(1)
		go func(k Kind) {
			defer wg.Done()
			d.generate(ctx, k)
		}(k)
	}
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	emit := func(final bool) {
		_ = enc.Encode(map[string]any{"t_unix": time.Now().Unix(), "final": final, "counts": d.stats.take()})
	}
loop:
	for {
		select {
		case <-tick.C:
			emit(false)
		case <-ctx.Done():
			break loop
		}
	}
	wg.Wait() // every flow has finished (each is bounded by its hold and deadlines)
	emit(true)
	log.Printf("driver finished")
}

func (d *driver) generate(ctx context.Context, k Kind) {
	every := time.Duration(float64(time.Second) / k.Rate)
	t := time.NewTicker(every)
	defer t.Stop()
	var inflight atomic.Int64
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if inflight.Load() >= int64(k.Max) {
			d.stats.add(k.Name, "skipped")
			continue
		}
		inflight.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer inflight.Add(-1)
			d.stats.add(k.Name, d.flow(k.Name))
		}()
	}
}

// connect opens a CONNECT tunnel; the returned reader holds any bytes read past the reply.
func (d *driver) connect(dest string) (net.Conn, *bufio.Reader, error) {
	c, err := net.DialTimeout("tcp4", d.proxy, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("dial: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(flowDeadline))
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dest, dest); err != nil {
		c.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("connect reply: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, nil, fmt.Errorf("connect status %d", resp.StatusCode)
	}
	return c, br, nil
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func classify(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return "ok"
	case strings.HasPrefix(err.Error(), "dial"):
		return "err_dial"
	case strings.HasPrefix(err.Error(), "connect"):
		return "err_connect"
	case errors.As(err, &ne) && ne.Timeout():
		return "err_timeout"
	default:
		return "err_traffic"
	}
}

func (d *driver) flow(kind string) string {
	switch kind {
	case "tls":
		return classify(d.httpsFlow("origin.lab.test:443", "origin.lab.test", &tls.Config{RootCAs: d.originCA,
			ServerName: "origin.lab.test", MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, "/", body))
	case "http1":
		return classify(d.httpFlow())
	case "ssh":
		return classify(d.sshFlow())
	case "inspect":
		return d.inspectFlow()
	case "adverse":
		return classify(d.adverseFlow())
	case "quiet":
		return d.quietFlow()
	case "blocked":
		return d.blockedFlow()
	}
	return "err_kind"
}

func readResponse(c net.Conn, br *bufio.Reader, method string, want []byte) error {
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK || (want != nil && !bytes.Equal(got, want)) {
		return fmt.Errorf("status %d, %d body bytes", resp.StatusCode, len(got))
	}
	return nil
}

func (d *driver) httpsFlow(dest, host string, cfg *tls.Config, path string, want []byte) error {
	c, br, err := d.connect(dest)
	if err != nil {
		return err
	}
	defer c.Close()
	tc := tls.Client(bufConn{c, br}, cfg)
	if err := tc.Handshake(); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tc, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host); err != nil {
		return err
	}
	return readResponse(tc, bufio.NewReader(tc), http.MethodGet, want)
}

func (d *driver) httpFlow() error {
	c, br, err := d.connect("origin.lab.test:80")
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: origin.lab.test\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	return readResponse(c, br, http.MethodGet, body)
}

func (d *driver) sshFlow() error {
	c, br, err := d.connect("origin.lab.test:2222")
	if err != nil {
		return err
	}
	defer c.Close()
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if line != sshBanner {
		return fmt.Errorf("banner %q", line)
	}
	_, err = io.WriteString(c, sshClient)
	return err
}

// The child-app mix of PRO-516 (decrypted path); the proxy inspects *.googleapis.com.
var inspectMix = []struct{ host, path string }{
	{"www.googleapis.com", "/drive/v3/files/1AbCdEf/export?mimeType=text/plain"},
	{"gmail.googleapis.com", "/gmail/v1/users/me/labels"},
}

func (d *driver) inspectConfig() (*tls.Config, error) {
	st, err := os.Stat(d.inspectCA)
	if err != nil {
		return nil, err
	}
	d.inspectMu.Lock()
	defer d.inspectMu.Unlock()
	if d.inspectCfg == nil || !st.ModTime().Equal(d.inspectMod) {
		pemData, err := os.ReadFile(d.inspectCA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, errors.New("no certificate in -inspect-ca")
		}
		d.inspectCfg, d.inspectMod = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, st.ModTime()
	}
	return d.inspectCfg, nil
}

func (d *driver) inspectFlow() string {
	cfg, err := d.inspectConfig()
	if err != nil {
		return "err_inspect_ca"
	}
	m := inspectMix[mrand.Intn(len(inspectMix))]
	c := cfg.Clone()
	c.ServerName = m.host
	err = d.httpsFlow(m.host+":443", m.host, c, m.path, body)
	var ue x509.UnknownAuthorityError
	if errors.As(err, &ue) {
		return "err_inspect_ca" // the proxy restarted with a new in-memory CA; the orchestrator refreshes the file
	}
	return classify(err)
}

func (d *driver) adverseFlow() error {
	a := d.adverse[int(d.advNext.Add(1)-1)%len(d.adverse)]
	c, _, err := d.connect("origin.lab.test:9003")
	if err != nil {
		return err
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if a.OneByte {
		for i := range a.Data {
			if _, err := c.Write(a.Data[i : i+1]); err != nil {
				return err
			}
			if i%8 == 7 {
				time.Sleep(time.Millisecond) // keep the fragments apart on the wire
			}
		}
		return nil
	}
	_, err = c.Write(a.Data)
	return err
}

// quietFlow holds a silent tunnel past the observation window. "ok" means the tunnel stayed open for the
// whole hold: the proxy did not close it when observation expired.
func (d *driver) quietFlow() string {
	c, br, err := d.connect("origin.lab.test:9002")
	if err != nil {
		return classify(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(quietHold))
	_, err = br.ReadByte()
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "ok"
	}
	return "err_closed_early"
}

// blockedFlow writes into a tunnel whose origin never reads until a write blocks, then holds the tunnel past
// the window with the proxy's relay blocked in Write. "ok": the write blocked and the tunnel stayed open.
func (d *driver) blockedFlow() string {
	c, br, err := d.connect("origin.lab.test:9001")
	if err != nil {
		return classify(err)
	}
	defer c.Close()
	chunk := bytes.Repeat([]byte("B"), 16384)
	start := time.Now()
	blocked := false
	for time.Since(start) < 5*time.Second {
		_ = c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := c.Write(chunk); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				blocked = true
				break
			}
			return "err_traffic"
		}
	}
	if !blocked {
		return "err_never_blocked"
	}
	_ = c.SetReadDeadline(time.Now().Add(blockedHold))
	_, err = br.ReadByte()
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "ok"
	}
	return "err_closed_early"
}

// ---------- adverse inputs ----------

// clientHello returns a real Go crypto/tls ClientHello record for host.
func clientHello(host string) ([]byte, error) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		_ = c.Handshake()
	}()
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(b, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	rec := make([]byte, 5+n)
	copy(rec, hdr)
	if _, err := io.ReadFull(b, rec[5:]); err != nil {
		return nil, err
	}
	b.Close()
	return rec, nil
}

// fuzzCorpus reads the first []byte argument of every "go test fuzz v1" file in dirs.
func fuzzCorpus(dirs []string) ([]adverseCase, error) {
	var out []adverseCase
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		err := filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			lines := strings.Split(string(raw), "\n")
			if len(lines) < 2 || lines[0] != "go test fuzz v1" {
				return nil
			}
			for _, l := range lines[1:] {
				if strings.HasPrefix(l, "[]byte(") && strings.HasSuffix(l, ")") {
					s, err := strconv.Unquote(l[len("[]byte(") : len(l)-1])
					if err == nil && len(s) > 0 {
						out = append(out, adverseCase{Name: "fuzz:" + filepath.Base(filepath.Dir(p)) + "/" + e.Name()[:8], Data: []byte(s)})
					}
					break
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func buildAdverse(dirs []string, seed int64) ([]adverseCase, error) {
	ch, err := clientHello("origin.lab.test")
	if err != nil {
		return nil, err
	}
	r := mrand.New(mrand.NewSource(seed))
	random := func(n int) []byte {
		b := make([]byte, n)
		_, _ = r.Read(b)
		return b
	}
	// Oversized: a handshake record that claims a 16 MiB ClientHello and sends 20 KiB of it (past the 16 KiB budget).
	over := append([]byte{0x16, 0x03, 0x01, 0x40, 0x00, 0x01, 0xff, 0xff, 0xff, 0x03, 0x03}, random(20*1024)...)
	cases := []adverseCase{
		{Name: "random_64", Data: random(64)},
		{Name: "random_4k", Data: random(4096)},
		{Name: "random_20k", Data: random(20 * 1024)},
		{Name: "clienthello_truncated_5", Data: ch[:5]},
		{Name: "clienthello_truncated_half", Data: ch[:len(ch)/2]},
		{Name: "clienthello_truncated_last", Data: ch[:len(ch)-1]},
		{Name: "clienthello_oversized", Data: over},
		{Name: "clienthello_1byte_fragments", Data: ch, OneByte: true},
	}
	fz, err := fuzzCorpus(dirs)
	if err != nil {
		return nil, err
	}
	return append(cases, fz...), nil
}

func selfTest() error {
	ch, err := clientHello("origin.lab.test")
	if err != nil {
		return err
	}
	if ch[0] != 0x16 || ch[5] != 0x01 || !bytes.Contains(ch, []byte("origin.lab.test")) {
		return errors.New("clientHello is not a TLS ClientHello record naming the host")
	}
	dir, err := os.MkdirTemp("", "endurance-selftest")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	sub := filepath.Join(dir, "FuzzX")
	if err := os.Mkdir(sub, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(sub, "0123456789abcdef"), []byte("go test fuzz v1\n[]byte(\"\\x16\\x03\")\nbyte('O')\n"), 0o600); err != nil {
		return err
	}
	cases, err := buildAdverse([]string{dir}, 1)
	if err != nil {
		return err
	}
	last := cases[len(cases)-1]
	if !bytes.Equal(last.Data, []byte{0x16, 0x03}) || last.Name != "fuzz:FuzzX/01234567" || len(cases) != 9 {
		return fmt.Errorf("corpus parse: %d cases, last %q %x", len(cases), last.Name, last.Data)
	}
	var c counters
	c.m = map[string]map[string]int64{}
	c.add("tls", "ok")
	c.add("tls", "ok")
	if got := c.take(); got["tls"]["ok"] != 2 || len(c.take()) != 0 {
		return errors.New("counters")
	}
	if classify(errors.New("dial: x")) != "err_dial" || classify(nil) != "ok" {
		return errors.New("classify")
	}
	return nil
}
