package serve

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/keylogcap"
	"github.com/leenadav/protocol-detector/go/internal/ojson"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// The decryption showcase (presentation/poc_decryption/demo.py showcase()): three TLS exchanges made in memory
// by this process's own TLS stack, recorded as a capture with their key log, and decrypted by the key-log
// adapter. Nothing is sent on a network; the throwaway key, certificate and secrets live only in this process.

type showcaseCase struct {
	version           uint16
	cipher            uint16 // 0: the stack's choice (TLS 1.3)
	request, response []byte
}

var showcaseCases = []showcaseCase{
	{version: tls.VersionTLS13,
		request:  []byte("PROPFIND /documents HTTP/1.1\r\nHost: demo.invalid\r\nDepth: 0\r\nContent-Length: 0\r\n\r\n"),
		response: []byte("HTTP/1.1 207 Multi-Status\r\nContent-Length: 0\r\n\r\n")},
	{version: tls.VersionTLS12, cipher: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		request:  []byte("GET / HTTP/1.1\r\nHost: demo.invalid\r\n\r\n"),
		response: []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")},
	{version: tls.VersionTLS12, cipher: tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		request: []byte("*1\r\n$4\r\nPING\r\n"), response: []byte("+PONG\r\n")},
}

// Showcase is showcase(): the merged decryption report of the three exchanges, with "synthetic": true.
func Showcase(ctx context.Context) (*ojson.Object, error) {
	pack, err := content.Embedded()
	if err != nil {
		return nil, err
	}
	certificate, err := throwawayCertificate()
	if err != nil {
		return nil, err
	}
	connections := []ojson.Value{}
	totals := map[string]int64{}
	for index, c := range showcaseCases {
		capture, keylog, err := showcaseFixture(ctx, certificate, c, uint16(51000+index))
		if err != nil {
			return nil, err
		}
		text, err := keylogcap.Analyze(capture, keylog, pack)
		if err != nil {
			return nil, err
		}
		v, err := ojson.Decode([]byte(text))
		if err != nil {
			return nil, err
		}
		report, ok := v.(*ojson.Object)
		if !ok {
			return nil, errors.New("the decryption report is not an object")
		}
		if list, ok := report.Get("connections"); ok {
			if items, ok := list.([]ojson.Value); ok {
				connections = append(connections, items...)
			}
		}
		for _, field := range []string{"frames", "decrypted", "skipped"} {
			value, _ := report.Get(field)
			n, ok := ojson.IntValue(value)
			if !ok {
				return nil, errors.New("the decryption report has no " + field + " count")
			}
			totals[field] += n
		}
	}
	return ojson.NewObject("connections", connections, "frames", ojson.FromInt(totals["frames"]),
		"decrypted", ojson.FromInt(totals["decrypted"]), "skipped", ojson.FromInt(totals["skipped"]), "synthetic", true), nil
}

// throwawayCertificate is a self-signed RSA-2048 certificate for demo.invalid, valid from a minute ago for a day.
func throwawayCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "demo.invalid"},
		DNSNames: []string{"demo.invalid"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// showcaseFixture is fixture(): one exchange (handshake, one request, one response) and its capture and key log.
func showcaseFixture(ctx context.Context, certificate tls.Certificate, c showcaseCase, clientPort uint16) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	toServer, toClient := newMemPipe(), newMemPipe()
	var sent [2]bytes.Buffer // what the client and the server wrote, in order
	clientConn := &memConn{in: toClient, out: toServer, record: &sent[0]}
	serverConn := &memConn{in: toServer, out: toClient, record: &sent[1]}
	stop := context.AfterFunc(ctx, func() { toServer.close(); toClient.close() })
	defer stop()

	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)
	var keylog bytes.Buffer
	clientConfig := &tls.Config{ServerName: "demo.invalid", RootCAs: roots, MinVersion: c.version, MaxVersion: c.version,
		KeyLogWriter: &keylog, CurvePreferences: []tls.CurveID{tls.X25519}}
	serverConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: c.version, MaxVersion: c.version,
		CurvePreferences: []tls.CurveID{tls.X25519}}
	if c.cipher != 0 {
		clientConfig.CipherSuites = []uint16{c.cipher}
		serverConfig.CipherSuites = []uint16{c.cipher}
	}
	client, server := tls.Client(clientConn, clientConfig), tls.Server(serverConn, serverConfig)

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- func() error {
			if err := server.HandshakeContext(ctx); err != nil {
				return err
			}
			if _, err := io.ReadFull(server, make([]byte, len(c.request))); err != nil {
				return err
			}
			_, err := server.Write(c.response)
			return err
		}()
	}()
	clientErr := func() error {
		if err := client.HandshakeContext(ctx); err != nil {
			return err
		}
		if _, err := client.Write(c.request); err != nil {
			return err
		}
		_, err := io.ReadFull(client, make([]byte, len(c.response)))
		return err
	}()
	if clientErr != nil {
		toServer.close()
		toClient.close()
		<-serverDone
		return nil, "", errors.New("Synthetic TLS handshake did not finish.")
	}
	if err := <-serverDone; err != nil {
		return nil, "", errors.New("Synthetic TLS handshake did not finish.")
	}

	const clientAddr, serverAddr = "192.0.2.10", "198.51.100.20"
	frames := [][]byte{testframes.TCP(clientAddr, clientPort, serverAddr, 443, 999, 0, 2, nil),
		testframes.TCP(serverAddr, 443, clientAddr, clientPort, 8999, 1000, 18, nil)}
	for side, data := range [][]byte{sent[0].Bytes(), sent[1].Bytes()} {
		srcAddr, srcPort, dstAddr, dstPort, seq := clientAddr, clientPort, serverAddr, uint16(443), uint32(1000)
		if side == 1 {
			srcAddr, srcPort, dstAddr, dstPort, seq = serverAddr, 443, clientAddr, clientPort, 9000
		}
		// Reversed segments prove record reconstruction is independent of packet boundaries.
		var pieces [][]byte
		for offset := 0; offset < len(data); offset += 700 {
			pieces = append(pieces, testframes.TCP(srcAddr, srcPort, dstAddr, dstPort, seq+uint32(offset), 0, 24, data[offset:min(offset+700, len(data))]))
		}
		for i := len(pieces) - 1; i >= 0; i-- {
			frames = append(frames, pieces[i])
		}
		frames = append(frames, testframes.TCP(srcAddr, srcPort, dstAddr, dstPort, seq+uint32(len(data)), 0, 17, nil))
	}
	return pcapBytes(frames), keylog.String(), nil
}

// pcapBytes is make_sample_pcap.pcap_bytes: a little-endian microsecond pcap, one frame per second.
func pcapBytes(frames [][]byte) []byte {
	out := binary.LittleEndian.AppendUint32(nil, 0xa1b2c3d4)
	out = binary.LittleEndian.AppendUint16(out, 2)
	out = binary.LittleEndian.AppendUint16(out, 4)
	for _, v := range []uint32{0, 0, 65535, 1} {
		out = binary.LittleEndian.AppendUint32(out, v)
	}
	for index, frame := range frames {
		for _, v := range []uint32{1700000000 + uint32(index), 0, uint32(len(frame)), uint32(len(frame))} {
			out = binary.LittleEndian.AppendUint32(out, v)
		}
		out = append(out, frame...)
	}
	return out
}

// memPipe is one direction of an in-memory connection: writes never block, reads wait for bytes or close.
type memPipe struct {
	mu     sync.Mutex
	ready  *sync.Cond
	buf    bytes.Buffer
	closed bool
}

func newMemPipe() *memPipe {
	p := &memPipe{}
	p.ready = sync.NewCond(&p.mu)
	return p
}

func (p *memPipe) close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.ready.Broadcast()
}

// memConn is the net.Conn the TLS stack runs over; record keeps every byte it writes.
type memConn struct {
	in, out *memPipe
	record  *bytes.Buffer
}

func (c *memConn) Read(b []byte) (int, error) {
	c.in.mu.Lock()
	defer c.in.mu.Unlock()
	for c.in.buf.Len() == 0 && !c.in.closed {
		c.in.ready.Wait()
	}
	if c.in.buf.Len() == 0 {
		return 0, io.EOF
	}
	return c.in.buf.Read(b)
}

func (c *memConn) Write(b []byte) (int, error) {
	c.out.mu.Lock()
	if c.out.closed {
		c.out.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.out.buf.Write(b)
	c.record.Write(b) // written only by this side's goroutine
	c.out.mu.Unlock()
	c.out.ready.Broadcast()
	return len(b), nil
}

func (c *memConn) Close() error                     { c.out.close(); return nil }
func (c *memConn) LocalAddr() net.Addr              { return memAddr{} }
func (c *memConn) RemoteAddr() net.Addr             { return memAddr{} }
func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

type memAddr struct{}

func (memAddr) Network() string { return "memory" }
func (memAddr) String() string  { return "memory" }

// showcaseError is the worker's message for a failed showcase (str(error)[:240] in the reference).
func showcaseError(err error) string {
	return runeTruncate(strings.TrimSpace(err.Error()), 240)
}
