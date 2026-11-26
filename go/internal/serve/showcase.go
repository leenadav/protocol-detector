package serve

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/keylogcap"
	"github.com/leenadav/protocol-detector/go/internal/ojson"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// The three answers the service used to take from the Python reference (PRO-401, Lee 2026-11-25: the reference is
// removed). Each is now the service's own:
//
//   - the catalog (/api/catalog): the protocol descriptors, the applications and the evidence-limited outcomes,
//     frozen from the reference's catalog_data() into catalog.json, with the build source read from SOURCE.json and
//     the service's limits, as the reference assembled them;
//   - the demo capture (/api/sample and the "demo" job): one capture the reference's demo_bytes() generated, frozen
//     into demo.pcap (synthetic fixtures on documentation addresses; the reference drew a fresh TLS random per call,
//     which is the only thing that varied);
//   - the decryption showcase (the "decrypt-demo" job): three real TLS exchanges made in memory with crypto/tls
//     (TLS 1.3, TLS 1.2 with ECDHE-RSA-AES128-GCM-SHA256 carrying HTTP, TLS 1.2 with ECDHE-RSA-AES256-GCM-SHA384
//     carrying RESP), as poc_decryption/demo.py's showcase() made them with OpenSSL, framed into captures and
//     decrypted by this engine. Nothing leaves the process; the keys are thrown away with it.

//go:embed catalog.json
var catalogJSON []byte

//go:embed demo.pcap
var demoCapture []byte

// DemoCapture is the frozen synthetic demo capture (a copy).
func DemoCapture() []byte { return append([]byte(nil), demoCapture...) }

// catalog is catalog_data(): {source, protocols, applications, outcomes, limits}.
func catalog(root string) (*ojson.Object, error) {
	frozen, err := ojson.Decode(catalogJSON)
	if err != nil {
		return nil, err
	}
	pieces, ok := frozen.(*ojson.Object)
	if !ok {
		return nil, errors.New("catalog.json is not an object")
	}
	data, err := os.ReadFile(filepath.Join(root, "SOURCE.json"))
	if err != nil {
		return nil, err
	}
	v, err := ojson.Decode(data)
	if err != nil {
		return nil, err
	}
	source, ok := v.(*ojson.Object)
	if !ok {
		return nil, errors.New("SOURCE.json is not an object")
	}
	subset := ojson.NewObject()
	for _, key := range []string{"version", "branch", "commit", "repository", "build_digest", "components"} {
		value, _ := source.Get(key) // source.get(k): a missing key is null
		subset.Set(key, value)
	}
	part := func(key string) ojson.Value { value, _ := pieces.Get(key); return value }
	limits := ojson.NewObject("upload_mb", ojson.FromInt(8), "frames", ojson.FromInt(MaxFrames), "sessions", ojson.FromInt(MaxSessions),
		"worker_seconds", ojson.FromInt(WorkerSeconds))
	return ojson.NewObject("source", subset, "protocols", part("protocols"), "applications", part("applications"),
		"outcomes", part("outcomes"), "limits", limits), nil
}

// showcaseCase is one exchange of the showcase: the TLS version, the one cipher suite of a TLS 1.2 exchange, and
// the application bytes each side sends once the handshake is done.
type showcaseCase struct {
	version           uint16
	cipher            uint16
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

// memEnd is one end of an in-memory, buffered duplex connection (a write never waits for the reader, unlike
// net.Pipe, so neither TLS side can block the other while both write a flight); it keeps every byte its side wrote.
type memEnd struct {
	in, out *memQueue
	written bytes.Buffer
}

type memQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	data   bytes.Buffer
	closed bool
}

func newQueue() *memQueue {
	q := &memQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func memPair() (*memEnd, *memEnd) {
	a, b := newQueue(), newQueue()
	return &memEnd{in: a, out: b}, &memEnd{in: b, out: a}
}

func (e *memEnd) Read(p []byte) (int, error) {
	q := e.in
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.data.Len() == 0 && !q.closed {
		q.cond.Wait()
	}
	if q.data.Len() == 0 {
		return 0, io.EOF
	}
	return q.data.Read(p)
}

func (e *memEnd) Write(p []byte) (int, error) {
	q := e.out
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return 0, io.ErrClosedPipe
	}
	q.data.Write(p)
	e.written.Write(p) // only this end's goroutine writes, under the queue's lock
	q.cond.Broadcast()
	return len(p), nil
}

// Close ends both directions: a blocked reader on either end sees EOF.
func (e *memEnd) Close() error {
	for _, q := range []*memQueue{e.in, e.out} {
		q.mu.Lock()
		q.closed = true
		q.cond.Broadcast()
		q.mu.Unlock()
	}
	return nil
}

func (e *memEnd) bytes() []byte {
	e.out.mu.Lock()
	defer e.out.mu.Unlock()
	return append([]byte(nil), e.written.Bytes()...)
}

type memAddr struct{}

func (memAddr) Network() string { return "memory" }
func (memAddr) String() string  { return "memory" }

func (e *memEnd) LocalAddr() net.Addr              { return memAddr{} }
func (e *memEnd) RemoteAddr() net.Addr             { return memAddr{} }
func (e *memEnd) SetDeadline(time.Time) error      { return nil }
func (e *memEnd) SetReadDeadline(time.Time) error  { return nil }
func (e *memEnd) SetWriteDeadline(time.Time) error { return nil }

// selfSigned is a throwaway RSA certificate for demo.invalid (the reference's fixture used RSA 2048 too: the TLS 1.2
// suites are ECDHE-RSA).
func selfSigned() (tls.Certificate, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "demo.invalid"},
		Issuer: pkix.Name{CommonName: "demo.invalid"}, DNSNames: []string{"demo.invalid"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf, nil
}

// exchange runs one TLS exchange in memory: (client bytes, server bytes, the client's NSS key log).
func exchange(c showcaseCase, certificate tls.Certificate, leaf *x509.Certificate) ([]byte, []byte, string, error) {
	client, server := memPair()
	defer func() { _ = client.Close() }()
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	var keys bytes.Buffer
	clientConfig := &tls.Config{ServerName: "demo.invalid", RootCAs: pool, MinVersion: c.version, MaxVersion: c.version, KeyLogWriter: &keys}
	serverConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: c.version, MaxVersion: c.version}
	if c.cipher != 0 {
		clientConfig.CipherSuites = []uint16{c.cipher}
		serverConfig.CipherSuites = []uint16{c.cipher}
	}
	tlsClient, tlsServer := tls.Client(client, clientConfig), tls.Server(server, serverConfig)
	served := make(chan error, 1)
	go func() {
		served <- func() error {
			if err := tlsServer.Handshake(); err != nil {
				return err
			}
			request := make([]byte, len(c.request))
			if _, err := io.ReadFull(tlsServer, request); err != nil {
				return err
			}
			_, err := tlsServer.Write(c.response)
			return err
		}()
	}()
	fail := func(err error) ([]byte, []byte, string, error) {
		_ = client.Close() // unblocks the server's goroutine, which then ends with its own error (or none)
		return nil, nil, "", errors.Join(err, <-served)
	}
	if err := tlsClient.Handshake(); err != nil {
		return fail(err)
	}
	if _, err := tlsClient.Write(c.request); err != nil {
		return fail(err)
	}
	response := make([]byte, len(c.response))
	if _, err := io.ReadFull(tlsClient, response); err != nil {
		return fail(err)
	}
	if err := <-served; err != nil {
		return nil, nil, "", err
	}
	if !bytes.Equal(response, c.response) {
		return nil, nil, "", errors.New("synthetic TLS exchange returned other bytes")
	}
	return client.bytes(), server.bytes(), keys.String(), nil
}

// u32 is a length, offset or time of the showcase's own small captures as a PCAP field; nothing it frames comes near
// 2^32, and a value outside the range would be a bug here, framed as 0 rather than wrapped.
func u32(n int) uint32 {
	if n < 0 || n > math.MaxUint32 {
		return 0
	}
	return uint32(n)
}

// showcaseCapture frames one exchange as the reference's fixture() did: SYN and SYN-ACK, each direction cut into
// 700-byte segments sent in reverse order (record reassembly must not depend on packet boundaries), then each
// side's FIN; classic PCAP, one second apart.
func showcaseCapture(clientPort uint16, clientBytes, serverBytes []byte) []byte {
	const clientAddr, serverAddr = "192.0.2.10", "198.51.100.20"
	frames := [][]byte{
		testframes.TCP(clientAddr, clientPort, serverAddr, 443, 999, 0, 0x02, nil),
		testframes.TCP(serverAddr, 443, clientAddr, clientPort, 8999, 1000, 0x12, nil),
	}
	for _, side := range []struct {
		fromAddr, toAddr string
		fromPort, toPort uint16
		seq              uint32
		data             []byte
	}{{clientAddr, serverAddr, clientPort, 443, 1000, clientBytes}, {serverAddr, clientAddr, 443, clientPort, 9000, serverBytes}} {
		var pieces [][]byte
		var offsets []uint32
		for offset := 0; offset < len(side.data); offset += 700 {
			end := min(offset+700, len(side.data))
			pieces, offsets = append(pieces, side.data[offset:end]), append(offsets, u32(offset))
		}
		for i := len(pieces) - 1; i >= 0; i-- {
			frames = append(frames, testframes.TCP(side.fromAddr, side.fromPort, side.toAddr, side.toPort, side.seq+offsets[i], 0, 0x18, pieces[i]))
		}
		frames = append(frames, testframes.TCP(side.fromAddr, side.fromPort, side.toAddr, side.toPort, side.seq+u32(len(side.data)), 0, 0x11, nil))
	}
	var out bytes.Buffer
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:], 2)
	binary.LittleEndian.PutUint16(header[6:], 4)
	binary.LittleEndian.PutUint32(header[16:], 65535)
	binary.LittleEndian.PutUint32(header[20:], 1)
	_, _ = out.Write(header) // a bytes.Buffer write never fails
	for index, frame := range frames {
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record[0:], u32(1700000000+index))
		binary.LittleEndian.PutUint32(record[8:], u32(len(frame)))
		binary.LittleEndian.PutUint32(record[12:], u32(len(frame)))
		_, _ = out.Write(record)
		_, _ = out.Write(frame)
	}
	return out.Bytes()
}

// Showcase is showcase(): the three exchanges, each decrypted by this engine, their connections concatenated and
// their frame, decrypted and skipped counts summed; "synthetic" is true.
func Showcase() (*ojson.Object, error) {
	pack, err := content.Embedded()
	if err != nil {
		return nil, err
	}
	certificate, leaf, err := selfSigned()
	if err != nil {
		return nil, err
	}
	connections := []ojson.Value{}
	totals := map[string]int64{}
	for index, c := range showcaseCases {
		clientBytes, serverBytes, keylog, err := exchange(c, certificate, leaf)
		if err != nil {
			return nil, fmt.Errorf("synthetic TLS handshake did not finish: %w", err)
		}
		text, err := keylogcap.Analyze(showcaseCapture(uint16(51000+index), clientBytes, serverBytes), keylog, pack)
		if err != nil {
			return nil, err
		}
		v, err := ojson.Decode([]byte(text))
		if err != nil {
			return nil, err
		}
		report, ok := v.(*ojson.Object)
		if !ok {
			return nil, errors.New("decryption report is not an object")
		}
		if rows, ok := report.Get("connections"); ok {
			if list, ok := rows.([]ojson.Value); ok {
				connections = append(connections, list...)
			}
		}
		for _, field := range []string{"frames", "decrypted", "skipped"} {
			value, _ := report.Get(field)
			n, _ := ojson.IntValue(value)
			totals[field] += n
		}
	}
	return ojson.NewObject("connections", connections, "frames", ojson.FromInt(totals["frames"]), "decrypted", ojson.FromInt(totals["decrypted"]),
		"skipped", ojson.FromInt(totals["skipped"]), "synthetic", true), nil
}

// DecryptDemoWorker is `server.py --decrypt-worker --demo`: the showcase report on standard output, or
// {"error": ...} when it could not be made.
func DecryptDemoWorker(stdout io.Writer) int {
	limitCPU(22)
	report, err := Showcase()
	if err != nil {
		return emit(stdout, ojson.NewObject("error", runeTruncate(err.Error(), 240)))
	}
	return emit(stdout, report)
}
