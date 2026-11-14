package detector

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// tlsFlights runs one real TLS handshake between Go's crypto/tls client and server over in-memory pipes
// and returns the first bytes each side wrote (the ClientHello flight and the ServerHello flight). The
// key exchange is whatever the standard library offers by default unless curves restricts it, so the
// default case is the post-quantum hybrid group current clients negotiate.
func tlsFlights(t *testing.T, serverName string, alpn []string, curves []tls.CurveID) (client, server []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: serverName},
		DNSNames: []string{serverName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	cRaw, sRaw := net.Pipe()
	cRec, sRec := &firstWrite{Conn: cRaw}, &firstWrite{Conn: sRaw}
	srv := tls.Server(sRec, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: alpn, CurvePreferences: curves})
	cli := tls.Client(cRec, &tls.Config{ServerName: serverName, NextProtos: alpn, InsecureSkipVerify: true, //nolint:gosec // synthetic lab certificate
		CurvePreferences: curves})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Handshake()
	}()
	_ = cli.Handshake()
	// Close the raw pipes, not the TLS conns: a close_notify would block on the unread synchronous pipe.
	_ = cRaw.Close()
	_ = sRaw.Close()
	wg.Wait()
	return cRec.bytes(), sRec.bytes()
}

// firstWrite records what one side wrote before it first read again after writing (its first flight).
type firstWrite struct {
	net.Conn
	mu     sync.Mutex
	buf    []byte
	sealed bool
}

func (w *firstWrite) Write(p []byte) (int, error) {
	w.mu.Lock()
	if !w.sealed {
		w.buf = append(w.buf, p...)
	}
	w.mu.Unlock()
	return w.Conn.Write(p)
}

func (w *firstWrite) Read(p []byte) (int, error) {
	w.mu.Lock()
	if len(w.buf) > 0 {
		w.sealed = true
	}
	w.mu.Unlock()
	return w.Conn.Read(p)
}

func (w *firstWrite) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf...)
}
