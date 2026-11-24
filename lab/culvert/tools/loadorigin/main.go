// Command loadorigin is the synthetic origin of the Culvert load test (docs/integration/LOAD-TEST.md).
//
// It serves a fixed 33-byte plain-text body over HTTP on <addr>:80 and HTTPS on <addr>:443, where <addr> is a
// loopback-bound RFC 5737 address (default 203.0.113.10, origin.lab.test). The TLS certificate is generated at
// start, self-signed for origin.lab.test, and written as PEM to -cert so the load generator can trust it. Nothing
// leaves the host. Lab tooling only: standard library, never shipped.
//
//	GOWORK=off go build -o loadorigin lab/culvert/tools/loadorigin/main.go && ./loadorigin -cert /path/origin.pem
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

var body = []byte("lab origin says hello: load test\n")

func main() {
	addr := flag.String("addr", "203.0.113.10", "loopback-bound IPv4 address to listen on")
	certOut := flag.String("cert", "origin.pem", "where to write the generated certificate (PEM)")
	flag.Parse()

	cert, err := selfSigned(*certOut)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	})
	// The header timeout also bounds the TLS handshake, so it is longer than loadhold.py's silent tunnels live.
	plain := &http.Server{Addr: *addr + ":80", Handler: handler, ReadHeaderTimeout: 60 * time.Second}
	secure := &http.Server{Addr: *addr + ":443", Handler: handler, ReadHeaderTimeout: 60 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}}
	go func() { log.Fatal(plain.ListenAndServe()) }()
	log.Printf("loadorigin up on %s:80 and :443", *addr)
	log.Fatal(secure.ListenAndServeTLS("", ""))
}

func selfSigned(path string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "origin.lab.test"},
		DNSNames:              []string{"origin.lab.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
