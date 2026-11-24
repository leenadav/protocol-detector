// Command loadorigin is the synthetic origin for the Culvert lab load test (PRO-269).
//
// It serves HTTP/1.1 on <addr>:80 and HTTPS on <addr>:443 with a throw-away self-signed certificate made at
// start-up. The default address is 203.0.113.10 (RFC 5737 TEST-NET-3), which the lab adds to the loopback
// interface; nothing leaves the container. It is a test tool, never shipped, and has no dependency outside the
// Go standard library.
//
// Usage: go run ./lab/culvert/tools/loadorigin [-addr 203.0.113.10]
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("addr", "203.0.113.10", "IPv4 address to listen on (a loopback alias)")
	flag.Parse()

	body := []byte("lab origin says hello\n")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	})

	cert, err := selfSigned()
	if err != nil {
		log.Fatal(err)
	}
	plain := &http.Server{Addr: net.JoinHostPort(*addr, "80"), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	secure := &http.Server{
		Addr:              net.JoinHostPort(*addr, "443"),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
	}
	errs := make(chan error, 2)
	go func() { errs <- plain.ListenAndServe() }()
	go func() { errs <- secure.ListenAndServeTLS("", "") }()
	log.Printf("loadorigin: http://%s:80 and https://%s:443", *addr, *addr)
	log.Fatal(<-errs)
}

// selfSigned makes an ECDSA P-256 certificate for origin.lab.test, valid for one day.
func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "origin.lab.test"},
		DNSNames:     []string{"origin.lab.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
