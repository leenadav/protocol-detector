// Command origin is the synthetic HTTPS origin of the PRO-516 child-app load test.
//
// It serves HTTP/1.1 and HTTP/2 (ALPN) on <addr>:443 with a leaf certificate signed by a throw-away lab CA,
// so the Culvert lab build can verify the upstream leg of an inspected tunnel through SSL_CERT_FILE. It reads
// and discards the request body and answers 200 with a 22-byte text/plain body. Default address 203.0.113.10
// (RFC 5737), a loopback alias; nothing leaves the container. Go standard library only; never shipped.
//
// Usage: go run ./lab/culvert/tools/childappload/origin -certs <dir> [-addr 203.0.113.10]
// <dir> receives ca.pem (the lab CA) and is reused if it already holds ca.pem, ca.key, leaf.pem and leaf.key.
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
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Hosts is the set of names the leaf certificate covers: the request mix of the load test.
var Hosts = []string{"gmail.googleapis.com", "www.googleapis.com", "unowned.example"}

func main() {
	addr := flag.String("addr", "203.0.113.10", "IPv4 address to listen on (a loopback alias)")
	dir := flag.String("certs", "", "directory for the lab CA and leaf (created if missing)")
	flag.Parse()
	if *dir == "" {
		log.Fatal("-certs is required")
	}
	cert, err := loadOrMake(*dir)
	if err != nil {
		log.Fatal(err)
	}
	body := []byte("lab origin says hello\n")
	// A plain handler, not http.ServeMux: ServeMux answers a path with a ".." segment with a 301 to the
	// cleaned path, which would turn the non-canonical request of the mix into two requests.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	})
	srv := &http.Server{
		Addr:              net.JoinHostPort(*addr, "443"),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}},
	}
	log.Printf("origin on %s (h2, http/1.1)", srv.Addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func writePEM(path, typ string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600)
}

func loadOrMake(dir string) (tls.Certificate, error) {
	leafPEM, leafKey := filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "leaf.key")
	if c, err := tls.LoadX509KeyPair(leafPEM, leafKey); err == nil {
		return c, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PRO-516 lab origin CA (throw-away)"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: Hosts[0]}, DNSNames: Hosts,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	cakder, _ := x509.MarshalECPrivateKey(caKey)
	for _, f := range []struct {
		p, t string
		d    []byte
	}{
		{filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER}, {filepath.Join(dir, "ca.key"), "EC PRIVATE KEY", cakder},
		{leafPEM, "CERTIFICATE", der}, {leafKey, "EC PRIVATE KEY", kder},
	} {
		if err := writePEM(f.p, f.t, f.d); err != nil {
			return tls.Certificate{}, err
		}
	}
	return tls.LoadX509KeyPair(leafPEM, leafKey)
}
