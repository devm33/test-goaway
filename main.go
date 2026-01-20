package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

const targetURL = "https://api.githubcopilot.com"

func main() {
	// Create a reverse proxy to the target server
	target, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Failed to parse target URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Customize the director to preserve the original request
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
		req.Header.Set("Host", target.Host)
	}

	// Create the main handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is a /chat/completions request
		// This matches /chat/completions and any path ending with /chat/completions
		// (e.g., /v1/chat/completions, /api/chat/completions)
		if strings.HasSuffix(r.URL.Path, "/chat/completions") {
			// Send GOAWAY frame for HTTP/2 connections
			if r.ProtoMajor == 2 {
				log.Printf("Sending GOAWAY for /chat/completions request")
				// Send an initial response header before GOAWAY
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				// Close the stream after 100ms to send GOAWAY
				time.Sleep(100 * time.Millisecond)
				panic(http.ErrAbortHandler)
			}
			// For HTTP/1.1, just close the connection
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		// For all other requests, proxy to the target server
		log.Printf("Proxying request: %s %s", r.Method, r.URL.Path)
		proxy.ServeHTTP(w, r)
	})

	// Create TLS config for the server
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	server := &http.Server{
		Addr:      ":8443",
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	// Configure HTTP/2
	http2Server := &http2.Server{}
	if err := http2.ConfigureServer(server, http2Server); err != nil {
		log.Fatalf("Failed to configure HTTP/2: %v", err)
	}

	log.Printf("Starting server on https://localhost:8443")
	log.Printf("Proxying to %s", targetURL)
	log.Printf("GOAWAY will be sent for /chat/completions requests")

	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	// Generate a new RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create a certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test GOAWAY Server"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Convert to tls.Certificate
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}
