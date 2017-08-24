// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package selfsign exposes a GetCertificate function that generates self-signed
// certificates and is suitable for use in the *tls.Config of an HTTPS server.
//
// Based on https://golang.org/src/crypto/tls/generate_cert.go
package selfsign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

type cacheEntry struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

var (
	cache = make(map[string]*cacheEntry)
	mutex sync.Mutex
)

const (
	validFor       = 24 * time.Hour
	expirationSlop = time.Minute
)

// GetCertificate generates a self-signed certificate
func GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	mutex.Lock()
	defer mutex.Unlock()

	if entry, ok := cache[hello.ServerName]; ok && entry.expiresAt.After(time.Now()) {
		return entry.cert, nil
	}

	generated, err := generateCert(hello.ServerName)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %s", err)
	}

	cache[hello.ServerName] = &cacheEntry{
		cert:      generated,
		expiresAt: time.Now().Add(validFor - expirationSlop),
	}

	return generated, nil
}

func generateCert(serverName string) (*tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(serverName); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, serverName)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %s", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}, nil
}
