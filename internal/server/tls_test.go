/*
Copyright 2026, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testHost       = "localhost"
	certValidity   = time.Hour
	reloadTimeout  = 5 * time.Second
	reloadInterval = 20 * time.Millisecond
	fileMode       = 0o600
)

// writeCertificate writes a new self-signed certificate for testHost, with the
// given serial number, and its key to certFile and keyFile.
func writeCertificate(t *testing.T, certFile, keyFile string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: testHost},
		DNSNames:              []string{testHost},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, os.WriteFile(certFile, certPEM, fileMode))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, fileMode))
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func certPaths(t *testing.T) (certFile, keyFile string) {
	dir := t.TempDir()
	return filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
}

// listen serves TLS handshakes with config until the test ends, and returns
// the address.
func listen(t *testing.T, config *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()
	return ln.Addr().String()
}

// handshake connects to addr, trusting only trusted, and returns the
// connection state.
func handshake(t *testing.T, addr string, trusted *x509.Certificate) tls.ConnectionState {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs: certPool(trusted), ServerName: testHost, MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState()
}

func TestNewTLSConfig_NegotiatesHybridPostQuantumKeyExchange(t *testing.T) {
	certFile, keyFile := certPaths(t)
	cert := writeCertificate(t, certFile, keyFile, 1)
	config, err := NewTLSConfig(certFile, keyFile)
	require.NoError(t, err)

	state := handshake(t, listen(t, config), cert)
	assert.Equal(t, uint16(tls.VersionTLS13), state.Version)
	assert.Equal(t, tls.X25519MLKEM768, state.CurveID)
}

func TestNewTLSConfig_ReloadsAChangedCertificate(t *testing.T) {
	certFile, keyFile := certPaths(t)
	first := writeCertificate(t, certFile, keyFile, 1)
	c, err := newCertificate(certFile, keyFile)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.fw.Close() })
	addr := listen(t, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: c.get})
	assert.Equal(t, first.SerialNumber, handshake(t, addr, first).PeerCertificates[0].SerialNumber)

	second := writeCertificate(t, certFile, keyFile, 2)
	assert.Eventually(t, func() bool {
		conn, dialErr := tls.Dial("tcp", addr, &tls.Config{
			RootCAs: certPool(second), ServerName: testHost, MinVersion: tls.VersionTLS12,
		})
		if dialErr != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, reloadTimeout, reloadInterval, "the renewed certificate is served")

	// A file that cannot be loaded keeps the previous certificate in use.
	generation := c.fw.Generation()
	require.NoError(t, os.WriteFile(certFile, []byte("not a certificate"), fileMode))
	require.Eventually(t, func() bool { return c.fw.Generation() > generation }, reloadTimeout, reloadInterval)
	cert, err := c.get(nil)
	require.NoError(t, err)
	assert.Equal(t, second.Raw, cert.Certificate[0])
}

func certPool(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

func TestNewTLSConfig_FailsWithoutUsableFiles(t *testing.T) {
	certFile, keyFile := certPaths(t)
	_, err := NewTLSConfig(certFile, keyFile)
	require.ErrorContains(t, err, "cannot load the TLS certificate")
}
