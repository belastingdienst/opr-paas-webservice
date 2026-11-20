/*
Copyright 2026, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"sync"

	"github.com/belastingdienst/opr-paas-webservice/v3/internal/utils"
)

// certificate is the serving certificate. It is read again when its files
// change, so a renewed certificate (for example from cert-manager) is used
// without a restart.
type certificate struct {
	certFile string
	keyFile  string
	fw       *utils.FileWatcher

	mu         sync.Mutex
	cert       *tls.Certificate
	generation uint64 // the watcher generation the certificate was last loaded at
}

// NewTLSConfig returns the TLS configuration for serving the certificate in
// certFile with the key in keyFile. It returns an error when they cannot be
// loaded. Go's defaults for versions and key exchange are kept, so clients that
// support it get the hybrid post-quantum key exchange X25519MLKEM768.
func NewTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	c, err := newCertificate(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: c.get}, nil
}

func newCertificate(certFile, keyFile string) (*certificate, error) {
	// Watch before the first load, so a change during the load is not missed.
	fw := utils.NewFileWatcher(certFile, keyFile)
	c := &certificate{certFile: certFile, keyFile: keyFile, fw: fw, generation: fw.Generation()}
	if err := c.load(); err != nil {
		_ = fw.Close()
		return nil, err
	}
	return c, nil
}

// load reads the certificate files. The caller holds mu, or is the only user.
func (c *certificate) load() error {
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return fmt.Errorf("cannot load the TLS certificate: %w", err)
	}
	c.cert = &cert
	return nil
}

// get returns the current certificate, after reading it again when its files
// changed. When the new files cannot be loaded, for example because only one
// of them has been replaced yet, the previous certificate is kept until the
// next change.
func (c *certificate) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	generation := c.fw.Generation()
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation != c.generation {
		c.generation = generation
		if err := c.load(); err != nil {
			log.Printf("ERROR: %v; serving the previous certificate", err)
		}
	}
	return c.cert, nil
}
