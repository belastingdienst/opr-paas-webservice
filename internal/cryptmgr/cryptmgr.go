package cryptmgr

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/utils"
)

// ErrNoPrivateKeys is returned for a decryption request when the service runs
// encrypt-only: no private keys are configured, so nothing can be decrypted.
var ErrNoPrivateKeys = errors.New("check disabled: no private keys configured")

// readinessPaasName is the Paas name used to build a crypt for the readiness
// check. The Paas name only binds a ciphertext to its Paas; any name proves
// that the configured keys can be loaded.
const readinessPaasName = "readiness"

// Manager is struct to manage crypts
type Manager struct {
	mu    sync.RWMutex
	cache map[string]*crypt.Crypt
	fw    *utils.FileWatcher
	cfg   *config.WsConfig
}

// NewManager returns a new Manager based on the provided WsConfig
func NewManager(cfg *config.WsConfig) *Manager {
	m := &Manager{
		cache: make(map[string]*crypt.Crypt),
		cfg:   cfg,
	}
	if m.EncryptOnly() {
		log.Printf("no private keys at %q: running encrypt-only, the check endpoints are disabled", cfg.PrivateKeyPath)
	}
	return m
}

// EncryptOnly reports whether no private keys are configured: the private key
// path does not exist. The service then encrypts with the public key alone and
// cannot decrypt.
func (m *Manager) EncryptOnly() bool {
	if m.cfg.PrivateKeyPath == "" {
		return true
	}
	_, err := os.Stat(m.cfg.PrivateKeyPath)
	return errors.Is(err, os.ErrNotExist)
}

func (m *Manager) privateKeyPaths() []string {
	if m.EncryptOnly() {
		return nil
	}
	return []string{m.cfg.PrivateKeyPath}
}

func (m *Manager) get(paas string) *crypt.Crypt {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cache[paas]
}

func (m *Manager) reset() {
	log.Println("Resetting RSA")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache = make(map[string]*crypt.Crypt)
}

// build creates a crypt from the configured key files, without the cache.
func (m *Manager) build(paasName string) (*crypt.Crypt, error) {
	c, err := crypt.NewCryptFromFiles(m.privateKeyPaths(), m.cfg.PublicKeyPath, paasName)
	if err != nil {
		return nil, fmt.Errorf("unable to create a crypt: %w", err)
	}
	return c, nil
}

// GetOrCreate returns a crypt based on the paasName, or an error when the
// configured keys cannot be loaded.
func (m *Manager) GetOrCreate(paasName string) (*crypt.Crypt, error) {
	if m.fw == nil {
		log.Println("Starting watcher")
		m.fw = utils.NewFileWatcher(m.cfg.PrivateKeyPath, m.cfg.PublicKeyPath)
	}

	triggered := m.fw.WasTriggered()

	if !triggered {
		if c := m.get(paasName); c != nil {
			return c, nil // cache hit, no reset needed
		}
	} else {
		m.reset() // only reset if files actually changed
	}

	c, err := m.build(paasName)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache[paasName] = c
	return c, nil
}

// Ready returns an error when the configured keys, read from disk now rather
// than from the cache, cannot encrypt: they cannot be loaded, or no public key
// can be found for encryption.
func (m *Manager) Ready() error {
	c, err := m.build(readinessPaasName)
	if err != nil {
		return err
	}
	if _, err = c.Encrypt([]byte(readinessPaasName)); err != nil {
		return fmt.Errorf("unable to encrypt: %w", err)
	}
	return nil
}
