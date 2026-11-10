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
	mu         sync.RWMutex
	cache      map[string]*crypt.Crypt
	generation uint64 // the watcher generation the cached crypts were built at
	watchOnce  sync.Once
	fw         *utils.FileWatcher
	cfg        *config.WsConfig
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

// watcher starts the file watcher on first use, once.
func (m *Manager) watcher() *utils.FileWatcher {
	m.watchOnce.Do(func() {
		log.Println("Starting watcher")
		m.fw = utils.NewFileWatcher(m.cfg.PrivateKeyPath, m.cfg.PublicKeyPath)
	})
	return m.fw
}

// get returns the cached crypt for paas when the cache was built at generation.
func (m *Manager) get(paas string, generation uint64) *crypt.Crypt {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.generation != generation {
		return nil
	}
	return m.cache[paas]
}

// put caches c, built after the watcher reached generation. A newer generation
// empties the cache first; a crypt built before a change the cache already
// reflects is not stored.
func (m *Manager) put(paas string, c *crypt.Crypt, generation uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if generation < m.generation {
		return
	}
	if generation > m.generation {
		log.Println("Key files changed: resetting crypt cache")
		m.cache = make(map[string]*crypt.Crypt)
		m.generation = generation
	}
	m.cache[paas] = c
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
	generation := m.watcher().Generation()
	if c := m.get(paasName, generation); c != nil {
		return c, nil // cache hit, the key files did not change
	}

	c, err := m.build(paasName)
	if err != nil {
		return nil, err
	}
	m.put(paasName, c, generation)
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
