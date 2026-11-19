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
// encrypt-only (PAAS_ENCRYPT_ONLY): it holds no private keys, so nothing can
// be decrypted.
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
	m.logKeySetup()
	return m
}

// logKeySetup logs how the service uses its keys, and warns about a setup
// that does not match: private keys mounted in encrypt-only mode, or missing
// private keys without it.
func (m *Manager) logKeySetup() {
	_, err := os.Stat(m.cfg.PrivateKeyPath)
	privateKeysExist := m.cfg.PrivateKeyPath != "" && !errors.Is(err, os.ErrNotExist)
	switch {
	case m.EncryptOnly() && privateKeysExist:
		log.Printf("WARNING: running encrypt-only, the check endpoints are disabled; "+
			"the private keys at %q are not used and should not be mounted", m.cfg.PrivateKeyPath)
	case m.EncryptOnly():
		log.Println("running encrypt-only, the check endpoints are disabled")
	case !privateKeysExist:
		log.Printf("ERROR: no private keys at %q: requests fail until they are mounted; "+
			"set PAAS_ENCRYPT_ONLY=true to run without private keys", m.cfg.PrivateKeyPath)
	}
}

// EncryptOnly reports whether the service runs without private keys
// (PAAS_ENCRYPT_ONLY). It then encrypts with the public key alone and cannot
// decrypt.
func (m *Manager) EncryptOnly() bool {
	return m.cfg.EncryptOnly
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
		var privateKeyPath string // empty paths are not watched
		if !m.EncryptOnly() {
			privateKeyPath = m.cfg.PrivateKeyPath
		}
		m.fw = utils.NewFileWatcher(privateKeyPath, m.cfg.PublicKeyPath)
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

// Ready returns an error when the service cannot do its job with the keys on
// disk now (not the cache): the keys cannot be loaded, or, when it runs
// encrypt-only, they cannot encrypt.
//
// With private keys, a crypt that cannot encrypt still makes the service
// ready. During a key rotation the keys directory may hold two private keys
// and no public key: the check endpoints still work then, and only the encrypt
// endpoints answer 500. Every replica reads the same keys, so failing
// readiness would take the whole service out of traffic.
func (m *Manager) Ready() error {
	c, err := m.build(readinessPaasName)
	if err != nil {
		return err
	}
	if !m.EncryptOnly() {
		return nil
	}
	if _, err = c.Encrypt([]byte(readinessPaasName)); err != nil {
		return fmt.Errorf("unable to encrypt: %w", err)
	}
	return nil
}
