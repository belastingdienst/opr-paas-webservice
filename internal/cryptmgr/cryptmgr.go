package cryptmgr

import (
	"fmt"
	"log"
	"sync"

	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/utils"
)

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
	return &Manager{
		cache: make(map[string]*crypt.Crypt),
		cfg:   cfg,
	}
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

// GetOrCreate returns a crypt based on the paasName
func (m *Manager) GetOrCreate(paasName string) *crypt.Crypt {
	generation := m.watcher().Generation()
	if c := m.get(paasName, generation); c != nil {
		return c // cache hit, the key files did not change
	}

	c, err := crypt.NewCryptFromFiles([]string{m.cfg.PrivateKeyPath}, m.cfg.PublicKeyPath, paasName)
	if err != nil {
		panic(fmt.Errorf("unable to create a crypt: %w", err))
	}
	m.put(paasName, c, generation)
	return c
}
