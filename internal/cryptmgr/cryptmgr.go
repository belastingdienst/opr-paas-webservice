package cryptmgr

import (
	"fmt"
	"log"
	"sync"

	"github.com/belastingdienst/opr-paas-crypttool/pkg/crypt"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/utils"
)

// Manager is struct to manage crypts
type Manager struct {
	mu    sync.RWMutex
	cache map[string]*crypt.Crypt
	fw    *utils.FileWatcher
	cfg   *config.WsConfig
}

// NewManager returns a new Manager based on the provided WsConfig
func NewManager(cfg *config.WsConfig) *Manager {
	return &Manager{
		cache: make(map[string]*crypt.Crypt),
		cfg:   cfg,
	}
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

// GetOrCreate returns a crypt based on the paasName
func (m *Manager) GetOrCreate(paasName string) *crypt.Crypt {
	if m.fw == nil {
		log.Println("Starting watcher")
		m.fw = utils.NewFileWatcher(m.cfg.PrivateKeyPath, m.cfg.PublicKeyPath)
	}
	if m.fw.WasTriggered() || len(m.cache) == 0 {
		m.reset()
	}
	if c := m.get(paasName); c != nil {
		return c
	}

	c, err := crypt.NewCryptFromFiles([]string{m.cfg.PrivateKeyPath}, m.cfg.PublicKeyPath, paasName)
	if err != nil {
		panic(fmt.Errorf("unable to create a crypt: %w", err))
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache[paasName] = c
	return c
}
