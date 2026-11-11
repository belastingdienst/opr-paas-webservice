package cryptmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/v3/test/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	dirMode           = 0o700
	concurrentCallers = 20
	paasNames         = 4
	lastVersion       = 4 // three ConfigMap updates after the first mount
	waitForRotation   = 2 * time.Second
	pollInterval      = 10 * time.Millisecond
)

func Test_GetOrCreate(t *testing.T) {
	pub, priv, cleanup := testutils.MakeCrypt(t)
	defer cleanup()

	cfg := config.NewWSConfig()
	cfg.PublicKeyPath = pub.Name()
	cfg.PrivateKeyPath = priv.Name()

	mgr := NewManager(&cfg)

	// first call should create a new crypt
	c := mgr.GetOrCreate("paasName")
	assert.NotNil(t, c)

	// second call should return cached
	c2 := mgr.GetOrCreate("paasName")
	assert.Equal(t, c, c2)
}

// Concurrent first requests start one watcher and share the cache safely
// (run with -race).
func Test_GetOrCreateConcurrently(t *testing.T) {
	pub, priv, cleanup := testutils.MakeCrypt(t)
	defer cleanup()
	cfg := config.NewWSConfig()
	cfg.PublicKeyPath = pub.Name()
	cfg.PrivateKeyPath = priv.Name()
	mgr := NewManager(&cfg)

	var wg sync.WaitGroup
	for i := range concurrentCallers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NotNil(t, mgr.GetOrCreate(fmt.Sprintf("paas%d", i%paasNames)))
		}()
	}
	wg.Wait()
	assert.Same(t, mgr.GetOrCreate("paas0"), mgr.GetOrCreate("paas0"))
}

// rotatePublicKey lays out dir the way the kubelet updates a mounted
// ConfigMap: a new timestamped directory, then an atomic swap of `..data`.
// It returns the private key that belongs to the new public key.
func rotatePublicKey(t *testing.T, dir string, version int) string {
	t.Helper()
	versioned := fmt.Sprintf("..2026_11_11_%02d", version)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, versioned), dirMode))
	privateKey := filepath.Join(t.TempDir(), "privateKey")
	require.NoError(t, crypt.GenerateKeyPair(privateKey, filepath.Join(dir, versioned, "publicKey")))
	tmpLink := filepath.Join(dir, "..data_tmp")
	require.NoError(t, os.Symlink(versioned, tmpLink))
	require.NoError(t, os.Rename(tmpLink, filepath.Join(dir, "..data")))
	if version == 1 {
		require.NoError(t, os.Symlink(filepath.Join("..data", "publicKey"), filepath.Join(dir, "publicKey")))
	} else {
		require.NoError(t, os.RemoveAll(filepath.Join(dir, fmt.Sprintf("..2026_11_11_%02d", version-1))))
	}
	return privateKey
}

// encryptsFor reports whether a secret encrypted by c decrypts with privateKey.
func encryptsFor(t *testing.T, c *crypt.Crypt, privateKey string) bool {
	t.Helper()
	encrypted, err := c.Encrypt([]byte("secret"))
	require.NoError(t, err)
	decrypter, err := crypt.NewCryptFromFiles([]string{privateKey}, "", "paasName")
	require.NoError(t, err)
	_, err = decrypter.Decrypt(encrypted)
	return err == nil
}

// After a ConfigMap update of the public key the next request encrypts with
// the new key, three rotations in a row.
func Test_ARotatedPublicKeyIsUsed(t *testing.T) {
	_, priv, cleanup := testutils.MakeCrypt(t)
	defer cleanup()
	publicDir := t.TempDir()
	privateKey := rotatePublicKey(t, publicDir, 1)

	cfg := config.NewWSConfig()
	cfg.PublicKeyPath = filepath.Join(publicDir, "publicKey")
	cfg.PrivateKeyPath = priv.Name()
	mgr := NewManager(&cfg)
	require.True(t, encryptsFor(t, mgr.GetOrCreate("paasName"), privateKey))

	for version := 2; version <= lastVersion; version++ {
		privateKey = rotatePublicKey(t, publicDir, version)
		require.Eventually(t, func() bool { return encryptsFor(t, mgr.GetOrCreate("paasName"), privateKey) },
			waitForRotation, pollInterval, "rotation %d is used", version-1)
	}
}
