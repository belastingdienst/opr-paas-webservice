package cryptmgr

import (
	"testing"

	"github.com/belastingdienst/opr-paas-webservice/v3/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/v3/test/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOrCreate(t *testing.T) {
	pub, priv, cleanup := testutils.MakeCrypt(t)
	defer cleanup()

	cfg := config.NewWSConfig()
	cfg.PublicKeyPath = pub.Name()
	cfg.PrivateKeyPath = priv.Name()

	mgr := NewManager(&cfg)

	// first call should create a new crypt
	c, err := mgr.GetOrCreate("paasName")
	require.NoError(t, err)
	assert.NotNil(t, c)

	// second call should return cached
	c2, err := mgr.GetOrCreate("paasName")
	require.NoError(t, err)
	assert.Equal(t, c, c2)
}
