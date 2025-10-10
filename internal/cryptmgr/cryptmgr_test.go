package cryptmgr

import (
	"testing"

	"github.com/belastingdienst/opr-paas-webservice/v3/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/v3/test/testutils"
	"github.com/stretchr/testify/assert"
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
