/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/belastingdienst/opr-paas-webservice/v3/internal/config"
	v "github.com/belastingdienst/opr-paas-webservice/v3/internal/version"
	"github.com/belastingdienst/opr-paas-webservice/v3/test/testutils"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// Build a working config for router tests
func newTestConfig(t *testing.T) *config.WsConfig {
	t.Helper()

	// Generate ephemeral key files so cryptmgr.NewManager(cfg) is happy.
	pub, priv, cleanup := testutils.MakeCrypt(t)
	t.Cleanup(cleanup)

	cfg := config.NewWSConfig()
	cfg.PublicKeyPath = pub.Name()
	cfg.PrivateKeyPath = priv.Name()
	// Allow all origins to exercise AllowAllOrigins branch
	cfg.AllowedOrigins = []string{"*"}
	return &cfg
}

func TestNoSniffIsSet(t *testing.T) {
	cfg := newTestConfig(t)
	router := NewRouter(cfg)

	w := performRequest(router, http.MethodGet, "/version")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
}

func Test_version(t *testing.T) {
	cfg := newTestConfig(t)
	router := NewRouter(cfg)

	w := performRequest(router, http.MethodGet, "/version")
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	value, exists := response["version"]
	assert.True(t, exists, "expected version key")
	assert.Equal(t, v.PaasWebserviceVersion, value)
}

// PerformRequest is a helper function for testing
func performRequest(r http.Handler, method, path string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}
