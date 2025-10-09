/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	apiV1 "github.com/belastingdienst/opr-paas-webservice/api/v1"
	"github.com/belastingdienst/opr-paas-webservice/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/internal/cryptmgr"
	"github.com/belastingdienst/opr-paas-webservice/test/testutils"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

const testPaasName = "paas-a"

// --- Helpers for setting up handler & requests ---

func setupHandler(t *testing.T) *Handler {
	t.Helper()

	pub, priv, cleanup := testutils.MakeCrypt(t)
	t.Cleanup(cleanup)

	cfg := config.NewWSConfig()
	cfg.PublicKeyPath = pub.Name()
	cfg.PrivateKeyPath = priv.Name()

	mgr := cryptmgr.NewManager(&cfg)
	return NewHandler(mgr)
}

func perform(r http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader([]byte{})
	}
	req, _ := http.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// --- Tests ---

func TestV1Encrypt_ValidPrivateKey(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST("/v1/encrypt", h.V1Encrypt)

	// Generate a valid RSA private key in PEM format
	const bits = 2048
	privKeyPEM, err := generateRSAPrivateKeyPEM(bits)
	require.NoError(t, err)

	input := apiV1.RestEncryptInput{PaasName: testPaasName, Secret: privKeyPEM}
	w := perform(r, http.MethodPost, "/apiV1/encrypt", input)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp apiV1.RestEncryptResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Valid, "expected Valid=true for a valid private key")
	assert.Equal(t, testPaasName, resp.PaasName)
	assert.NotEmpty(t, resp.Encrypted, "expected non-empty encrypted payload")
}

func TestV1Encrypt_InvalidPrivateKey(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST("/v1/encrypt", h.V1Encrypt)

	// Not a valid SSH private key
	input := apiV1.RestEncryptInput{PaasName: testPaasName, Secret: "not-a-key"}
	w := perform(r, http.MethodPost, "/apiV1/encrypt", input)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp apiV1.RestEncryptResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Valid, "expected Valid=false for an invalid private key")
	assert.Equal(t, testPaasName, resp.PaasName)
	// For invalid keys, Encrypted is omitted by handler — that’s fine.
}

func TestV1CheckPaas_BadRequest(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST("/v1/checkpaas", h.V1CheckPaas)

	// Send invalid JSON body
	req, _ := http.NewRequest(http.MethodPost, "/v1/checkpaas", bytes.NewBuffer([]byte("{bad-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOperatorVersion(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.GET("/version", h.Version)

	w := perform(r, http.MethodGet, "/version", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	_, ok := resp["version"]
	assert.True(t, ok, "expected version field in response")
}

func TestHealthz(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.GET("/healthz", h.Healthz)

	w := perform(r, http.MethodGet, "/healthz", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "healthy", resp["message"])
}

func TestReadyz(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.GET("/readyz", h.Readyz)

	w := perform(r, http.MethodGet, "/readyz", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "ready", resp["message"])
}

func generateRSAPrivateKeyPEM(bits int) (string, error) {
	// Generate the RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", err
	}

	// Encode the private key to PKCS#1 ASN.1 PEM
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	})

	return string(privPEM), nil
}
