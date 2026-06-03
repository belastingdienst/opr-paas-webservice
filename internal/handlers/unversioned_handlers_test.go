/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Tests ---

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
