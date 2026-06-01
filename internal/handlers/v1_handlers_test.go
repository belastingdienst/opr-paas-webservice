package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	apiv1 "github.com/belastingdienst/opr-paas-webservice/v3/api/v1"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	epv1Encrypt = "/v1/encrypt"
	epv1check   = "/v1/checkpaas"
)

func TestV1Encrypt_ValidPrivateKey(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST(epv1Encrypt, h.V1Encrypt)

	// Generate a valid RSA private key in PEM format
	const bits = 2048
	privKeyPEM, err := generateRSAPrivateKeyPEM(bits)
	require.NoError(t, err)

	input := apiv1.RestEncryptInput{PaasName: testPaasName, Secret: privKeyPEM}
	w := perform(r, http.MethodPost, epv1Encrypt, input)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp apiv1.RestEncryptResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Valid, "expected Valid=true for a valid private key")
	assert.Equal(t, testPaasName, resp.PaasName)
	assert.NotEmpty(t, resp.Encrypted, "expected non-empty encrypted payload")
}

func TestV1Encrypt_InvalidPrivateKey(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST(epv1Encrypt, h.V1Encrypt)

	// Not a valid SSH private key
	input := apiv1.RestEncryptInput{PaasName: testPaasName, Secret: "not-a-key"}
	w := perform(r, http.MethodPost, epv1Encrypt, input)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp apiv1.RestEncryptResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Valid, "expected Valid=false for an invalid private key")
	assert.Equal(t, testPaasName, resp.PaasName)
	// For invalid keys, Encrypted is omitted by handler — that’s fine.
}

func TestV1Encrypt_InvalidJSON(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST(epv1Encrypt, h.V1Encrypt)

	// Not a valid SSH private key
	w := perform(r, http.MethodPost, epv1Encrypt, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	require.Len(t, w.Body.Bytes(), 0)
}

func TestV1CheckPaas_Valid(t *testing.T) {
	h := setupHandler(t)

	var (
		secret    = "secret"
		encrypted string
	)
	encrypted, err := h.CryptMgr.GetOrCreate(testPaasName).Encrypt([]byte(secret))
	require.NoError(t, err)

	r := gin.New()
	r.POST(epv1check, h.V1CheckPaas)

	paas := v1alpha2.Paas{
		Spec: v1alpha2.PaasSpec{
			Secrets: map[string]string{
				"some": encrypted,
			},
		},
	}
	paas.Name = testPaasName
	w := perform(r, http.MethodPost, epv1check, apiv1.RestCheckPaasInput{Paas: paas})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp apiv1.RestCheckPaasResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Decrypted, "expected Decrypted=true for a valid private key")
	assert.Equal(t, testPaasName, resp.PaasName)
	assert.Empty(t, resp.Error, "expected no error message")
}

func TestV1CheckPaas_InvalidSecret(t *testing.T) {
	h := setupHandler(t)

	var (
		encrypted = "this is not yet encrypted"
	)
	r := gin.New()
	r.POST(epv1check, h.V1CheckPaas)

	paas := v1alpha2.Paas{
		Spec: v1alpha2.PaasSpec{
			Secrets: map[string]string{
				"some": encrypted,
			},
		},
	}
	paas.Name = testPaasName
	w := perform(r, http.MethodPost, epv1check, apiv1.RestCheckPaasInput{Paas: paas})

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	var resp apiv1.RestCheckPaasResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Decrypted, "expected Decrypted=true for a valid private key")
	assert.Equal(t, testPaasName, resp.PaasName)
	assert.Contains(t, resp.Error, "illegal base64 data", "expected no error message")
}

func TestV1CheckPaas_BadRequest(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST(epv1check, h.V1CheckPaas)

	// Send invalid JSON body
	req, _ := http.NewRequest(http.MethodPost, epv1check, nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
