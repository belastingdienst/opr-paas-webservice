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
	epv2Encrypt    = "/v2/encrypt"
	epv2EncryptSSH = "/v2/encryptSSH"
	epv2check      = "/v2/checkpaas"
)

func TestV2EncryptSSH_ValidPrivateKey(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST(epv2EncryptSSH, h.V2EncryptSSH)

	// Generate a valid RSA private key in PEM format
	const bits = 2048
	privKeyPEM, err := generateRSAPrivateKeyPEM(bits)
	require.NoError(t, err)

	input := apiv1.RestEncryptInput{PaasName: testPaasName, Secret: privKeyPEM}
	w := perform(r, http.MethodPost, epv2EncryptSSH, input)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp apiv1.RestEncryptResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Valid, "expected Valid=true for a valid private key")
	assert.Equal(t, testPaasName, resp.PaasName)
	assert.NotEmpty(t, resp.Encrypted, "expected non-empty encrypted payload")
}

func TestV2EncryptSSH_InvalidPrivateKey(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST(epv2EncryptSSH, h.V2EncryptSSH)

	// Not a valid SSH private key
	input := apiv1.RestEncryptInput{PaasName: testPaasName, Secret: "not-a-key"}
	w := perform(r, http.MethodPost, epv2EncryptSSH, input)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Len(t, w.Body.Bytes(), 0)
}

func TestV2EncryptSSH_InvalidJSON(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST(epv2EncryptSSH, h.V2EncryptSSH)

	// Not a valid SSH private key
	// w := perform(r, http.MethodPost, epv2Encrypt, bytes.NewBuffer([]byte("{bad-json")))
	w := perform(r, http.MethodPost, epv2EncryptSSH, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	require.Len(t, w.Body.Bytes(), 0)
}

func TestV2Encrypt_ValidPrivateKey(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST(epv2Encrypt, h.V2Encrypt)

	// This can be any secret value
	const secret = "can be anything, even with $, # and & signs, \t, and \n"

	input := apiv1.RestEncryptInput{PaasName: testPaasName, Secret: secret}
	w := perform(r, http.MethodPost, epv2Encrypt, input)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp apiv1.RestEncryptResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Valid, "expected Valid=true for a valid private key")
	assert.Equal(t, testPaasName, resp.PaasName)
	assert.NotEmpty(t, resp.Encrypted, "expected non-empty encrypted payload")
}

func TestV2Encrypt_InvalidJSON(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST(epv2Encrypt, h.V2Encrypt)

	w := perform(r, http.MethodPost, epv2Encrypt, nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	require.Len(t, w.Body.Bytes(), 0)
}

func TestV2CheckPaas_Valid(t *testing.T) {
	h := setupHandler(t)

	var (
		secret    = "secret"
		encrypted string
	)
	encrypted, err := h.CryptMgr.GetOrCreate(testPaasName).Encrypt([]byte(secret))
	require.NoError(t, err)

	r := gin.New()
	r.POST(epv2check, h.V2CheckPaas)

	paas := v1alpha2.Paas{
		Spec: v1alpha2.PaasSpec{
			Secrets: map[string]string{
				"some": encrypted,
			},
		},
	}
	paas.Name = testPaasName
	w := perform(r, http.MethodPost, epv2check, apiv1.RestCheckPaasInput{Paas: paas})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp apiv1.RestCheckPaasResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Decrypted, "expected Decrypted=true for a valid private key")
	assert.Equal(t, testPaasName, resp.PaasName)
	assert.Empty(t, resp.Error, "expected no error message")
}

func TestV2CheckPaas_InvalidSecret(t *testing.T) {
	h := setupHandler(t)

	var (
		encrypted = "this is not yet encrypted"
	)
	r := gin.New()
	r.POST(epv2check, h.V2CheckPaas)

	paas := v1alpha2.Paas{
		Spec: v1alpha2.PaasSpec{
			Secrets: map[string]string{
				"some": encrypted,
			},
		},
	}
	paas.Name = testPaasName
	w := perform(r, http.MethodPost, epv2check, apiv1.RestCheckPaasInput{Paas: paas})

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestV2CheckPaas_BadRequest(t *testing.T) {
	h := setupHandler(t)
	r := gin.New()
	r.POST(epv2check, h.V2CheckPaas)

	// Send invalid JSON body
	req, _ := http.NewRequest(http.MethodPost, epv2check, nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
