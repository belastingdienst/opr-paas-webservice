package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	apiv1 "github.com/belastingdienst/opr-paas-webservice/v3/api/v1"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/cryptmgr"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyFiles generates a key pair in dir and returns the private and public key paths.
func keyFiles(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	priv, pub := filepath.Join(dir, name), filepath.Join(dir, name+".pub")
	require.NoError(t, crypt.GenerateKeyPair(priv, pub))
	return priv, pub
}

// handlerFor returns a handler for the given key paths.
func handlerFor(privateKeyPath, publicKeyPath string) *Handler {
	cfg := config.WsConfig{PrivateKeyPath: privateKeyPath, PublicKeyPath: publicKeyPath}
	return NewHandler(cryptmgr.NewManager(&cfg))
}

// router routes every endpoint without gin.Recovery, so a panic fails the test.
func router(h *Handler) *gin.Engine {
	r := gin.New()
	r.POST(epv1Encrypt, h.V1Encrypt)
	r.POST("/v2/encrypt", h.V2Encrypt)
	r.POST("/v2/encryptSSH", h.V2EncryptSSH)
	r.POST(epv1check, h.V1CheckPaas)
	r.POST("/v2/checkpaas", h.V2CheckPaas)
	r.GET("/readyz", h.Readyz)
	return r
}

func sshKey(t *testing.T) string {
	t.Helper()
	key, err := generateRSAPrivateKeyPEM(2048)
	require.NoError(t, err)
	return key
}

func paasWithSecret(secret string) apiv1.RestCheckPaasInput {
	paas := v1alpha2.Paas{Spec: v1alpha2.PaasSpec{Secrets: map[string]string{"some": secret}}}
	paas.Name = testPaasName
	return apiv1.RestCheckPaasInput{Paas: paas}
}

// Without private keys (the opr-paas manifest mounts only the public key) the
// service encrypts, and only the private key outside the service decrypts.
func TestEncryptOnlyEncrypts(t *testing.T) {
	dir := t.TempDir()
	priv, pub := keyFiles(t, dir, "key")
	r := router(handlerFor(filepath.Join(dir, "missing"), pub))
	key := sshKey(t)

	for _, path := range []string{epv1Encrypt, "/v2/encrypt", "/v2/encryptSSH"} {
		w := perform(r, http.MethodPost, path, apiv1.RestEncryptInput{PaasName: testPaasName, Secret: key})
		require.Equal(t, http.StatusOK, w.Code, path)
		var resp apiv1.RestEncryptResult
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), path)
		require.True(t, resp.Valid, path)

		decrypter, err := crypt.NewCryptFromFiles([]string{priv}, "", testPaasName)
		require.NoError(t, err)
		plain, err := decrypter.Decrypt(resp.Encrypted)
		require.NoError(t, err, path)
		assert.Equal(t, key, string(plain), path)
	}
}

func TestEncryptOnlyDisablesTheCheck(t *testing.T) {
	dir := t.TempDir()
	_, pub := keyFiles(t, dir, "key")
	r := router(handlerFor(filepath.Join(dir, "missing"), pub))

	for _, path := range []string{epv1check, "/v2/checkpaas"} {
		w := perform(r, http.MethodPost, path, paasWithSecret("anything"))
		assert.Equal(t, http.StatusServiceUnavailable, w.Code, path)
		var resp apiv1.RestCheckPaasResult
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), path)
		assert.Equal(t, cryptmgr.ErrNoPrivateKeys.Error(), resp.Error, path)
	}
}

// Keys that cannot be loaded give 500 on every endpoint, with a fixed message:
// the file paths in the underlying error stay in the log.
func TestUnloadableKeysAnswer500(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "broken")
	require.NoError(t, os.WriteFile(priv, []byte("not a key"), 0o600))
	r := router(handlerFor(priv, ""))
	key := sshKey(t)

	for _, path := range []string{epv1Encrypt, "/v2/encrypt", "/v2/encryptSSH"} {
		w := perform(r, http.MethodPost, path, apiv1.RestEncryptInput{PaasName: testPaasName, Secret: key})
		assert.Equal(t, http.StatusInternalServerError, w.Code, path)
		assert.NotContains(t, w.Body.String(), dir, path)
	}
	w := perform(r, http.MethodPost, epv1Encrypt, apiv1.RestEncryptInput{PaasName: testPaasName, Secret: key})
	var resp apiv1.RestEncryptResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, errKeysUnavailable, resp.Error)

	for _, path := range []string{epv1check, "/v2/checkpaas"} {
		w := perform(r, http.MethodPost, path, paasWithSecret("anything"))
		assert.Equal(t, http.StatusInternalServerError, w.Code, path)
		assert.NotContains(t, w.Body.String(), dir, path)
	}
}

// During a key rotation the keys directory holds two keys and there is no
// public key: encryption fails, and v1 says so instead of answering an empty 200.
func TestV1EncryptFailureIsNotAnEmptySuccess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "privateKeys")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	keyFiles(t, dir, "old")
	keyFiles(t, dir, "new")
	require.NoError(t, os.Remove(filepath.Join(dir, "old.pub")))
	require.NoError(t, os.Remove(filepath.Join(dir, "new.pub")))
	r := router(handlerFor(dir, ""))

	w := perform(r, http.MethodPost, epv1Encrypt, apiv1.RestEncryptInput{PaasName: testPaasName, Secret: sshKey(t)})
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp apiv1.RestEncryptResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Valid)
	assert.Equal(t, errEncryptionFailed, resp.Error)
}

// A secret that does not decrypt is 422, whatever the decryption error says:
// not base64, for other keys, or too short to be a ciphertext.
func TestASecretThatDoesNotDecryptIs422(t *testing.T) {
	dir := t.TempDir()
	priv, pub := keyFiles(t, dir, "key")
	otherDir := t.TempDir()
	_, otherPub := keyFiles(t, otherDir, "other")
	other, err := crypt.NewCryptFromFiles(nil, otherPub, testPaasName)
	require.NoError(t, err)
	foreign, err := other.Encrypt([]byte("for another key"))
	require.NoError(t, err)
	r := router(handlerFor(priv, pub))

	for name, secret := range map[string]string{
		"not base64":  "this is not yet encrypted",
		"another key": foreign,
		"too short":   base64.StdEncoding.EncodeToString([]byte("short")),
	} {
		for _, path := range []string{epv1check, "/v2/checkpaas"} {
			w := perform(r, http.MethodPost, path, paasWithSecret(secret))
			assert.Equal(t, http.StatusUnprocessableEntity, w.Code, "%s %s", name, path)
		}
	}
}

func TestReadyzReflectsTheKeys(t *testing.T) {
	dir := t.TempDir()
	priv, pub := keyFiles(t, dir, "key")
	broken := filepath.Join(dir, "broken")
	require.NoError(t, os.WriteFile(broken, []byte("not a key"), 0o600))

	for name, tc := range map[string]struct {
		priv, pub string
		status    int
	}{
		"private and public key": {priv, pub, http.StatusOK},
		"encrypt-only":           {filepath.Join(dir, "missing"), pub, http.StatusOK},
		"unloadable private key": {broken, "", http.StatusServiceUnavailable},
		"no key at all":          {filepath.Join(dir, "missing"), "", http.StatusServiceUnavailable},
		"unloadable public key":  {filepath.Join(dir, "missing"), broken, http.StatusServiceUnavailable},
	} {
		w := perform(router(handlerFor(tc.priv, tc.pub)), http.MethodGet, "/readyz", nil)
		assert.Equal(t, tc.status, w.Code, name)
	}
}
