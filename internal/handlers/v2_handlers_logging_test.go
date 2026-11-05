package handlers

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net/http"
	"testing"

	apiv1 "github.com/belastingdienst/opr-paas-webservice/v3/api/v1"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// captureLogs redirects the global zerolog logger (at debug level) to a buffer for the duration of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf).Level(zerolog.TraceLevel)
	t.Cleanup(func() { log.Logger = orig })
	return &buf
}

func generatePassphraseProtectedKeyPEM(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("correct horse battery staple"))
	require.NoError(t, err)
	return string(pem.EncodeToMemory(block))
}

func TestV2EncryptSSH_DoesNotLogRejectedSecret(t *testing.T) {
	const invalidSecret = "not-a-key-but-still-secret-value"

	tests := []struct {
		name   string
		secret string
	}{
		{name: "invalid key", secret: invalidSecret},
		{name: "passphrase protected key", secret: generatePassphraseProtectedKeyPEM(t)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			h := setupHandler(t)
			r := gin.New()
			r.POST(epv2EncryptSSH, h.V2EncryptSSH)

			w := perform(r, http.MethodPost, epv2EncryptSSH,
				apiv1.RestEncryptInput{PaasName: testPaasName, Secret: tt.secret})

			assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
			assert.Contains(t, logs.String(), "failed to parse private key")
			assert.NotContains(t, logs.String(), tt.secret)
			// Also guard against partial leakage of PEM key material.
			for _, line := range bytes.Split([]byte(tt.secret), []byte("\n")) {
				if len(line) > 20 {
					assert.NotContains(t, logs.String(), string(line))
				}
			}
		})
	}
}
