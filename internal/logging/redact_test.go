package logging

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func newPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	return string(pem.EncodeToMemory(block))
}

// logLine writes one log line through a redacting writer and returns the parsed output.
func logLine(t *testing.T, write func(zerolog.Logger)) (string, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	write(zerolog.New(NewRedactingWriter(&buf)))
	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry), "redacted output must stay valid JSON: %s", buf.String())
	return buf.String(), entry
}

func TestRedactSensitiveFields(t *testing.T) {
	const value = `sup3r "s3cret" \ value`
	for _, key := range []string{
		"secret", "Secret", "client_secret", "password", "passphrase", "token", "access_token",
		"authorization", "Authorization", "private_key", "privateKey", "api_key", "apiKey",
	} {
		t.Run(key, func(t *testing.T) {
			raw, entry := logLine(t, func(l zerolog.Logger) { l.Info().Str(key, value).Msg("msg") })
			assert.Equal(t, Redacted, entry[key])
			assert.NotContains(t, raw, "sup3r")
		})
	}
}

func TestRedactKeepsOtherFields(t *testing.T) {
	_, entry := logLine(t, func(l zerolog.Logger) {
		l.Info().Str("paas", "my-paas").Str("path", "/v2/encrypt").Int("token_count", 3).Msg("hello")
	})
	assert.Equal(t, "my-paas", entry["paas"])
	assert.Equal(t, "/v2/encrypt", entry["path"])
	assert.InDelta(t, 3, entry["token_count"], 0, "non-string values are left alone")
	assert.Equal(t, "hello", entry["message"])
}

func TestRedactPrivateKeyAnywhere(t *testing.T) {
	key := newPrivateKeyPEM(t)
	body := strings.Split(strings.TrimSpace(key), "\n")[1]

	tests := map[string]func(zerolog.Logger){
		"innocent field name": func(l zerolog.Logger) { l.Info().Str("input", key).Msg("") },
		"message":             func(l zerolog.Logger) { l.Info().Msg("got " + key) },
		"error":               func(l zerolog.Logger) { l.Error().Err(errors.New("bad key: " + key)).Msg("") },
		"truncated key":       func(l zerolog.Logger) { l.Info().Str("input", key[:len(key)/2]).Msg("") },
	}
	for name, write := range tests {
		t.Run(name, func(t *testing.T) {
			raw, _ := logLine(t, write)
			assert.Contains(t, raw, Redacted)
			assert.NotContains(t, raw, body)
		})
	}
}

func TestRedactingWriterReportsOriginalLength(t *testing.T) {
	var buf bytes.Buffer
	in := []byte(`{"secret":"a much longer value than the redaction marker"}`)
	n, err := NewRedactingWriter(&buf).Write(in)
	require.NoError(t, err)
	assert.Equal(t, len(in), n)
	assert.JSONEq(t, `{"secret":"[REDACTED]"}`, buf.String())
}
