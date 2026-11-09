/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package logging

import (
	"io"
	"os"
	"regexp"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Redacted replaces sensitive values in log output.
const Redacted = "[REDACTED]"

var (
	// sensitiveFieldRe matches JSON string fields whose key suggests a sensitive value, e.g.
	// "secret":"...", "client_secret":"...", "Authorization":"...". Only the value is replaced.
	sensitiveFieldRe = regexp.MustCompile(
		`(?i)("[a-z0-9_.-]*(?:secret|password|passwd|passphrase|token|authorization|private_?key|api_?key)` +
			`[a-z0-9_.-]*"\s*:\s*)"(?:[^"\\]|\\.)*"`,
	)
	// privateKeyBlockRe matches complete PEM / OpenSSH private key blocks, anywhere in a line.
	privateKeyBlockRe = regexp.MustCompile(
		`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`,
	)
	// privateKeyStartRe matches a private key block without an END marker (e.g. a truncated key),
	// up to the end of the JSON string it is in.
	privateKeyStartRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:[^"\\]|\\.)*`)
)

// Redact masks sensitive values in a (JSON) log line:
//   - the values of string fields with a sensitive key (secret, password, token, authorization, ...)
//   - private key blocks, in any field or message
//
// It is a safety net: code should never log secrets in the first place.
func Redact(line []byte) []byte {
	line = sensitiveFieldRe.ReplaceAll(line, []byte(`${1}"`+Redacted+`"`))
	line = privateKeyBlockRe.ReplaceAll(line, []byte(Redacted))
	return privateKeyStartRe.ReplaceAll(line, []byte(Redacted))
}

type redactingWriter struct {
	out io.Writer
}

// NewRedactingWriter returns a writer that applies Redact to everything written to it before passing it on to out.
func NewRedactingWriter(out io.Writer) io.Writer {
	return redactingWriter{out: out}
}

// Write redacts p and writes it to the underlying writer. zerolog writes one log line per call.
func (w redactingWriter) Write(p []byte) (int, error) {
	if _, err := w.out.Write(Redact(p)); err != nil {
		return 0, err
	}
	// Report the original length, as the caller expects all of p to be consumed
	return len(p), nil
}

// ConfigureGlobalLogger makes the global zerolog logger write redacted output to stderr.
func ConfigureGlobalLogger() {
	log.Logger = zerolog.New(NewRedactingWriter(os.Stderr)).With().Timestamp().Logger()
}
