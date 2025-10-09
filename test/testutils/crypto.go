/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package testutils

import (
	"os"
	"testing"

	"github.com/belastingdienst/opr-paas-crypttool/pkg/crypt"
	"github.com/stretchr/testify/require"
)

// MakeCrypt is a helper to create a Crypt for testing
func MakeCrypt(t *testing.T) (pub, priv *os.File, toDefer func()) {
	// generate private/public keys
	t.Log("creating temp private key")
	priv, err := os.CreateTemp("", "private")
	require.NoError(t, err, "Creating tempfile for private key")

	t.Log("creating temp public key")
	pub, err = os.CreateTemp("", "public")
	require.NoError(t, err, "Creating tempfile for public key")

	// Set env for ws Config
	t.Setenv("PAAS_PUBLIC_KEY_PATH", pub.Name())    //nolint:errcheck // this is fine in test
	t.Setenv("PAAS_PRIVATE_KEYS_PATH", priv.Name()) //nolint:errcheck // this is fine in test

	// Generate keyPair to be used during test
	crypt.GenerateKeyPair(priv.Name(), pub.Name()) //nolint:errcheck // this is fine in test

	return pub, priv, func() { // clean up function
		os.Remove(priv.Name())
		os.Remove(pub.Name())
	}
}
