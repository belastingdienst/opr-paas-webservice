/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package services

import (
	"testing"

	"github.com/belastingdienst/opr-paas-webservice/v3/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/cryptmgr"
	"github.com/belastingdienst/opr-paas-webservice/v3/test/testutils"
	"github.com/stretchr/testify/require"

	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	paasName = "paasName"
	repoName = "ssh://git@scm/some-repo.git"
)

func TestCheckPaas(t *testing.T) {
	pub, priv, cleanup := testutils.MakeCrypt(t)
	t.Cleanup(cleanup)

	cfg := config.NewWSConfig()
	cfg.PublicKeyPath = pub.Name()
	cfg.PrivateKeyPath = priv.Name()

	mgr := cryptmgr.NewManager(&cfg)
	rsa := mgr.GetOrCreate(paasName)

	encrypted, err := rsa.Encrypt([]byte("My test string"))
	require.NoError(t, err)

	toBeDecryptedPaas := &v1alpha2.Paas{
		ObjectMeta: metav1.ObjectMeta{
			Name: paasName,
		},
		Spec: v1alpha2.PaasSpec{
			Secrets: map[string]string{repoName: encrypted},
			Capabilities: v1alpha2.PaasCapabilities{
				"sso": v1alpha2.PaasCapability{
					Secrets: map[string]string{repoName: encrypted},
				},
			},
		},
	}

	err = CheckPaas(rsa, toBeDecryptedPaas)
	require.NoError(t, err)

	notTeBeDecryptedPaas := &v1alpha2.Paas{
		ObjectMeta: metav1.ObjectMeta{
			Name: paasName,
		},
		Spec: v1alpha2.PaasSpec{Secrets: map[string]string{repoName: "bm90RGVjcnlwdGFibGU="}},
	}

	// Must be able to decrypt this
	err = CheckPaas(rsa, notTeBeDecryptedPaas)
	require.Error(t, err)

	partialToBeDecryptedPaas := &v1alpha2.Paas{
		ObjectMeta: metav1.ObjectMeta{
			Name: paasName,
		},
		Spec: v1alpha2.PaasSpec{
			Secrets: map[string]string{repoName: encrypted},
			Capabilities: v1alpha2.PaasCapabilities{
				"sso": v1alpha2.PaasCapability{
					Secrets: map[string]string{repoName: "bm90RGVjcnlwdGFibGU="},
				},
			},
		},
	}

	// Must error as it can be partially decrypted
	err = CheckPaas(rsa, partialToBeDecryptedPaas)
	require.Error(t, err)
}
