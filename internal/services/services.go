/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package services

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"

	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	"github.com/sirupsen/logrus"
)

// CheckPaas determines whether a Paas can be decrypted using the provided crypt
// it returns an error containing which secrets cannot be decrypted if any
func CheckPaas(cryptObj *crypt.Crypt, paas *v1alpha2.Paas) error {
	var allErrors []string
	for key, secret := range paas.Spec.Secrets {
		decrypted, err := cryptObj.Decrypt(secret)
		if err != nil {
			errMessage := fmt.Errorf("%s: .spec.Secrets[%s], error: %w", paas.Name, key, err)
			logrus.Error(errMessage)
			allErrors = append(allErrors, errMessage.Error())
		} else {
			logrus.Infof(
				"%s: .spec.Secrets[%s], checksum: %s, len %d",
				paas.Name,
				key,
				hashData(decrypted),
				len(decrypted),
			)
		}
	}

	for capName, capability := range paas.Spec.Capabilities {
		logrus.Debugf("capability name: %s", capName)
		for key, secret := range capability.Secrets {
			decrypted, err := cryptObj.Decrypt(secret)
			if err != nil {
				errMessage := fmt.Errorf(
					"%s: .spec.capabilities[%s].Secrets[%s], error: %w",
					paas.Name,
					capName,
					key,
					err,
				)
				logrus.Error(errMessage)
				allErrors = append(allErrors, errMessage.Error())
			} else {
				logrus.Infof("%s: .spec.capabilities[%s].Secrets[%s], checksum: %s, len %d.",
					paas.Name,
					capName,
					key,
					hashData(decrypted),
					len(decrypted),
				)
			}
		}
	}
	if len(allErrors) > 0 {
		errorString := strings.Join(allErrors, " , ")
		return errors.New(errorString)
	}
	return nil
}

func hashData(original []byte) string {
	sum := sha512.Sum512(original)
	return hex.EncodeToString(sum[:])
}
