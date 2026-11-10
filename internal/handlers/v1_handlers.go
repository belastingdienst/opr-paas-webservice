package handlers

import (
	"errors"
	"net/http"

	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	apiv1 "github.com/belastingdienst/opr-paas-webservice/v3/api/v1"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/cryptmgr"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/logging"
	internal "github.com/belastingdienst/opr-paas-webservice/v3/internal/services"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

// V1Encrypt encrypts a secret and returns the encrypted value
func (h *Handler) V1Encrypt(c *gin.Context) {
	var input apiv1.RestEncryptInput
	_, logger := logging.GetLogComponent(c.Request.Context(), logging.EncryptComponent)
	logger.Debug().Msg("entered V1Encrypt")
	if err := c.BindJSON(&input); err != nil {
		logger.Error().Err(err).Msg("failed to parse json")
		return
	}
	secret := []byte(input.Secret)
	if _, err := ssh.ParsePrivateKey(secret); err != nil {
		logger.Error().Err(err).Msg("failed to parse private key")

		c.IndentedJSON(http.StatusOK, apiv1.RestEncryptResult{
			PaasName: input.PaasName, Valid: false,
		})
		return
	}
	cryptObj, err := h.CryptMgr.GetOrCreate(input.PaasName)
	if err != nil {
		logger.Error().Err(err).Msg("failed to load the keys")
		c.IndentedJSON(http.StatusInternalServerError, apiv1.RestEncryptResult{
			PaasName: input.PaasName, Valid: false, Error: errKeysUnavailable,
		})
		return
	}
	encrypted, err := cryptObj.Encrypt(secret)
	if err != nil {
		logger.Error().Err(err).Msg("failed to encrypt")
		c.IndentedJSON(http.StatusInternalServerError, apiv1.RestEncryptResult{
			PaasName: input.PaasName, Valid: false, Error: errEncryptionFailed,
		})
		return
	}
	c.IndentedJSON(http.StatusOK, apiv1.RestEncryptResult{
		PaasName:  input.PaasName,
		Encrypted: encrypted,
		Valid:     true,
	})
}

// V1CheckPaas checks whether a Paas can be decrypted using provided private/public keys
func (h *Handler) V1CheckPaas(c *gin.Context) {
	var input apiv1.RestCheckPaasInput
	_, logger := logging.GetLogComponent(c.Request.Context(), logging.CheckPaasComponent)
	logger.Debug().Msg("entered V1CheckPaas")
	if err := c.BindJSON(&input); err != nil {
		logger.Error().AnErr("error", err).Msg("failed to parse json")
		c.IndentedJSON(http.StatusBadRequest, apiv1.RestCheckPaasResult{Error: err.Error()})
		return
	}
	cryptObj, err := h.checkCrypt(input.Paas.Name)
	if err != nil {
		logger.Error().AnErr("error", err).Msg("cannot check paas")
		status, message := checkUnavailable(err)
		c.IndentedJSON(status, apiv1.RestCheckPaasResult{PaasName: input.Paas.Name, Error: message})
		return
	}
	// Every error CheckPaas returns is a secret that does not decrypt.
	if err = internal.CheckPaas(cryptObj, &input.Paas); err != nil {
		logger.Error().AnErr("error", err).Msg("paas not ok")
		c.IndentedJSON(http.StatusUnprocessableEntity, apiv1.RestCheckPaasResult{
			PaasName: input.Paas.Name, Decrypted: false, Error: err.Error(),
		})
		return
	}
	logger.Debug().Msg("paas ok")
	c.IndentedJSON(http.StatusOK, apiv1.RestCheckPaasResult{
		PaasName: input.Paas.Name, Decrypted: true,
	})
}

// checkCrypt returns the crypt for checking a Paas: cryptmgr.ErrNoPrivateKeys
// when the service runs encrypt-only, or the error loading the keys.
func (h *Handler) checkCrypt(paasName string) (*crypt.Crypt, error) {
	if h.CryptMgr.EncryptOnly() {
		return nil, cryptmgr.ErrNoPrivateKeys
	}
	return h.CryptMgr.GetOrCreate(paasName)
}

// checkUnavailable is the status and message for a check that cannot run:
// 503 when the service runs encrypt-only, 500 when its keys cannot be loaded.
func checkUnavailable(err error) (int, string) {
	if errors.Is(err, cryptmgr.ErrNoPrivateKeys) {
		return http.StatusServiceUnavailable, cryptmgr.ErrNoPrivateKeys.Error()
	}
	return http.StatusInternalServerError, errKeysUnavailable
}
