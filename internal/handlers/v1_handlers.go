package handlers

import (
	"net/http"
	"strings"

	apiv1 "github.com/belastingdienst/opr-paas-webservice/v3/api/v1"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/logging"
	internal "github.com/belastingdienst/opr-paas-webservice/v3/internal/services"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

// V1Encrypt encrypts a secret and returns the encrypted value
func (h *Handler) V1Encrypt(c *gin.Context) {
	var input apiv1.RestEncryptInput
	_, logger := logging.SetWebserviceLogger(c.Request)
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
	encrypted, err := h.CryptMgr.GetOrCreate(input.PaasName).Encrypt(secret)
	if err != nil {
		logger.Error().Err(err).Msg("failed to encrypt")
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
	_, logger := logging.SetWebserviceLogger(c.Request)
	logger.Debug().Msg("entered V1CheckPaas")
	if err := c.BindJSON(&input); err != nil {
		logger.Error().AnErr("error", err).Msg("failed to parse json")
		c.IndentedJSON(http.StatusBadRequest, apiv1.RestCheckPaasResult{Error: err.Error()})
		return
	}
	rsa := h.CryptMgr.GetOrCreate(input.Paas.Name)
	err := internal.CheckPaas(rsa, &input.Paas)
	if err != nil {
		logger.Error().AnErr("error", err).Msg("paas not ok")
		if strings.Contains(err.Error(), "unable to decrypt data") ||
			strings.Contains(err.Error(), "base64") {
			c.IndentedJSON(http.StatusUnprocessableEntity, apiv1.RestCheckPaasResult{
				PaasName: input.Paas.Name, Decrypted: false, Error: err.Error(),
			})
			return
		}
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	logger.Debug().Msg("paas ok")
	c.IndentedJSON(http.StatusOK, apiv1.RestCheckPaasResult{
		PaasName: input.Paas.Name, Decrypted: true,
	})
}
