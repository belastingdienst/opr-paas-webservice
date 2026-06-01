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

// V2Encrypt encrypts a secret and returns the encrypted value
func (h *Handler) V2Encrypt(c *gin.Context) {
	var input apiv1.RestEncryptInput
	_, logger := logging.SetWebserviceLogger(c.Request)
	logger.Debug().Msg("entered V2Encrypt")
	if err := c.BindJSON(&input); err != nil {
		logger.Error().Err(err).Msg("failed to parse json")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	secret := []byte(input.Secret)
	if _, err := ssh.ParsePrivateKey(secret); err != nil {
		logger.Debug().Str("secret", input.Secret).Msg("")
		logger.Error().Err(err).Msg("failed to parse private key")
		// StatusUnprocessableEntity means that the data can be parsed, but functionally contains invalid data
		// which in our case meets with 'you sent proper json, but the secret is not a proper ssh secret
		c.AbortWithStatus(http.StatusUnprocessableEntity)
		return
	}
	encrypted, err := h.CryptMgr.GetOrCreate(input.PaasName).Encrypt(secret)
	if err != nil {
		logger.Error().Err(err).Msg("failed to encrypt")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	logger.Debug().Msg("secret encrypted properly")
	c.IndentedJSON(http.StatusOK, apiv1.RestEncryptResult{
		PaasName:  input.PaasName,
		Encrypted: encrypted,
		Valid:     true,
	})
}

// V2EncryptSSH verifies an SSH key, and if valid, it encrypts it and returns the encrypted value
func (h *Handler) V2EncryptSSH(c *gin.Context) {
	var input apiv1.RestEncryptInput
	_, logger := logging.SetWebserviceLogger(c.Request)
	logger.Debug().Msg("entered V2Encrypt")
	if err := c.BindJSON(&input); err != nil {
		logger.Error().Err(err).Msg("failed to parse json")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	secret := []byte(input.Secret)
	if _, err := ssh.ParsePrivateKey(secret); err != nil {
		logger.Debug().Str("secret", input.Secret).Msg("")
		logger.Error().Err(err).Msg("failed to parse private key")
		// StatusUnprocessableEntity means that the data can be parsed, but functionally contains invalid data
		// which in our case meets with 'you sent proper json, but the secret is not a proper ssh secret
		c.AbortWithStatus(http.StatusUnprocessableEntity)
		return
	}
	encrypted, err := h.CryptMgr.GetOrCreate(input.PaasName).Encrypt(secret)
	if err != nil {
		logger.Error().Err(err).Msg("failed to encrypt")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	logger.Debug().Msg("secret encrypted properly")
	c.IndentedJSON(http.StatusOK, apiv1.RestEncryptResult{
		PaasName:  input.PaasName,
		Encrypted: encrypted,
		Valid:     true,
	})
}

// V2CheckPaas checks whether a Paas can be decrypted using provided private/public keys
func (h *Handler) V2CheckPaas(c *gin.Context) {
	var input apiv1.RestCheckPaasInput
	_, logger := logging.SetWebserviceLogger(c.Request)
	logger.Debug().Msg("entered V1CheckPaas")
	if err := c.BindJSON(&input); err != nil {
		logger.Error().AnErr("error", err).Msg("failed to parse json")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	rsa := h.CryptMgr.GetOrCreate(input.Paas.Name)
	err := internal.CheckPaas(rsa, &input.Paas)
	if err != nil {
		logger.Error().AnErr("error", err).Msg("paas not ok")
		if strings.Contains(err.Error(), "unable to decrypt data") ||
			strings.Contains(err.Error(), "base64") {
			c.AbortWithStatus(http.StatusUnprocessableEntity)
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
