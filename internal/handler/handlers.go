/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package handlers

import (
	"net/http"
	"strings"

	apiv1 "github.com/belastingdienst/opr-paas-webservice/v3/api/v1"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/cryptmgr"
	internal "github.com/belastingdienst/opr-paas-webservice/v3/internal/services"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/version"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

// Handler struct for handlers
type Handler struct {
	CryptMgr *cryptmgr.Manager
}

// NewHandler returns a handler based on the provided crypt
func NewHandler(cryptMgr *cryptmgr.Manager) *Handler {
	return &Handler{CryptMgr: cryptMgr}
}

// V1Encrypt encrypts a secret and returns the encrypted value
func (h *Handler) V1Encrypt(c *gin.Context) {
	var input apiv1.RestEncryptInput
	if err := c.BindJSON(&input); err != nil {
		return
	}
	secret := []byte(input.Secret)
	if _, err := ssh.ParsePrivateKey(secret); err == nil {
		encrypted, err := h.CryptMgr.GetOrCreate(input.PaasName).Encrypt(secret)
		if err != nil {
			return
		}
		c.IndentedJSON(http.StatusOK, apiv1.RestEncryptResult{
			PaasName:  input.PaasName,
			Encrypted: encrypted,
			Valid:     true,
		})
		return
	}
	c.IndentedJSON(http.StatusOK, apiv1.RestEncryptResult{
		PaasName: input.PaasName, Valid: false,
	})
}

// V1CheckPaas checks whether a Paas can be decrypted using provided private/public keys
func (h *Handler) V1CheckPaas(c *gin.Context) {
	var input apiv1.RestCheckPaasInput
	if err := c.BindJSON(&input); err != nil {
		c.IndentedJSON(http.StatusBadRequest, apiv1.RestCheckPaasResult{Error: err.Error()})
		return
	}
	rsa := h.CryptMgr.GetOrCreate(input.Paas.Name)
	err := internal.CheckPaas(rsa, &input.Paas)
	if err != nil {
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
	c.IndentedJSON(http.StatusOK, apiv1.RestCheckPaasResult{
		PaasName: input.Paas.Name, Decrypted: true,
	})
}

// Version is a handler to return the webservice version
func (h *Handler) Version(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"version": version.PaasWebserviceVersion})
}

// Healthz is a handler for the Healthcheck
func (h *Handler) Healthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "healthy"})
}

// Readyz is a handler for the Readinesscheck
func (h *Handler) Readyz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "ready"})
}
