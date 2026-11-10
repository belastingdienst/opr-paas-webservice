/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package handlers

import (
	"net/http"

	"github.com/belastingdienst/opr-paas-webservice/v3/internal/cryptmgr"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/logging"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/version"
	"github.com/gin-gonic/gin"
)

// Handler struct for handlers
// Messages returned to clients when the keys cannot be used. The details stay
// in the log: the endpoints are not authenticated.
const (
	errKeysUnavailable  = "the service cannot load its keys"
	errEncryptionFailed = "encryption failed"
	errNotReady         = "the configured keys cannot be loaded or cannot encrypt"
)

type Handler struct {
	CryptMgr *cryptmgr.Manager
}

// NewHandler returns a handler based on the provided crypt
func NewHandler(cryptMgr *cryptmgr.Manager) *Handler {
	return &Handler{CryptMgr: cryptMgr}
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
	if err := h.CryptMgr.Ready(); err != nil {
		_, logger := logging.GetLogComponent(c.Request.Context(), logging.RouterComponent)
		logger.Error().Err(err).Msg("not ready")
		c.JSON(http.StatusServiceUnavailable, gin.H{"message": "not ready", "error": errNotReady})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ready"})
}
