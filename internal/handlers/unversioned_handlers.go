/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package handlers

import (
	"net/http"

	"github.com/belastingdienst/opr-paas-webservice/v3/internal/cryptmgr"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/version"
	"github.com/gin-gonic/gin"
)

// Handler struct for handlers
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
	c.JSON(http.StatusOK, gin.H{"message": "ready"})
}
