/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package server

import (
	"fmt"
	"strings"

	"github.com/belastingdienst/opr-paas-webservice/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/internal/cryptmgr"
	handlers "github.com/belastingdienst/opr-paas-webservice/internal/handler"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewRouter creates a new Gin router based on the WsConfig
func NewRouter(cfg *config.WsConfig) *gin.Engine {
	cryptMgr := cryptmgr.NewManager(cfg)
	h := handlers.NewHandler(cryptMgr)

	router := gin.New()

	corsCfg := cors.DefaultConfig()
	corsCfg.AllowMethods = []string{"GET", "POST", "HEAD", "OPTIONS"}
	corsCfg.AllowHeaders = []string{"Origin", "Content-Type"}
	if len(cfg.AllowedOrigins) > 0 {
		if len(cfg.AllowedOrigins) == 1 && cfg.AllowedOrigins[0] == "*" {
			corsCfg.AllowAllOrigins = true
		} else {
			corsCfg.AllowOrigins = cfg.AllowedOrigins
		}
	}
	if err := corsCfg.Validate(); err != nil {
		panic(fmt.Errorf("cors config invalid: %w", err))
	}
	router.Use(cors.New(corsCfg), gin.Logger(), gin.Recovery())

	// Security headers
	router.Use(func(c *gin.Context) {
		csp := buildCSP(strings.Join(cfg.AllowedOrigins, " "))
		c.Header("Content-Security-Policy", csp)
		c.Header("X-Content-Type-Options", "nosniff")
		c.Next()
	})

	// Routes
	router.GET("/version", h.Version)
	router.POST("/v1/encrypt", h.V1Encrypt)
	router.POST("/v1/checkpaas", h.V1CheckPaas)
	router.GET("/healthz", h.Healthz)
	router.GET("/readyz", h.Readyz)
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	return router
}

// buildCSP returns a Content-Security-Policy string.
// If externalHosts is non-empty, we append it to script-src, style-src, etc.
// externalHosts should a space-separated list of http:// and/or https:// urls
func buildCSP(externalHosts string) string {
	defaultSrc := "default-src 'none'"
	scriptSrc := "script-src 'self'"
	styleSrc := "style-src 'self'"
	imgSrc := "img-src 'self'"
	connectSrc := "connect-src 'self'"
	fontSrc := "font-src 'self'"
	objectSrc := "object-src 'none'"

	// If we have a non-empty external host, append it to each directive that needs it.
	toAppend := " " + externalHosts
	if externalHosts != "" {
		scriptSrc += toAppend
		styleSrc += toAppend
		imgSrc += toAppend
		connectSrc += toAppend
		fontSrc += toAppend
	}

	// Combine them into one directive string
	return fmt.Sprintf(
		"%s; %s; %s; %s; %s; %s; %s",
		defaultSrc, scriptSrc, styleSrc, imgSrc, connectSrc, fontSrc, objectSrc,
	)
}
