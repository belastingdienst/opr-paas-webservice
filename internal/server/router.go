/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/belastingdienst/opr-paas-webservice/v3/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/cryptmgr"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/handlers"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/logging"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

func simpleLogger(c *gin.Context) {
	ctx, _ := logging.SetWebserviceLogger(c.Request)
	_, logger := logging.GetLogComponent(ctx, logging.RouterComponent)
	logger.Debug().Msg("new request")
	c.Next()
}

func intrusiveLogger(c *gin.Context) {
	ctx, _ := logging.SetWebserviceLogger(c.Request)
	_, logger := logging.GetLogComponent(ctx, logging.RouterComponent)
	logger.Debug().Msg("new request")
	start := time.Now()
	c.Next()

	param := gin.LogFormatterParams{
		Request: c.Request,
		Keys:    c.Keys,
	}

	end := time.Now()
	latency := end.Sub(start)

	statusCode := c.Writer.Status()
	clientIP := c.ClientIP()

	var loggerEvent *zerolog.Event
	if statusCode >= http.StatusInternalServerError {
		loggerEvent = logger.Error()
	} else if statusCode >= http.StatusBadRequest {
		loggerEvent = logger.Warn()
	} else {
		loggerEvent = logger.Info()
	}

	loggerEvent.
		Int("status", statusCode).
		Str("ip", clientIP).
		Dur("latency", latency).
		Str("user_agent", param.Request.UserAgent()).
		Msg("HTTP Request")
}

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

	if _, exists := cfg.DebugComponents[logging.RouterComponent]; !exists && !cfg.Debug {
		router.Use(cors.New(corsCfg), simpleLogger, gin.Recovery())
	} else {
		router.Use(cors.New(corsCfg), intrusiveLogger, gin.Recovery())
	}

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
	router.POST("/v2/encrypt", h.V2Encrypt)
	router.POST("/v2/encryptSSH", h.V2EncryptSSH)
	router.POST("/v2/checkpaas", h.V2CheckPaas)
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
