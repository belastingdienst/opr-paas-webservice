/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package main

import (
	"log"
	"net/http"

	"github.com/belastingdienst/opr-paas-webservice/v3/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/logging"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/server"
	"github.com/belastingdienst/opr-paas-webservice/v3/internal/version"
	"github.com/gin-gonic/gin"
)

func main() {
	log.Println("Starting API endpoint")
	log.Printf("Version: %s", version.PaasWebserviceVersion)
	gin.SetMode(gin.ReleaseMode)

	cfg := config.NewWSConfig()
	logging.ConfigureGlobalLogger()
	logging.SetStaticLoggingConfig(cfg.Debug, cfg.DebugComponents)
	router := server.NewRouter(&cfg)

	var err error
	if cfg.TLSEnabled() {
		err = serveTLS(cfg, router)
	} else {
		log.Printf("Listening on: %s", cfg.Endpoint)
		err = router.Run(cfg.Endpoint)
	}
	if err != nil {
		log.Fatalf("router error: %v", err)
	}
}

// serveTLS serves handler with TLS, using the certificate and key files in cfg.
func serveTLS(cfg config.WsConfig, handler http.Handler) error {
	tlsConfig, err := server.NewTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: cfg.Endpoint, Handler: handler, TLSConfig: tlsConfig}
	log.Printf("Listening with TLS on: %s", cfg.Endpoint)
	// The certificate comes from TLSConfig, so no file names are passed here.
	return srv.ListenAndServeTLS("", "")
}
