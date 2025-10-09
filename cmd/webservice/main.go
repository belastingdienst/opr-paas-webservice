/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package main

import (
	"log"

	"github.com/belastingdienst/opr-paas-webservice/internal/config"
	"github.com/belastingdienst/opr-paas-webservice/internal/server"
	"github.com/belastingdienst/opr-paas-webservice/internal/version"
	"github.com/gin-gonic/gin"
)

func main() {
	log.Println("Starting API endpoint")
	log.Printf("Version: %s", version.PaasWebserviceVersion)
	gin.SetMode(gin.ReleaseMode)

	cfg := config.NewWSConfig()
	router := server.NewRouter(&cfg)

	log.Printf("Listening on: %s", cfg.Endpoint)
	if err := router.Run(cfg.Endpoint); err != nil {
		log.Fatalf("router error: %v", err)
	}
}
