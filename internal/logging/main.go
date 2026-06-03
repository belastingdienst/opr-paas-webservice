/*
Copyright 2023, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package logging

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	// Commandline args will use this to enable all debug logging
	staticDebug bool
	// Commandline args can use this to enable logging for a component
	staticComponents Components
)

// SetWebserviceLogger derives a context with a `zerolog` logger configured for a webservice request.
func SetWebserviceLogger(
	req *http.Request,
) (context.Context, *zerolog.Logger) {
	logger := log.With().
		Str("path", req.URL.Path).
		Str("method", req.Method).
		Str("requestID", uuid.NewString()).
		Logger()
	logger.Info().Msg("started processing request")

	return logger.WithContext(req.Context()), &logger
}

// SetStaticLoggingConfig configures global debugging and component debugging from commandline argument perspective
func SetStaticLoggingConfig(debug bool, components Components) {
	staticDebug = debug
	staticComponents = components
}

func getComponentDebugLevel(name Component) zerolog.Level {
	if staticDebug {
		return zerolog.DebugLevel
	}
	if enabled := staticComponents[name]; enabled {
		return zerolog.DebugLevel
	}
	return zerolog.InfoLevel
}

// GetLogComponent gets the logger for a component from a context.
func GetLogComponent(ctx context.Context, name Component) (context.Context, *zerolog.Logger) {
	logger := log.Ctx(ctx)
	level := getComponentDebugLevel(name)

	if logger.GetLevel() != level {
		ll := logger.Level(level).With().Str("component", componentToString(name)).Logger()
		logger = &ll
		ctx = logger.WithContext(ctx)
	}
	return ctx, logger
}
