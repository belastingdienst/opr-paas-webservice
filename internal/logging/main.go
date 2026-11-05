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
		Logger().
		Level(getBaseLevel())
	logger.Info().Msg("started processing request")

	return logger.WithContext(req.Context()), &logger
}

// SetStaticLoggingConfig configures global debugging and component debugging from commandline argument perspective
func SetStaticLoggingConfig(debug bool, components Components) {
	staticDebug = debug
	staticComponents = components
}

// getBaseLevel returns the level for loggers that are not tied to a component.
// Debug logging is only enabled when debugging is enabled globally.
func getBaseLevel() zerolog.Level {
	if staticDebug {
		return zerolog.DebugLevel
	}
	return zerolog.InfoLevel
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
	if logger.GetLevel() == zerolog.Disabled {
		// No logger in the context (e.g. a handler called without the router middleware).
		// Fall back to the global logger, so log lines are not silently dropped.
		logger = &log.Logger
	}

	ll := logger.Level(getComponentDebugLevel(name)).With().Str("component", componentToString(name)).Logger()
	return ll.WithContext(ctx), &ll
}
