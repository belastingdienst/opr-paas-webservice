package logging

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	paasName = "my-paas"
)

type logSink struct {
	logs []string
}

func (l *logSink) Write(p []byte) (n int, err error) {
	l.logs = append(l.logs, string(p))
	return len(p), nil
}

func (l *logSink) Index(i int) string {
	if len(l.logs) >= i {
		return l.logs[i]
	}
	return ""
}

func TestSetWebServiceLogger(t *testing.T) {
	var testRequest = &http.Request{
		Method: "POST",
		URL: &url.URL{
			Path: "some/path",
		},
	}

	obj := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: paasName,
		},
	}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Kind: "Paas",
		// Setting this to v1alpha0 to make it very distinct from whatever we actually use
		Version: "v1alpha0",
		Group:   "cpet.belastingdienst.nl",
	})

	output := &logSink{}
	log.Logger = log.Output(output)
	_, logger := SetWebserviceLogger(testRequest)
	require.NotNil(t, logger, "SetWebserviceLogger should return a logger")

	logger.Log().Msg("some webservice log")
	require.Len(t, output.logs, 2, "There should be 1 item in logs")
	logLine := output.Index(1)
	assert.Contains(t, logLine, `"path":"some/path"`)
	assert.Contains(t, logLine, `"method":"POST"`)
	assert.Contains(t, logLine, `"message":"some webservice log"`)
}

func TestDebugging(t *testing.T) {
	const comp1 = TestComponent
	ctx := context.TODO()
	// debug false
	SetStaticLoggingConfig(false, nil)
	_, noDebugLogger := GetLogComponent(ctx, comp1)
	assert.Equal(t, zerolog.InfoLevel, noDebugLogger.GetLevel())
	// debug true
	SetStaticLoggingConfig(true, nil)
	_, allDebugLogger := GetLogComponent(ctx, comp1)
	assert.Equal(t, zerolog.DebugLevel, allDebugLogger.GetLevel())
	// debug component
	SetStaticLoggingConfig(false, Components{comp1: true})
	_, componentDebugLogger := GetLogComponent(ctx, comp1)
	assert.Equal(t, zerolog.DebugLevel, componentDebugLogger.GetLevel())
}

// resetStaticLoggingConfig restores the default (no debug) config after a test.
func resetStaticLoggingConfig(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { SetStaticLoggingConfig(false, nil) })
}

func TestSetWebServiceLoggerDebugOnlyWhenEnabled(t *testing.T) {
	resetStaticLoggingConfig(t)
	req := &http.Request{Method: "POST", URL: &url.URL{Path: "some/path"}}

	SetStaticLoggingConfig(false, nil)
	output := &logSink{}
	log.Logger = log.Output(output)
	_, logger := SetWebserviceLogger(req)
	logger.Debug().Msg("hidden debug line")
	assert.NotContains(t, output.logs, "hidden debug line")
	for _, line := range output.logs {
		assert.NotContains(t, line, "hidden debug line")
	}

	SetStaticLoggingConfig(true, nil)
	output = &logSink{}
	log.Logger = log.Output(output)
	_, logger = SetWebserviceLogger(req)
	logger.Debug().Msg("visible debug line")
	require.Len(t, output.logs, 2)
	assert.Contains(t, output.Index(1), "visible debug line")
}

func TestGetLogComponentKeepsRequestLogger(t *testing.T) {
	resetStaticLoggingConfig(t)
	req := &http.Request{Method: "POST", URL: &url.URL{Path: "some/path"}}

	for _, debugComponent := range []bool{false, true} {
		SetStaticLoggingConfig(false, Components{TestComponent: debugComponent})
		output := &logSink{}
		log.Logger = log.Output(output)
		ctx, _ := SetWebserviceLogger(req)

		_, logger := GetLogComponent(ctx, TestComponent)
		logger.Info().Msg("component line")
		require.Len(t, output.logs, 2)
		line := output.Index(1)
		assert.Contains(t, line, `"component":"unittest_component"`)
		assert.Contains(t, line, `"path":"some/path"`)
		assert.Contains(t, line, `"requestID"`)
	}
}

func TestGetLogComponentWithoutContextLogger(t *testing.T) {
	resetStaticLoggingConfig(t)
	output := &logSink{}
	log.Logger = log.Output(output)

	_, logger := GetLogComponent(context.TODO(), TestComponent)
	logger.Info().Msg("fallback line")
	require.Len(t, output.logs, 1, "logs must not be dropped when the context has no logger")
	assert.Contains(t, output.Index(0), `"component":"unittest_component"`)
}
