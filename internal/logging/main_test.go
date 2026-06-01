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
