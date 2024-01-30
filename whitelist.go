package skyloftwhitelist

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/ip"
	"github.com/traefik/traefik/v3/pkg/middlewares"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	typeName = "SkyloftWhiteLister"
)

type skyloftWhiteLister struct {
	name        string
	whiteLister *ip.Checker
	next        http.Handler
}

type SkyloftWhiteList struct {
	SourceRange []string `json:"sourceRange,omitempty" toml:"sourceRange,omitempty" yaml:"sourceRange,omitempty"`
}

func SetStatusErrorf(ctx context.Context, format string, args ...interface{}) {
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetStatus(codes.Error, fmt.Sprintf(format, args...))
	}
}

func New(ctx context.Context, next http.Handler, config SkyloftWhiteList, name string) (http.Handler, error) {
	logger := middlewares.GetLogger(ctx, name, typeName)
	logger.Debug().Msg("Creating middleware")

	if len(config.SourceRange) == 0 {
		return nil, errors.New("sourceRange is empty, SkyloftWhiteLister not created")
	}

	checker, err := ip.NewChecker(config.SourceRange)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CIDR whitelist %s: %w", config.SourceRange, err)
	}

	logger.Debug().Msgf("Setting up SkyloftWhiteLister with sourceRange: %s", config.SourceRange)

	return &skyloftWhiteLister{
		name:        name,
		whiteLister: checker,
		next:        next,
	}, nil
}

func (wl *skyloftWhiteLister) GetIP(req *http.Request) string {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return ip
}

func (wl *skyloftWhiteLister) GetTracingInformation() (string, string, trace.SpanKind) {
	return wl.name, typeName, trace.SpanKindInternal
}

func (wl *skyloftWhiteLister) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := middlewares.GetLogger(req.Context(), wl.name, typeName)
	ctx := logger.WithContext(req.Context())

	clientIP := wl.GetIP(req)
	err := wl.whiteLister.IsAuthorized(clientIP)
	if err != nil {
		msg := fmt.Sprintf("Rejecting IP %s: %v", clientIP, err)
		logger.Debug().Msg(msg)
		SetStatusErrorf(req.Context(), msg)
		reject(ctx, rw)
		return
	}
	logger.Debug().Msgf("Accepting IP %s", clientIP)

	wl.next.ServeHTTP(rw, req)
}

func reject(ctx context.Context, rw http.ResponseWriter) {
	statusCode := http.StatusForbidden

	rw.WriteHeader(statusCode)
	_, err := rw.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Send()
	}
}
