package traefik_ipwhitelist

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/dmahmalat/traefik-ipwhitelist/ip"
	"github.com/dmahmalat/traefik-ipwhitelist/log"
)

const (
	moduleName = "SkyloftWhiteLister"
)

type skyloftWhiteLister struct {
	name        string
	whiteLister *ip.Checker
	next        http.Handler
}

type SkyloftWhiteList struct {
	SourceRange []string `json:"sourceRange,omitempty" toml:"sourceRange,omitempty" yaml:"sourceRange,omitempty"`
}

func CreateConfig() *SkyloftWhiteList {
	return &SkyloftWhiteList{
		SourceRange: []string{"127.0.0.1"},
	}
}

func New(ctx context.Context, next http.Handler, config SkyloftWhiteList, name string) (http.Handler, error) {
	logger := log.New(moduleName, log.Info)
	logger.Debug("Creating middleware")

	if len(config.SourceRange) == 0 {
		return nil, fmt.Errorf("sourceRange is empty, %s not created", moduleName)
	}

	checker, err := ip.NewChecker(config.SourceRange)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CIDR whitelist %s: %w", config.SourceRange, err)
	}

	logger.Debugf("Setting up %s with sourceRange: %s", moduleName, config.SourceRange)

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

func (wl *skyloftWhiteLister) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := log.New(moduleName, log.Info)

	clientIP := wl.GetIP(req)
	err := wl.whiteLister.IsAuthorized(clientIP)
	if err != nil {
		msg := fmt.Sprintf("Rejecting IP %s: %v", clientIP, err)
		logger.Debug(msg)
		reject(rw)
		return
	}
	logger.Debugf("Accepting IP %s", clientIP)

	wl.next.ServeHTTP(rw, req)
}

func reject(rw http.ResponseWriter) {
	logger := log.New(moduleName, log.Info)

	statusCode := http.StatusForbidden
	rw.WriteHeader(statusCode)
	_, err := rw.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		logger.Error(err.Error())
	}
}
