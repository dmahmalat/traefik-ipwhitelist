package traefik_ipwhitelist

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/dmahmalat/traefik-ipwhitelist/ip"
)

const (
	moduleName = "SkyloftWhiteLister"
)

var (
	logger = log.New(io.Discard, fmt.Sprintf("[INFO] %s: ", moduleName), log.Ldate|log.Ltime)
)

type skyloftWhiteLister struct {
	name        string
	whiteLister *ip.Checker
	next        http.Handler
}

type SkyloftWhiteList struct {
	SourceRange []string
}

func CreateConfig() *SkyloftWhiteList {
	return &SkyloftWhiteList{
		SourceRange: []string{"127.0.0.1"},
	}
}

func New(ctx context.Context, next http.Handler, config *SkyloftWhiteList, name string) (http.Handler, error) {
	logger.SetOutput(os.Stdout)
	//logger.Println("Creating middleware")

	if len(config.SourceRange) == 0 {
		return nil, fmt.Errorf("sourceRange is empty, %s not created", moduleName)
	}

	checker, err := ip.NewChecker(config.SourceRange)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CIDR whitelist %s: %w", config.SourceRange, err)
	}

	//logger.Printf("Setting up %s with sourceRange: %s\n", moduleName, config.SourceRange)

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
	logger.SetOutput(os.Stdout)

	clientIP := wl.GetIP(req)
	err := wl.whiteLister.IsAuthorized(clientIP)
	if err != nil {
		msg := fmt.Sprintf("Rejecting IP %s: %v", clientIP, err)
		logger.Println(msg)
		reject(rw)
		return
	}
	//logger.Printf("Accepting IP %s\n", clientIP)

	wl.next.ServeHTTP(rw, req)
}

func reject(rw http.ResponseWriter) {
	logger.SetOutput(os.Stdout)

	statusCode := http.StatusForbidden
	rw.WriteHeader(statusCode)
	_, err := rw.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		logger.Fatal(err.Error())
	}
}
