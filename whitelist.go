package traefik_ipwhitelist

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/lost-woods/traefik-ipwhitelist/ip"
)

const (
	moduleName  = "SkyloftWhiteLister"
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

var (
	logger    = log.New(io.Discard, fmt.Sprintf("[INFO] %s: ", moduleName), log.Ldate|log.Ltime)
	uriRegexp = regexp.MustCompile(`^(https?):\/\/(\[[\w:.]+\]|[\w\._-]+)?(:\d+)?(.*)$`)
)

type skyloftWhiteLister struct {
	name        string
	whiteLister *ip.Checker
	regex       string
	replacement string
	next        http.Handler
}

type SkyloftWhiteList struct {
	Regex       string
	Replacement string
	SourceRange []string
}

type moveHandler struct {
	location  *url.URL
	permanent bool
}

func CreateConfig() *SkyloftWhiteList {
	return &SkyloftWhiteList{
		Regex:       "^(?:https?://)?(?:[^@/]+@)?([^:/]+)(?:.*)",
		Replacement: "https://$1/notfound",
		SourceRange: []string{"127.0.0.1"},
	}
}

func (wl *skyloftWhiteLister) GetIP(req *http.Request) string {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return ip
}

func rawURL(req *http.Request) string {
	scheme := schemeHTTP
	host := req.Host
	port := ""
	uri := req.RequestURI

	if match := uriRegexp.FindStringSubmatch(req.RequestURI); len(match) > 0 {
		scheme = match[1]

		if len(match[2]) > 0 {
			host = match[2]
		}

		if len(match[3]) > 0 {
			port = match[3]
		}

		uri = match[4]
	}

	if req.TLS != nil {
		scheme = schemeHTTPS
	}

	return strings.Join([]string{scheme, "://", host, port, uri}, "")
}

func rejectWith404(rw http.ResponseWriter) {
	statusCode := http.StatusNotFound
	rw.WriteHeader(statusCode)

	_, err := rw.Write([]byte(http.StatusText(statusCode)))
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func New(ctx context.Context, next http.Handler, config *SkyloftWhiteList, name string) (http.Handler, error) {
	// Initialize logger
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
		regex:       config.Regex,
		replacement: config.Replacement,
		next:        next,
	}, nil
}

func (wl *skyloftWhiteLister) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := wl.GetIP(req)
	err := wl.whiteLister.IsAuthorized(clientIP)
	if err != nil {
		logger.Printf("URL: %s %s - Rejecting IP: %v\n", req.Host, req.URL.Path, err)
		wl.reject(rw, req)
		return
	}

	//logger.Printf("Accepting IP %s\n", clientIP)
	wl.next.ServeHTTP(rw, req)
}

func (wl *skyloftWhiteLister) reject(rw http.ResponseWriter, req *http.Request) {
	oldURL := rawURL(req)

	// If the Regexp doesn't match, simply return 404.
	match, err := regexp.MatchString(wl.regex, oldURL)
	if err != nil || !match {
		rejectWith404(rw)
		return
	}

	// Apply a rewrite regexp to the URL.
	regex := regexp.MustCompile(wl.regex)
	newURL := regex.ReplaceAllString(oldURL, wl.replacement)

	// Parse the rewritten URL and replace request URL with it.
	parsedURL, err := url.Parse(newURL)
	if err != nil {
		rejectWith404(rw)
		return
	}

	// Replace the URL
	if newURL != oldURL {
		handler := &moveHandler{location: parsedURL, permanent: false}
		handler.ServeHTTP(rw, req)
		return
	}

	// If we fall here, simply reject with 404.
	rejectWith404(rw)
}

func (m *moveHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Location", m.location.String())

	status := http.StatusFound
	if req.Method != http.MethodGet {
		status = http.StatusTemporaryRedirect
	}

	if m.permanent {
		status = http.StatusMovedPermanently
		if req.Method != http.MethodGet {
			status = http.StatusPermanentRedirect
		}
	}

	rw.WriteHeader(status)
	_, err := rw.Write([]byte(http.StatusText(status)))
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}
