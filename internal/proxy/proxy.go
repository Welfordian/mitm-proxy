package proxy

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	capkg "mitm-proxy/internal/ca"
	cachepkg "mitm-proxy/internal/cache"
	cfgpkg "mitm-proxy/internal/config"
)

// Proxy is the core HTTP handler implementing MITM and tunneling.
type Proxy struct {
	ca     *capkg.CA
	config atomic.Value

	client *http.Client

	mu        sync.Mutex
	certCache map[string]*tls.Certificate
	cache     *cachepkg.Cache
}

// New creates a new Proxy instance with configured upstream transport.
func New(ca *capkg.CA, config *cfgpkg.Config) *Proxy {
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        config.MaxIdleConns,
		IdleConnTimeout:     time.Duration(config.IdleConnTimeout) * time.Second,
		TLSHandshakeTimeout: time.Duration(config.TLSHandshakeTimeout) * time.Second,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		log.Printf("warning: failed to configure HTTP/2 on transport: %v", err)
	}

	p := &Proxy{
		ca:        ca,
		client:    &http.Client{Transport: transport},
		certCache: make(map[string]*tls.Certificate),
		cache:     cachepkg.New(config),
	}
	p.config.Store(config)
	return p
}

// SetConfig updates the proxy's runtime configuration safely.
// Note: Transport settings such as timeouts are not rebuilt here to keep changes minimal.
// For settings used in hot paths (logging, cache, TLS min version), the new config will take effect immediately.
func (p *Proxy) SetConfig(cfg *cfgpkg.Config) {
	// Atomic swap avoids data races with concurrent reads
	p.config.Store(cfg)
	if p.cache != nil {
		p.cache.SetConfig(cfg)
	}
}

// cfg returns the current configuration snapshot safely.
func (p *Proxy) cfg() *cfgpkg.Config {
	if v := p.config.Load(); v != nil {
		return v.(*cfgpkg.Config)
	}
	return &cfgpkg.Config{}
}

func (p *Proxy) getCertForHost(host string) (*tls.Certificate, error) {
	p.mu.Lock()

	defer p.mu.Unlock()

	if cert, ok := p.certCache[host]; ok {
		return cert, nil
	}

	leaf, err := p.ca.GenerateCertForHost(host)

	if err != nil {
		return nil, err
	}

	p.certCache[host] = &leaf

	return &leaf, nil
}

// ServeHTTP routes requests between plain HTTP and CONNECT.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *Proxy) logRequest(format string, args ...interface{}) {
	if p.cfg().LogRequests {
		log.Printf(format, args...)
	}
}

func (p *Proxy) logVerbose(format string, args ...interface{}) {
	if p.cfg().VerboseLogging {
		log.Printf("[VERBOSE] "+format, args...)
	}
}

// makeCustomHeader returns a header name derived from the proxy name:
// lowercased, tokenized with hyphens, prefixed with "x-" and suffixed with the provided suffix.
// Example: "Cool Proxy" -> "x-cool-proxy-{suffix}"
func (p *Proxy) makeCustomHeader(suffix string) string {
	name := p.cfg().ProxyName
	// Convert to lowercase and replace any non-alphanumeric with '-'
	b := make([]rune, 0, len(name))
	prevHyphen := false

	for _, r := range name {
		// Normalize to lowercase ASCII where possible
		if r >= 'A' && r <= 'Z' {
			r = r + ('a' - 'A')
		}

		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b = append(b, r)
			prevHyphen = false
			continue
		}

		// For anything else, use a single hyphen separator (collapse repeats)
		if !prevHyphen {
			b = append(b, '-')
			prevHyphen = true
		}
	}

	// Trim leading/trailing hyphens
	// Find start
	start := 0

	for start < len(b) && b[start] == '-' {
		start++
	}

	end := len(b)

	for end > start && b[end-1] == '-' {
		end--
	}

	token := string(b[start:end])

	if token == "" {
		token = "proxy"
	}

	return "x-" + token + "-" + suffix
}
