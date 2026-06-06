package proxy

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mitm-proxy/internal/access"
	capkg "mitm-proxy/internal/ca"
	cachepkg "mitm-proxy/internal/cache"
	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/intercept"
	"mitm-proxy/internal/threats"
	"mitm-proxy/internal/upstream"
	"mitm-proxy/internal/wsinspect"
)

// Proxy is the core HTTP handler implementing MITM and tunneling.
type Proxy struct {
	ca     *capkg.CA
	config atomic.Value
	client atomic.Value

	mu        sync.Mutex
	certCache map[string]*tls.Certificate
	cache     *cachepkg.Cache
	threats   *threats.Manager
	intercept *intercept.Manager
	ws        *wsinspect.Manager
	events    *events.Bus
	access    *access.Controller
}

// New creates a new Proxy instance with configured upstream transport.
func New(ca *capkg.CA, config *cfgpkg.Config) *Proxy {
	return NewWithEvents(ca, config, events.NewBus(128))
}

func NewWithEvents(ca *capkg.CA, config *cfgpkg.Config, eventBus *events.Bus) *Proxy {
	if eventBus == nil {
		eventBus = events.NewBus(128)
	}

	p := &Proxy{
		ca:        ca,
		certCache: make(map[string]*tls.Certificate),
		cache:     cachepkg.New(config),
		events:    eventBus,
	}
	p.config.Store(config)
	p.client.Store(upstream.NewHTTPClient(config, 0))
	p.threats = threats.NewManager(p.cfg)
	p.access = access.NewController(p.cfg, nil)
	return p
}

// SetConfig updates the proxy's runtime configuration safely.
func (p *Proxy) SetConfig(cfg *cfgpkg.Config) {
	// Atomic swap avoids data races with concurrent reads
	p.config.Store(cfg)
	p.client.Store(upstream.NewHTTPClient(cfg, 0))
	if p.cache != nil {
		p.cache.SetConfig(cfg)
	}
}

func (p *Proxy) SetCacheStore(store cachepkg.BackingStore) {
	if p.cache != nil {
		p.cache.SetStore(store)
	}
}

func (p *Proxy) SetAccessStore(store access.Store) {
	p.access = access.NewController(p.cfg, store)
}

// cfg returns the current configuration snapshot safely.
func (p *Proxy) cfg() *cfgpkg.Config {
	if v := p.config.Load(); v != nil {
		return v.(*cfgpkg.Config)
	}
	return &cfgpkg.Config{}
}

func (p *Proxy) CurrentConfig() *cfgpkg.Config {
	return p.cfg()
}

func (p *Proxy) httpClient() *http.Client {
	if v := p.client.Load(); v != nil {
		return v.(*http.Client)
	}
	return upstream.NewHTTPClient(p.cfg(), 0)
}

func (p *Proxy) accessController() *access.Controller {
	if p.access == nil {
		p.access = access.NewController(p.cfg, nil)
	}
	return p.access
}

func (p *Proxy) ThreatScanner() *threats.Manager {
	return p.threats
}

func (p *Proxy) SetInterceptManager(manager *intercept.Manager) {
	p.intercept = manager
}

func (p *Proxy) SetWebSocketManager(manager *wsinspect.Manager) {
	p.ws = manager
}

func (p *Proxy) EventBus() *events.Bus {
	return p.events
}

func (p *Proxy) SetCA(ca *capkg.CA) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.ca = ca
	p.certCache = make(map[string]*tls.Certificate)
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
	payload := map[string]any{"host": host}
	if len(leaf.Certificate) > 0 {
		if cert, err := x509.ParseCertificate(leaf.Certificate[0]); err == nil {
			fingerprint := sha256.Sum256(cert.Raw)
			payload["subject"] = cert.Subject.String()
			payload["fingerprint"] = strings.ToUpper(hex.EncodeToString(fingerprint[:]))
			payload["created_at"] = cert.NotBefore.Format(time.RFC3339Nano)
			payload["expires_at"] = cert.NotAfter.Format(time.RFC3339Nano)
		}
	}
	p.publish(events.TopicCertGenerated, payload, "")

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

func (p *Proxy) publish(topic string, payload map[string]any, requestID string) {
	if p.events == nil {
		return
	}
	p.events.Publish(events.Event{
		Topic:     topic,
		Time:      time.Now().UTC(),
		Payload:   payload,
		RequestID: requestID,
	})
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
