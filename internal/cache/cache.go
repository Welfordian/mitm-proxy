package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cfgpkg "mitm-proxy/internal/config"
)

// Cache encapsulates simple on-disk cache logic.
type Cache struct {
	mu  sync.RWMutex
	cfg *cfgpkg.Config
}

// Response is the cached payload stored on disk.
type Response struct {
	URL       string      `json:"url"`
	Status    int         `json:"status"`
	Header    http.Header `json:"header"`
	Body      []byte      `json:"body"`
	StoredAt  int64       `json:"stored_at_unix"`
	ExpiresAt int64       `json:"expires_at_unix"`
}

// New creates a new Cache and ensures cache directory exists if enabled.
func New(cfg *cfgpkg.Config) *Cache {
	c := &Cache{cfg: cfg}
	c.ensureDir()

	return c
}

// SetConfig updates the cache configuration reference and ensures directory when needed.
func (c *Cache) SetConfig(cfg *cfgpkg.Config) {
	c.mu.Lock()
	c.cfg = cfg
	c.mu.Unlock()
	c.ensureDir()
}

func (c *Cache) ensureDir() {
	c.mu.RLock()

	enabled := c.cfg.Cache.Enabled
	dir := c.cfg.Cache.Directory
	verbose := c.cfg.VerboseLogging

	c.mu.RUnlock()

	if !enabled {
		return
	}

	if dir == "" {
		dir = "cache"

		// write back directory default under lock
		c.mu.Lock()
		c.cfg.Cache.Directory = dir
		c.mu.Unlock()
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("warning: failed to create cache dir %s: %v", dir, err)
	} else if verbose {
		log.Printf("[VERBOSE] cache directory ensured: %s", dir)
	}
}

// ShouldConsider reports whether the request should be considered for cache lookup/save.
func (c *Cache) ShouldConsider(r *http.Request) bool {
	c.mu.RLock()
	cfg := c.cfg
	c.mu.RUnlock()

	if !cfg.Cache.Enabled {
		return false
	}
	if r.Method != http.MethodGet {
		return false
	}

	u := r.URL

	if u == nil {
		return false
	}

	host := u.Host

	if host == "" {
		host = r.Host
	}

	// Domain filters
	if len(cfg.Cache.IncludeDomains) > 0 {
		if !matchDomainAny(host, cfg.Cache.IncludeDomains) {
			return false
		}
	} else if len(cfg.Cache.ExcludeDomains) > 0 {
		if matchDomainAny(host, cfg.Cache.ExcludeDomains) {
			return false
		}
	}

	// Extension filters
	ext := filepath.Ext(u.Path)

	if len(ext) > 0 && ext[0] == '.' {
		ext = ext[1:]
	}

	ext = strings.ToLower(ext)

	if len(cfg.Cache.IncludeExtensions) > 0 {
		if !containsStringFold(cfg.Cache.IncludeExtensions, ext) {
			return false
		}
	} else if len(cfg.Cache.ExcludeExtensions) > 0 {
		if containsStringFold(cfg.Cache.ExcludeExtensions, ext) {
			return false
		}
	}

	return true
}

func keyFromURL(u *url.URL) string {
	h := sha256.Sum256([]byte(u.String()))

	return hex.EncodeToString(h[:])
}

func (c *Cache) path(u *url.URL) (string, string) {
	c.mu.RLock()

	dirBase := c.cfg.Cache.Directory

	c.mu.RUnlock()

	key := keyFromURL(u)
	host := u.Hostname()

	if host == "" {
		host = "_"
	}

	dir := filepath.Join(dirBase, host)
	_ = os.MkdirAll(dir, 0o755)

	return filepath.Join(dir, key+".json"), key
}

// Load attempts to load a cached response for the given URL. Returns the cached Response and the cache key.
func (c *Cache) Load(u *url.URL) (*Response, string, error) {
	path, key := c.path(u)
	b, err := os.ReadFile(path)

	if err != nil {
		return nil, "", err
	}

	var cr Response

	if err := json.Unmarshal(b, &cr); err != nil {
		return nil, "", err
	}

	if cr.ExpiresAt > 0 && time.Now().Unix() > cr.ExpiresAt {
		_ = os.Remove(path)
		return nil, "", os.ErrNotExist
	}

	return &cr, key, nil
}

// Save stores the given response body for the URL with TTL.
func (c *Cache) Save(u *url.URL, resp *http.Response, body []byte) {
	c.mu.RLock()

	ttl := c.cfg.Cache.TTL
	verbose := c.cfg.VerboseLogging

	c.mu.RUnlock()

	if ttl <= 0 {
		return
	}

	cr := Response{
		URL:       u.String(),
		Status:    resp.StatusCode,
		Header:    resp.Header.Clone(),
		Body:      body,
		StoredAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second).Unix(),
	}

	data, err := json.Marshal(cr)

	if err != nil {
		if verbose {
			log.Printf("[VERBOSE] cache marshal error: %v", err)
		}
		return
	}

	path, _ := c.path(u)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		if verbose {
			log.Printf("[VERBOSE] cache write error: %v", err)
		}
	} else if verbose {
		log.Printf("[VERBOSE] cached %s -> %s", u.String(), path)
	}
}

func matchDomainAny(domain string, patterns []string) bool {
	d := strings.ToLower(domain)

	for _, ptn := range patterns {
		p := strings.ToLower(ptn)

		if strings.HasPrefix(p, "*.") {
			suf := p[1:]
			if strings.HasSuffix(d, suf) || d == p[2:] {
				return true
			}
		} else if p == d {
			return true
		}
	}

	return false
}

func containsStringFold(list []string, needle string) bool {
	n := strings.ToLower(needle)

	for _, s := range list {
		if strings.ToLower(strings.TrimPrefix(s, ".")) == n {
			return true
		}
	}

	return false
}
