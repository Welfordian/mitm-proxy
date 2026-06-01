package cache

import (
	"context"
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
	mu    sync.RWMutex
	cfg   *cfgpkg.Config
	store BackingStore
}

type BackingStore interface {
	LoadCacheEntry(ctx context.Context, key string) (StoredEntry, error)
	SaveCacheEntry(ctx context.Context, entry StoredEntry) error
}

type StoredEntry struct {
	Key         string      `json:"key"`
	URL         string      `json:"url"`
	Host        string      `json:"host,omitempty"`
	Status      int         `json:"status"`
	Headers     http.Header `json:"headers,omitempty"`
	Body        []byte      `json:"-"`
	StoredAt    time.Time   `json:"stored_at"`
	ExpiresAt   time.Time   `json:"expires_at"`
	Size        int64       `json:"size"`
	ContentType string      `json:"content_type,omitempty"`
	ViewURL     string      `json:"view_url,omitempty"`
}

type EntryPage struct {
	Items   []StoredEntry
	Total   int
	HasMore bool
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

func NewWithStore(cfg *cfgpkg.Config, store BackingStore) *Cache {
	c := New(cfg)
	c.SetStore(store)
	return c
}

func (c *Cache) SetStore(store BackingStore) {
	c.mu.Lock()
	c.store = store
	c.mu.Unlock()
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
	return c.LoadContext(context.Background(), u)
}

func (c *Cache) LoadContext(ctx context.Context, u *url.URL) (*Response, string, error) {
	key := keyFromURL(u)
	c.mu.RLock()
	store := c.store
	c.mu.RUnlock()

	if store != nil {
		entry, err := store.LoadCacheEntry(ctx, key)
		if err != nil {
			return nil, "", err
		}
		return &Response{
			URL:       entry.URL,
			Status:    entry.Status,
			Header:    entry.Headers.Clone(),
			Body:      entry.Body,
			StoredAt:  entry.StoredAt.Unix(),
			ExpiresAt: entry.ExpiresAt.Unix(),
		}, key, nil
	}

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

	if cr.Status == http.StatusNotModified && len(cr.Body) == 0 {
		_ = os.Remove(path)
		return nil, "", os.ErrNotExist
	}

	return &cr, key, nil
}

// Save stores the given response body for the URL with TTL.
func (c *Cache) Save(u *url.URL, resp *http.Response, body []byte) {
	c.SaveContext(context.Background(), u, resp, body)
}

func (c *Cache) SaveContext(ctx context.Context, u *url.URL, resp *http.Response, body []byte) {
	c.mu.RLock()

	ttl := c.cfg.Cache.TTL
	verbose := c.cfg.VerboseLogging
	store := c.store

	c.mu.RUnlock()

	if ttl <= 0 {
		return
	}

	if resp.StatusCode == http.StatusNotModified {
		if verbose {
			log.Printf("[VERBOSE] skipping cache save for 304 response: %s", u.String())
		}
		return
	}

	if store != nil {
		key := keyFromURL(u)
		now := time.Now().UTC()
		entry := StoredEntry{
			Key:         key,
			URL:         u.String(),
			Host:        u.Hostname(),
			Status:      resp.StatusCode,
			Headers:     resp.Header.Clone(),
			Body:        body,
			StoredAt:    now,
			ExpiresAt:   now.Add(time.Duration(ttl) * time.Second),
			Size:        int64(len(body)),
			ContentType: resp.Header.Get("Content-Type"),
		}
		if err := store.SaveCacheEntry(ctx, entry); err != nil {
			if verbose {
				log.Printf("[VERBOSE] cache store write error: %v", err)
			}
			return
		}
		if verbose {
			log.Printf("[VERBOSE] cached %s -> sqlite:%s", u.String(), key)
		}
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
