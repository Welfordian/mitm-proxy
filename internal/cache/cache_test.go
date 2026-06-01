package cache

import (
	"net/http"
	"net/url"
	"os"
	"testing"

	cfgpkg "mitm-proxy/internal/config"
)

func TestSaveSkipsNotModifiedResponses(t *testing.T) {
	dir := t.TempDir()
	cfg := &cfgpkg.Config{Cache: cfgpkg.CacheConfig{Enabled: true, Directory: dir, TTL: 3600}}
	c := New(cfg)
	rawURL, err := url.Parse("https://example.test/image.png")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	c.Save(rawURL, &http.Response{StatusCode: http.StatusNotModified, Header: http.Header{}}, nil)
	if _, _, err := c.Load(rawURL); err == nil {
		t.Fatal("expected 304 response to be skipped")
	}

	path, _ := c.path(rawURL)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected no cache file, got err %v", err)
	}
}

func TestLoadRemovesBodylessNotModifiedEntry(t *testing.T) {
	dir := t.TempDir()
	cfg := &cfgpkg.Config{Cache: cfgpkg.CacheConfig{Enabled: true, Directory: dir, TTL: 3600}}
	c := New(cfg)
	rawURL, err := url.Parse("https://example.test/image.png")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	path, _ := c.path(rawURL)
	if err := os.WriteFile(path, []byte(`{"url":"https://example.test/image.png","status":304,"header":{},"body":null,"stored_at_unix":1,"expires_at_unix":9999999999}`), 0o644); err != nil {
		t.Fatalf("write stale cache file: %v", err)
	}

	if _, _, err := c.Load(rawURL); err == nil {
		t.Fatal("expected stale 304 entry to be treated as a miss")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected stale 304 entry to be removed, got err %v", err)
	}
}
