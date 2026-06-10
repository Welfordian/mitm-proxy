package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cachepkg "mitm-proxy/internal/cache"
	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/store"
)

func TestCacheEntriesExposeSandboxedCachedResource(t *testing.T) {
	cacheDir := t.TempDir()
	rawURL := "https://example.test/page.html"
	body := []byte("<html><script>window.evil=true</script><h1>cached</h1></html>")
	key := writeCachedPayload(t, cacheDir, rawURL, http.StatusOK, http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}, body)

	s := New(Options{
		Token: "admin-token",
		Config: func() *cfgpkg.Config {
			return &cfgpkg.Config{Cache: cfgpkg.CacheConfig{Directory: cacheDir, Enabled: true, TTL: 3600}}
		},
	})

	list := getForTest(t, s, "/api/cache")
	var cacheList struct {
		Items []struct {
			Key     string `json:"key"`
			URL     string `json:"url"`
			ViewURL string `json:"view_url"`
		} `json:"items"`
	}
	if err := json.Unmarshal(list, &cacheList); err != nil {
		t.Fatalf("decode cache list: %v", err)
	}
	if len(cacheList.Items) != 1 {
		t.Fatalf("expected one cache item, got %d", len(cacheList.Items))
	}
	if cacheList.Items[0].Key != key || cacheList.Items[0].URL != rawURL {
		t.Fatalf("unexpected cache item: %+v", cacheList.Items[0])
	}
	parsed, err := url.Parse(cacheList.Items[0].ViewURL)
	if err != nil {
		t.Fatalf("parse view url: %v", err)
	}
	if parsed.Path != "/api/cache/resource" || parsed.Query().Get("key") != key {
		t.Fatalf("unexpected view url: %q", cacheList.Items[0].ViewURL)
	}

	req := httptest.NewRequest(http.MethodGet, cacheList.Items[0].ViewURL, nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected cached resource, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Security-Policy"); got != "sandbox" {
		t.Fatalf("expected sandbox CSP, got %q", got)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("expected cached content type, got %q", got)
	}
	if rr.Body.String() != string(body) {
		t.Fatalf("unexpected cached body: %q", rr.Body.String())
	}
}

func TestCacheEntriesSupportSearchAndPagination(t *testing.T) {
	cacheDir := t.TempDir()
	writeCachedPayload(t, cacheDir, "https://assets.example.test/app.js", http.StatusOK, http.Header{"Content-Type": []string{"application/javascript"}}, []byte("console.log(1)"))
	writeCachedPayload(t, cacheDir, "https://assets.example.test/app.css", http.StatusOK, http.Header{"Content-Type": []string{"text/css"}}, []byte("body{}"))
	writeCachedPayload(t, cacheDir, "https://images.example.test/logo.png", http.StatusOK, http.Header{"Content-Type": []string{"image/png"}}, []byte("png"))

	s := New(Options{
		Token: "admin-token",
		Config: func() *cfgpkg.Config {
			return &cfgpkg.Config{Cache: cfgpkg.CacheConfig{Directory: cacheDir, Enabled: true, TTL: 3600}}
		},
	})

	data := getForTest(t, s, "/api/cache?limit=1&offset=1&q=assets")
	var page struct {
		ItemsTotal int  `json:"items_total"`
		HasMore    bool `json:"has_more"`
		Limit      int  `json:"limit"`
		Offset     int  `json:"offset"`
		Items      []struct {
			URL string `json:"url"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &page); err != nil {
		t.Fatalf("decode cache page: %v", err)
	}
	if page.ItemsTotal != 2 || page.Limit != 1 || page.Offset != 1 {
		t.Fatalf("unexpected paging metadata: %+v", page)
	}
	if page.HasMore {
		t.Fatal("expected second one-item page to be the end of filtered entries")
	}
	if len(page.Items) != 1 || !strings.Contains(page.Items[0].URL, "assets.example.test") {
		t.Fatalf("unexpected filtered item: %+v", page.Items)
	}
}

func TestCacheResourceRejectsInvalidKey(t *testing.T) {
	s := New(Options{
		Token:  "admin-token",
		Config: func() *cfgpkg.Config { return &cfgpkg.Config{} },
	})
	req := httptest.NewRequest(http.MethodGet, "/api/cache/resource?key=../secret", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d", rr.Code)
	}
}

func TestCacheResourcePreservesContentEncoding(t *testing.T) {
	st := openAdminTestStore(t)
	key := strings.Repeat("d", 64)
	if err := st.SaveCacheEntry(context.Background(), cachepkg.StoredEntry{
		Key:         key,
		URL:         "https://assets.example.test/app.css",
		Host:        "assets.example.test",
		Status:      http.StatusOK,
		Headers:     http.Header{"Content-Type": []string{"text/css"}, "Content-Encoding": []string{"br"}},
		Body:        []byte{0xf1, 0x20, 0xad, 0x63},
		StoredAt:    time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
		Size:        4,
		ContentType: "text/css",
	}); err != nil {
		t.Fatalf("save cache entry: %v", err)
	}
	s := newTestServer(st)

	req := httptest.NewRequest(http.MethodGet, "/api/cache/resource?key="+key, nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected cached resource, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "text/css" {
		t.Fatalf("expected content type, got %q", got)
	}
	if got := rr.Header().Get("Content-Encoding"); got != "br" {
		t.Fatalf("expected content encoding br, got %q", got)
	}
	if rr.Body.Bytes()[0] != 0xf1 {
		t.Fatalf("expected encoded body to be served unchanged")
	}
}

func TestAdminUIRoutesServeIndexAndPreserveTokenRedirect(t *testing.T) {
	s := New(Options{
		UIEnabled: true,
		Config:    func() *cfgpkg.Config { return &cfgpkg.Config{} },
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/cache?token=abc", nil)
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected routed admin UI, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "MITM Proxy Admin") {
		t.Fatalf("expected admin index html, got %q", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/admin?token=abc", nil)
	rr = httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "/admin/?token=abc" {
		t.Fatalf("expected token-preserving redirect, got %q", got)
	}
}

func TestQueryTokenDoesNotAuthenticateMutations(t *testing.T) {
	s := New(Options{
		Token:  "admin-token",
		Config: func() *cfgpkg.Config { return &cfgpkg.Config{} },
	})
	req := httptest.NewRequest(http.MethodPut, "/api/settings?token=admin-token", strings.NewReader(`{"enable_mitm":true}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected mutation query token to be rejected, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestDeploymentRestartCallsConfiguredRestart(t *testing.T) {
	called := false
	s := New(Options{
		Token: "admin-token",
		Config: func() *cfgpkg.Config {
			return &cfgpkg.Config{}
		},
		Restart: func(context.Context) error {
			called = true
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/deployments/current/restart", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected accepted restart, got %d: %s", rr.Code, rr.Body.String())
	}
	if !called {
		t.Fatal("expected restart callback to be called")
	}
}

func TestSettingsDangerRequiresConfirmationAndPurges(t *testing.T) {
	st := openAdminTestStore(t)
	s := newTestServer(st)
	seedTrafficFlow(t, st, "body=1")
	if err := st.SaveCacheEntry(context.Background(), cachepkg.StoredEntry{
		Key:       strings.Repeat("e", 64),
		URL:       "https://example.test/app.js",
		Host:      "example.test",
		Status:    http.StatusOK,
		Headers:   http.Header{"Content-Type": []string{"application/javascript"}},
		Body:      []byte("console.log(1)"),
		StoredAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Size:      int64(len("console.log(1)")),
	}); err != nil {
		t.Fatalf("save cache entry: %v", err)
	}

	body, _ := json.Marshal(map[string]any{"action": "cache"})
	req := httptest.NewRequest(http.MethodPost, "/api/settings/danger", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected confirmation failure, got %d", rr.Code)
	}

	postJSONForTest(t, s, "/api/settings/danger", map[string]any{"action": "cache", "confirm": true})
	_, count, err := st.CacheStats(context.Background())
	if err != nil {
		t.Fatalf("cache stats: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected cache purge, got %d entries", count)
	}
	if flows, err := st.ListTraffic(context.Background(), 10); err != nil || len(flows) != 1 {
		t.Fatalf("expected traffic to remain after cache purge, flows=%+v err=%v", flows, err)
	}

	postJSONForTest(t, s, "/api/settings/danger", map[string]any{"action": "all", "confirm": true})
	if flows, err := st.ListTraffic(context.Background(), 10); err != nil || len(flows) != 0 {
		t.Fatalf("expected all data purge to clear traffic, flows=%+v err=%v", flows, err)
	}
}

func TestSettingsRejectsInvalidCacheFilters(t *testing.T) {
	s := New(Options{
		Token:  "admin-token",
		Config: func() *cfgpkg.Config { return &cfgpkg.Config{} },
	})
	body, _ := json.Marshal(map[string]any{
		"cache": map[string]any{
			"include_domains": []string{"example.test"},
			"exclude_domains": []string{"other.test"},
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid cache filters to be rejected, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSettingsApplySharedDefaults(t *testing.T) {
	var applied *cfgpkg.Config
	s := New(Options{
		Token:  "admin-token",
		Config: func() *cfgpkg.Config { return &cfgpkg.Config{} },
		ApplyConfig: func(cfg *cfgpkg.Config) {
			applied = cfg
		},
	})

	putJSONForTest(t, s, "/api/settings", map[string]any{
		"proxy_auth": map[string]any{"enabled": true},
		"intercept":  map[string]any{"enabled": true},
	})

	if applied == nil {
		t.Fatal("expected config to be applied")
	}
	if applied.ProxyAuth.DefaultAction != "deny" || applied.ProxyAuth.Realm == "" {
		t.Fatalf("expected proxy auth defaults to be applied: %+v", applied.ProxyAuth)
	}
	if applied.Intercept.TimeoutMS == 0 || applied.Intercept.TimeoutAction != "forward" {
		t.Fatalf("expected intercept defaults to be applied: %+v", applied.Intercept)
	}
	if applied.Cache.Directory == "" || applied.Cache.TTL == 0 {
		t.Fatalf("expected cache defaults to be applied: %+v", applied.Cache)
	}
}

func TestLeafCertificatesSupportSearchAndPagination(t *testing.T) {
	st := openAdminTestStore(t)
	s := newTestServer(st)
	seedCertificate(t, st, "api.example.test", "api-fingerprint")
	seedCertificate(t, st, "cdn.example.test", "cdn-fingerprint")
	seedCertificate(t, st, "outside.test", "outside-fingerprint")

	data := getForTest(t, s, "/api/certificates/leaf?limit=1&offset=1&q=example")
	var page struct {
		Items []store.CertificateRecord `json:"items"`
		Total int                       `json:"total"`
		More  bool                      `json:"has_more"`
	}
	if err := json.Unmarshal(data, &page); err != nil {
		t.Fatalf("decode leaf certificate page: %v", err)
	}
	if page.Total != 2 || page.More {
		t.Fatalf("unexpected page metadata: %+v", page)
	}
	if len(page.Items) != 1 || page.Items[0].Host != "api.example.test" {
		t.Fatalf("unexpected certificate page: %+v", page.Items)
	}
}

func writeCachedPayload(t *testing.T, cacheDir, rawURL string, status int, header http.Header, body []byte) string {
	t.Helper()
	keyBytes := sha256.Sum256([]byte(rawURL))
	key := hex.EncodeToString(keyBytes[:])
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse cached url: %v", err)
	}
	hostDir := filepath.Join(cacheDir, parsed.Hostname())
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		t.Fatalf("mkdir cache host dir: %v", err)
	}
	payload := map[string]any{
		"url":             rawURL,
		"status":          status,
		"header":          header,
		"body":            body,
		"stored_at_unix":  time.Now().Unix(),
		"expires_at_unix": time.Now().Add(time.Hour).Unix(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal cached payload: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, key+".json"), data, 0o644); err != nil {
		t.Fatalf("write cache file: %v", err)
	}
	return key
}

func seedCertificate(t *testing.T, st *store.Store, host, fingerprint string) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.RecordEvent(context.Background(), events.Event{
		Topic: events.TopicCertGenerated,
		Time:  now,
		Payload: map[string]any{
			"host":        host,
			"subject":     "CN=" + host,
			"fingerprint": fingerprint,
			"created_at":  now.Format(time.RFC3339Nano),
			"expires_at":  now.Add(time.Hour).Format(time.RFC3339Nano),
		},
	}); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}
}
