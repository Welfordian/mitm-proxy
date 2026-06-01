package store

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	cachepkg "mitm-proxy/internal/cache"
)

func TestCacheEntryRoundTripListAndPurge(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	entry := cachepkg.StoredEntry{
		Key:         strings.Repeat("a", 64),
		URL:         "https://assets.example.test/image.png",
		Host:        "assets.example.test",
		Status:      http.StatusOK,
		Headers:     http.Header{"Content-Type": []string{"image/png"}},
		Body:        []byte{0x89, 0x50, 0x4e, 0x47},
		StoredAt:    time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
		ContentType: "image/png",
	}
	if err := st.SaveCacheEntry(ctx, entry); err != nil {
		t.Fatalf("save cache entry: %v", err)
	}

	got, err := st.LoadCacheEntry(ctx, entry.Key)
	if err != nil {
		t.Fatalf("load cache entry: %v", err)
	}
	if got.URL != entry.URL || got.Status != http.StatusOK || string(got.Body) != string(entry.Body) || got.Headers.Get("Content-Type") != "image/png" {
		t.Fatalf("unexpected cache entry: %+v", got)
	}

	page, err := st.ListCacheEntries(ctx, 10, 0, "assets")
	if err != nil {
		t.Fatalf("list cache entries: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].Key != entry.Key {
		t.Fatalf("unexpected cache page: %+v", page)
	}
	size, count, err := st.CacheStats(ctx)
	if err != nil {
		t.Fatalf("cache stats: %v", err)
	}
	if size != int64(len(entry.Body)) || count != 1 {
		t.Fatalf("unexpected stats size=%d count=%d", size, count)
	}

	removed, err := st.PurgeCache(ctx, "assets.example.test")
	if err != nil {
		t.Fatalf("purge cache: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected one purged entry, got %d", removed)
	}
}

func TestCacheEntryPrunesExpiredAndBodyless304(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	expired := cachepkg.StoredEntry{
		Key:       strings.Repeat("b", 64),
		URL:       "https://example.test/expired.js",
		Host:      "example.test",
		Status:    http.StatusOK,
		Headers:   http.Header{},
		Body:      []byte("old"),
		StoredAt:  time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}
	if err := st.SaveCacheEntry(ctx, expired); err != nil {
		t.Fatalf("save expired cache entry: %v", err)
	}
	notModified := cachepkg.StoredEntry{
		Key:       strings.Repeat("c", 64),
		URL:       "https://example.test/not-modified.png",
		Host:      "example.test",
		Status:    http.StatusNotModified,
		Headers:   http.Header{},
		StoredAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := st.SaveCacheEntry(ctx, notModified); err != nil {
		t.Fatalf("save not-modified cache entry: %v", err)
	}

	page, err := st.ListCacheEntries(ctx, 10, 0, "")
	if err != nil {
		t.Fatalf("list cache entries: %v", err)
	}
	if page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("expected pruned cache page, got %+v", page)
	}
}
