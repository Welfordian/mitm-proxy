package threats

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

const scannerVersion = "threat-scanner-v2"

type cacheEntry struct {
	Verdict   ThreatVerdict
	CreatedAt time.Time
	ExpiresAt time.Time
	Model     string
	BodyHash  string
}

type VerdictCache struct {
	mu    sync.Mutex
	items map[string]cacheEntry
}

func NewVerdictCache() *VerdictCache {
	return &VerdictCache{items: make(map[string]cacheEntry)}
}

func CacheKey(input ScanInput) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s", input.Method, input.URL, input.StatusCode, input.ContentType, input.BodyHash, scannerVersion, rulesVersion, redactionVersion)))
	return hex.EncodeToString(sum[:])
}

func (c *VerdictCache) Get(key string) (ThreatVerdict, bool) {
	if c == nil {
		return ThreatVerdict{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.items[key]
	if !ok {
		return ThreatVerdict{}, false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(c.items, key)
		return ThreatVerdict{}, false
	}
	return entry.Verdict, true
}

func (c *VerdictCache) Set(key string, verdict ThreatVerdict, model, bodyHash string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()
	c.items[key] = cacheEntry{
		Verdict:   verdict,
		CreatedAt: now,
		ExpiresAt: now.Add(cacheTTL(verdict.Action)),
		Model:     model,
		BodyHash:  bodyHash,
	}
}

func cacheTTL(action string) time.Duration {
	switch action {
	case ActionWarn:
		return 24 * time.Hour
	case ActionBlock, ActionQuarantine:
		return 7 * 24 * time.Hour
	default:
		return 6 * time.Hour
	}
}
