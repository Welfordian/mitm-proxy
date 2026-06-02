package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cachepkg "mitm-proxy/internal/cache"
	"mitm-proxy/internal/events"

	_ "modernc.org/sqlite"
)

var DashboardTables = []string{
	"traffic_flows",
	"traffic_headers",
	"traffic_bodies",
	"certificates",
	"blocked_ports",
	"blocked_domains",
	"blocked_ips",
	"deployments",
	"audit_log",
	"admin_users",
	"settings",
	"threat_events",
	"threat_verdict_cache",
	"threat_rules",
	"repeater_cases",
	"repeater_runs",
	"research_scopes",
	"cache_entries",
	"ai_notes",
	"proxy_users",
	"proxy_acl_rules",
	"pentest_maps",
	"pentest_endpoints",
	"pentest_parameters",
	"pentest_observations",
}

type AuditEntry struct {
	ID        int64           `json:"id"`
	CreatedAt time.Time       `json:"created_at"`
	Actor     string          `json:"actor"`
	Action    string          `json:"action"`
	Details   json.RawMessage `json:"details,omitempty"`
	RemoteIP  string          `json:"remote_ip,omitempty"`
}

type AdminUser struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type ProxyUser struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

type ProxyACLRule struct {
	ID             string    `json:"id"`
	Priority       int       `json:"priority"`
	Enabled        bool      `json:"enabled"`
	Action         string    `json:"action"`
	Name           string    `json:"name"`
	Description    string    `json:"description,omitempty"`
	Users          []string  `json:"users,omitempty"`
	SourceIPs      []string  `json:"source_ips,omitempty"`
	HostPatterns   []string  `json:"host_patterns,omitempty"`
	PortPatterns   []string  `json:"port_patterns,omitempty"`
	MethodPatterns []string  `json:"method_patterns,omitempty"`
	ScopeIDs       []string  `json:"scope_ids,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type TrafficFlow struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	Method     string    `json:"method,omitempty"`
	URL        string    `json:"url,omitempty"`
	Host       string    `json:"host,omitempty"`
	Status     int       `json:"status,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	MIMEType   string    `json:"mime_type,omitempty"`
	RemoteIP   string    `json:"remote_ip,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	Bytes      int64     `json:"bytes,omitempty"`
	CacheHit   bool      `json:"cache_hit,omitempty"`
	Blocked    bool      `json:"blocked,omitempty"`
	RuleID     string    `json:"rule_id,omitempty"`
	ScopeID    string    `json:"scope_id,omitempty"`
	ProxyUser  string    `json:"proxy_user,omitempty"`
}

type HeaderRecord struct {
	Direction string `json:"direction"`
	Name      string `json:"name"`
	Value     string `json:"value"`
}

type TrafficDetail struct {
	TrafficFlow
	Headers      []HeaderRecord      `json:"headers,omitempty"`
	QueryParams  map[string][]string `json:"query_params,omitempty"`
	Cookies      map[string]string   `json:"cookies,omitempty"`
	RequestBody  string              `json:"request_body,omitempty"`
	ResponseBody string              `json:"response_body,omitempty"`
}

type CertificateRecord struct {
	ID          int64     `json:"id"`
	Host        string    `json:"host,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

type CertificatePage struct {
	Items   []CertificateRecord `json:"items"`
	Total   int                 `json:"total"`
	HasMore bool                `json:"has_more"`
}

type TrafficStats struct {
	Total    int64 `json:"total"`
	Blocked  int64 `json:"blocked"`
	CacheHit int64 `json:"cache_hit"`
}

type RepeaterCase struct {
	ID           string              `json:"id"`
	CreatedAt    time.Time           `json:"created_at"`
	UpdatedAt    time.Time           `json:"updated_at"`
	SourceFlowID string              `json:"source_flow_id,omitempty"`
	Name         string              `json:"name"`
	Method       string              `json:"method"`
	URL          string              `json:"url"`
	Headers      map[string][]string `json:"headers"`
	Body         string              `json:"body"`
	TimeoutMS    int                 `json:"timeout_ms"`
	ScopeID      string              `json:"scope_id,omitempty"`
}

type ResearchScope struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Enabled        bool      `json:"enabled"`
	HostPatterns   []string  `json:"host_patterns"`
	URLPatterns    []string  `json:"url_patterns"`
	MethodPatterns []string  `json:"method_patterns"`
}

type RepeaterRun struct {
	ID              string              `json:"id"`
	CaseID          string              `json:"case_id"`
	CreatedAt       time.Time           `json:"created_at"`
	Status          int                 `json:"status,omitempty"`
	DurationMS      int64               `json:"duration_ms,omitempty"`
	Bytes           int64               `json:"bytes,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	ResponseBody    string              `json:"response_body,omitempty"`
	Error           string              `json:"error,omitempty"`
}

type RepeaterCaseDetail struct {
	Case RepeaterCase  `json:"case"`
	Runs []RepeaterRun `json:"runs"`
}

type PentestMap struct {
	ID                string    `json:"id"`
	ScopeID           string    `json:"scope_id,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	Name              string    `json:"name"`
	SourceFlowCount   int       `json:"source_flow_count"`
	EndpointCount     int       `json:"endpoint_count"`
	ParameterCount    int       `json:"parameter_count"`
	IncludeOutOfScope bool      `json:"include_out_of_scope,omitempty"`
}

type PentestEndpoint struct {
	ID                   string         `json:"id"`
	MapID                string         `json:"map_id"`
	Method               string         `json:"method"`
	Scheme               string         `json:"scheme"`
	Host                 string         `json:"host"`
	Path                 string         `json:"path"`
	NormalizedPath       string         `json:"normalized_path"`
	StatusSummary        map[string]int `json:"status_summary"`
	ContentTypes         []string       `json:"content_types"`
	HasAuth              bool           `json:"has_auth"`
	HasCookies           bool           `json:"has_cookies"`
	HasRequestBody       bool           `json:"has_request_body"`
	HasResponseBody      bool           `json:"has_response_body"`
	CacheHit             bool           `json:"cache_hit"`
	ProxyUsers           []string       `json:"proxy_users,omitempty"`
	ParameterCount       int            `json:"parameter_count"`
	RepresentativeFlowID string         `json:"representative_flow_id,omitempty"`
}

type PentestParameter struct {
	ID                   string   `json:"id"`
	MapID                string   `json:"map_id"`
	EndpointID           string   `json:"endpoint_id"`
	Name                 string   `json:"name"`
	Location             string   `json:"location"`
	ObservedTypes        []string `json:"observed_types"`
	Examples             []string `json:"examples,omitempty"`
	EndpointCount        int      `json:"endpoint_count"`
	Reflected            bool     `json:"reflected"`
	Interesting          bool     `json:"interesting"`
	RepresentativeFlowID string   `json:"representative_flow_id,omitempty"`
}

type PentestObservation struct {
	ID                   string          `json:"id"`
	MapID                string          `json:"map_id"`
	EndpointID           string          `json:"endpoint_id,omitempty"`
	Kind                 string          `json:"kind"`
	Severity             string          `json:"severity"`
	Title                string          `json:"title"`
	Summary              string          `json:"summary"`
	Evidence             json.RawMessage `json:"evidence_json,omitempty"`
	RepresentativeFlowID string          `json:"representative_flow_id,omitempty"`
}

type PentestMapDetail struct {
	Map          PentestMap           `json:"map"`
	Endpoints    []PentestEndpoint    `json:"endpoints"`
	Parameters   []PentestParameter   `json:"parameters"`
	Observations []PentestObservation `json:"observations"`
}

type AINote struct {
	ID         string          `json:"id"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	Kind       string          `json:"kind"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	ScopeID    string          `json:"scope_id,omitempty"`
	Model      string          `json:"model,omitempty"`
	PromptHash string          `json:"prompt_hash,omitempty"`
	Title      string          `json:"title"`
	Summary    string          `json:"summary,omitempty"`
	Content    json.RawMessage `json:"content_json"`
}

type AINoteFilter struct {
	TargetType string
	TargetID   string
	ScopeID    string
	Limit      int
}

type Store struct {
	db      *sql.DB
	writeMu sync.Mutex
}

func Open(path string) (*Store, error) {
	if path == "" {
		path = "dashboard.db"
	}
	if filepath.Ext(path) == "" {
		path += ".db"
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &Store{db: db}
	if err := store.configureSQLite(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) configureSQLite(ctx context.Context) error {
	for _, statement := range []string{
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = NORMAL`,
		`PRAGMA foreign_keys = ON`,
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure sqlite store %q: %w", statement, err)
		}
	}
	return nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) SaveCacheEntry(ctx context.Context, entry cachepkg.StoredEntry) error {
	if s == nil {
		return nil
	}
	if strings.TrimSpace(entry.Key) == "" || strings.TrimSpace(entry.URL) == "" {
		return fmt.Errorf("save cache entry: key and url are required")
	}
	if entry.Status == http.StatusNotModified && len(entry.Body) == 0 {
		return nil
	}
	if entry.StoredAt.IsZero() {
		entry.StoredAt = time.Now().UTC()
	}
	if entry.ExpiresAt.IsZero() {
		entry.ExpiresAt = entry.StoredAt
	}
	if entry.Host == "" {
		if parsed, err := url.Parse(entry.URL); err == nil {
			entry.Host = parsed.Hostname()
		}
	}
	if entry.Headers == nil {
		entry.Headers = http.Header{}
	}
	if entry.Size == 0 {
		entry.Size = int64(len(entry.Body))
	}
	if entry.ContentType == "" {
		entry.ContentType = entry.Headers.Get("Content-Type")
	}
	headersJSON, err := json.Marshal(entry.Headers)
	if err != nil {
		return fmt.Errorf("marshal cache headers: %w", err)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO cache_entries (cache_key, url, host, status, headers_json, body, stored_at, expires_at, size, content_type)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(cache_key) DO UPDATE SET
			url=excluded.url,
			host=excluded.host,
			status=excluded.status,
			headers_json=excluded.headers_json,
			body=excluded.body,
			stored_at=excluded.stored_at,
			expires_at=excluded.expires_at,
			size=excluded.size,
			content_type=excluded.content_type`,
		entry.Key, entry.URL, entry.Host, entry.Status, string(headersJSON), entry.Body,
		entry.StoredAt.UTC().Format(time.RFC3339Nano), entry.ExpiresAt.UTC().Format(time.RFC3339Nano), entry.Size, entry.ContentType)
	if err != nil {
		return fmt.Errorf("save cache entry: %w", err)
	}
	return nil
}

func (s *Store) LoadCacheEntry(ctx context.Context, key string) (cachepkg.StoredEntry, error) {
	if s == nil {
		return cachepkg.StoredEntry{}, os.ErrNotExist
	}
	var entry cachepkg.StoredEntry
	var headersJSON, storedAt, expiresAt string
	row := s.db.QueryRowContext(ctx,
		`SELECT cache_key, url, host, status, headers_json, body, stored_at, expires_at, size, COALESCE(content_type, '')
		 FROM cache_entries WHERE cache_key = ?`, key)
	if err := row.Scan(&entry.Key, &entry.URL, &entry.Host, &entry.Status, &headersJSON, &entry.Body, &storedAt, &expiresAt, &entry.Size, &entry.ContentType); err != nil {
		if err == sql.ErrNoRows {
			return cachepkg.StoredEntry{}, os.ErrNotExist
		}
		return cachepkg.StoredEntry{}, fmt.Errorf("load cache entry: %w", err)
	}
	if err := decodeCacheEntry(&entry, headersJSON, storedAt, expiresAt); err != nil {
		return cachepkg.StoredEntry{}, err
	}
	if shouldPruneCacheEntry(entry) {
		_ = s.DeleteCacheEntry(ctx, key)
		return cachepkg.StoredEntry{}, os.ErrNotExist
	}
	entry.ViewURL = "/api/cache/resource?key=" + url.QueryEscape(entry.Key)
	return entry, nil
}

func (s *Store) ListCacheEntries(ctx context.Context, limit, offset int, search string) (cachepkg.EntryPage, error) {
	if s == nil {
		return cachepkg.EntryPage{Items: []cachepkg.StoredEntry{}}, nil
	}
	if limit <= 0 {
		limit = 10
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	_ = s.PruneCacheEntries(ctx)

	where, args := cacheSearchWhere(search)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cache_entries`+where, args...).Scan(&total); err != nil {
		return cachepkg.EntryPage{}, fmt.Errorf("count cache entries: %w", err)
	}

	queryArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx,
		`SELECT cache_key, url, host, status, headers_json, stored_at, expires_at, size, COALESCE(content_type, '')
		 FROM cache_entries`+where+` ORDER BY stored_at DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return cachepkg.EntryPage{}, fmt.Errorf("list cache entries: %w", err)
	}
	defer rows.Close()

	items := []cachepkg.StoredEntry{}
	for rows.Next() {
		var entry cachepkg.StoredEntry
		var headersJSON, storedAt, expiresAt string
		if err := rows.Scan(&entry.Key, &entry.URL, &entry.Host, &entry.Status, &headersJSON, &storedAt, &expiresAt, &entry.Size, &entry.ContentType); err != nil {
			return cachepkg.EntryPage{}, fmt.Errorf("scan cache entry: %w", err)
		}
		if err := decodeCacheEntry(&entry, headersJSON, storedAt, expiresAt); err != nil {
			return cachepkg.EntryPage{}, err
		}
		entry.ViewURL = "/api/cache/resource?key=" + url.QueryEscape(entry.Key)
		items = append(items, entry)
	}
	if err := rows.Err(); err != nil {
		return cachepkg.EntryPage{}, fmt.Errorf("iterate cache entries: %w", err)
	}
	return cachepkg.EntryPage{Items: items, Total: total, HasMore: offset+len(items) < total}, nil
}

func (s *Store) CacheStats(ctx context.Context) (int64, int, error) {
	if s == nil {
		return 0, 0, nil
	}
	_ = s.PruneCacheEntries(ctx)
	var size sql.NullInt64
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(size), 0), COUNT(*) FROM cache_entries`).Scan(&size, &count); err != nil {
		return 0, 0, fmt.Errorf("cache stats: %w", err)
	}
	return size.Int64, count, nil
}

func (s *Store) DeleteCacheEntry(ctx context.Context, key string) error {
	if s == nil {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `DELETE FROM cache_entries WHERE cache_key = ?`, key)
	if err != nil {
		return fmt.Errorf("delete cache entry: %w", err)
	}
	return nil
}

func (s *Store) PurgeCache(ctx context.Context, host string) (int, error) {
	if s == nil {
		return 0, nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var result sql.Result
	var err error
	if strings.TrimSpace(host) == "" {
		result, err = s.db.ExecContext(ctx, `DELETE FROM cache_entries`)
	} else {
		result, err = s.db.ExecContext(ctx, `DELETE FROM cache_entries WHERE host = ?`, strings.TrimSpace(host))
	}
	if err != nil {
		return 0, fmt.Errorf("purge cache: %w", err)
	}
	removed, _ := result.RowsAffected()
	return int(removed), nil
}

func (s *Store) PruneCacheEntries(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM cache_entries
		 WHERE expires_at <= ? OR (status = ? AND size = 0)`,
		time.Now().UTC().Format(time.RFC3339Nano), http.StatusNotModified)
	if err != nil {
		return fmt.Errorf("prune cache entries: %w", err)
	}
	return nil
}

func cacheSearchWhere(search string) (string, []any) {
	term := strings.ToLower(strings.TrimSpace(search))
	if term == "" {
		return "", nil
	}
	like := "%" + term + "%"
	return ` WHERE lower(cache_key) LIKE ?
		OR lower(url) LIKE ?
		OR lower(host) LIKE ?
		OR CAST(status AS TEXT) LIKE ?
		OR CAST(size AS TEXT) LIKE ?
		OR lower(COALESCE(content_type, '')) LIKE ?`, []any{like, like, like, like, like, like}
}

func decodeCacheEntry(entry *cachepkg.StoredEntry, headersJSON, storedAt, expiresAt string) error {
	entry.Headers = http.Header{}
	if strings.TrimSpace(headersJSON) != "" {
		if err := json.Unmarshal([]byte(headersJSON), &entry.Headers); err != nil {
			return fmt.Errorf("decode cache headers: %w", err)
		}
	}
	entry.StoredAt, _ = time.Parse(time.RFC3339Nano, storedAt)
	entry.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
	if entry.ContentType == "" {
		entry.ContentType = entry.Headers.Get("Content-Type")
	}
	return nil
}

func shouldPruneCacheEntry(entry cachepkg.StoredEntry) bool {
	return (!entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(time.Now().UTC())) ||
		(entry.Status == http.StatusNotModified && len(entry.Body) == 0)
}

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS traffic_flows (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			method TEXT,
			url TEXT,
			host TEXT,
			status INTEGER,
			protocol TEXT,
			mime_type TEXT,
			remote_ip TEXT,
			duration_ms INTEGER,
			bytes INTEGER,
			cache_hit INTEGER NOT NULL DEFAULT 0,
			blocked INTEGER NOT NULL DEFAULT 0,
			rule_id TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS traffic_headers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			flow_id TEXT NOT NULL,
			direction TEXT NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS traffic_bodies (
			flow_id TEXT PRIMARY KEY,
			request_body BLOB,
			response_body BLOB
		)`,
		`CREATE TABLE IF NOT EXISTS certificates (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host TEXT,
			subject TEXT,
			fingerprint TEXT,
			created_at TEXT,
			expires_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS blocked_ports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			port INTEGER NOT NULL,
			reason TEXT,
			enabled INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS blocked_domains (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pattern TEXT NOT NULL,
			reason TEXT,
			enabled INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS blocked_ips (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pattern TEXT NOT NULL,
			reason TEXT,
			enabled INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS deployments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			kind TEXT NOT NULL,
			config TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			created_at TEXT NOT NULL,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			details TEXT,
			remote_ip TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS admin_users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			role TEXT NOT NULL DEFAULT 'read',
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS threat_events (
			id TEXT PRIMARY KEY,
			timestamp TEXT NOT NULL,
			target TEXT NOT NULL,
			method TEXT,
			url TEXT,
			host TEXT,
			remote_ip TEXT,
			status_code INTEGER,
			content_type TEXT,
			body_hash TEXT,
			verdict TEXT NOT NULL,
			confidence REAL NOT NULL,
			category TEXT,
			reason TEXT,
			action TEXT NOT NULL,
			model TEXT,
			scan_latency_ms INTEGER,
			ai_used INTEGER NOT NULL,
			blocked INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS threat_verdict_cache (
			cache_key TEXT PRIMARY KEY,
			verdict_json TEXT NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS threat_rules (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			pattern TEXT NOT NULL,
			action TEXT NOT NULL,
			enabled INTEGER NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS repeater_cases (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			source_flow_id TEXT,
			name TEXT NOT NULL,
			method TEXT NOT NULL,
			url TEXT NOT NULL,
			headers_json TEXT NOT NULL,
			body BLOB,
			timeout_ms INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS repeater_runs (
			id TEXT PRIMARY KEY,
			case_id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			status INTEGER,
			duration_ms INTEGER,
			bytes INTEGER,
			response_headers_json TEXT NOT NULL,
			response_body BLOB,
			error TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS research_scopes (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			host_patterns_json TEXT NOT NULL,
			url_patterns_json TEXT NOT NULL,
			method_patterns_json TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS cache_entries (
			cache_key TEXT PRIMARY KEY,
			url TEXT NOT NULL,
			host TEXT NOT NULL,
			status INTEGER NOT NULL,
			headers_json TEXT NOT NULL,
			body BLOB NOT NULL,
			stored_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			size INTEGER NOT NULL,
			content_type TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS ai_notes (
			id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			kind TEXT NOT NULL,
			target_type TEXT NOT NULL,
			target_id TEXT NOT NULL,
			scope_id TEXT,
			model TEXT,
			prompt_hash TEXT,
			title TEXT NOT NULL,
			summary TEXT,
			content_json TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS proxy_users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_used_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS proxy_acl_rules (
			id TEXT PRIMARY KEY,
			priority INTEGER NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			action TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			users_json TEXT NOT NULL,
			source_ips_json TEXT NOT NULL,
			host_patterns_json TEXT NOT NULL,
			port_patterns_json TEXT NOT NULL,
			method_patterns_json TEXT NOT NULL,
			scope_ids_json TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS pentest_maps (
			id TEXT PRIMARY KEY,
			scope_id TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			name TEXT NOT NULL,
			source_flow_count INTEGER NOT NULL,
			endpoint_count INTEGER NOT NULL,
			parameter_count INTEGER NOT NULL,
			include_out_of_scope INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS pentest_endpoints (
			id TEXT PRIMARY KEY,
			map_id TEXT NOT NULL,
			method TEXT NOT NULL,
			scheme TEXT NOT NULL,
			host TEXT NOT NULL,
			path TEXT NOT NULL,
			normalized_path TEXT NOT NULL,
			status_summary_json TEXT NOT NULL,
			content_types_json TEXT NOT NULL,
			has_auth INTEGER NOT NULL,
			has_cookies INTEGER NOT NULL,
			has_request_body INTEGER NOT NULL,
			has_response_body INTEGER NOT NULL,
			cache_hit INTEGER NOT NULL,
			proxy_users_json TEXT NOT NULL,
			parameter_count INTEGER NOT NULL,
			representative_flow_id TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS pentest_parameters (
			id TEXT PRIMARY KEY,
			map_id TEXT NOT NULL,
			endpoint_id TEXT NOT NULL,
			name TEXT NOT NULL,
			location TEXT NOT NULL,
			observed_types_json TEXT NOT NULL,
			examples_json TEXT NOT NULL,
			endpoint_count INTEGER NOT NULL,
			reflected INTEGER NOT NULL,
			interesting INTEGER NOT NULL,
			representative_flow_id TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS pentest_observations (
			id TEXT PRIMARY KEY,
			map_id TEXT NOT NULL,
			endpoint_id TEXT,
			kind TEXT NOT NULL,
			severity TEXT NOT NULL,
			title TEXT NOT NULL,
			summary TEXT NOT NULL,
			evidence_json TEXT NOT NULL,
			representative_flow_id TEXT
		)`,
	}

	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate sqlite store: %w", err)
		}
	}
	_ = s.addColumnIfMissing(ctx, "traffic_flows", "mime_type", "TEXT")
	_ = s.addColumnIfMissing(ctx, "traffic_flows", "bytes", "INTEGER")
	_ = s.addColumnIfMissing(ctx, "traffic_flows", "cache_hit", "INTEGER NOT NULL DEFAULT 0")
	_ = s.addColumnIfMissing(ctx, "traffic_flows", "blocked", "INTEGER NOT NULL DEFAULT 0")
	_ = s.addColumnIfMissing(ctx, "traffic_flows", "rule_id", "TEXT")
	_ = s.addColumnIfMissing(ctx, "traffic_flows", "scope_id", "TEXT")
	_ = s.addColumnIfMissing(ctx, "traffic_flows", "proxy_user", "TEXT")
	_ = s.addColumnIfMissing(ctx, "repeater_cases", "scope_id", "TEXT")
	_ = s.addColumnIfMissing(ctx, "threat_events", "scope_id", "TEXT")
	_ = s.addColumnIfMissing(ctx, "admin_users", "role", "TEXT NOT NULL DEFAULT 'read'")
	_, _ = s.db.ExecContext(ctx, `DELETE FROM certificates WHERE id NOT IN (SELECT MAX(id) FROM certificates GROUP BY COALESCE(host, ''))`)
	_, _ = s.db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_host ON certificates(host)`)

	return nil
}

func (s *Store) addColumnIfMissing(ctx context.Context, table, column, definition string) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition))
	return err
}

func (s *Store) AddAudit(ctx context.Context, actor, action string, details any, remoteIP string) error {
	if s == nil {
		return nil
	}

	var raw []byte
	if details != nil {
		var err error
		raw, err = json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal audit details: %w", err)
		}
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (created_at, actor, action, details, remote_ip) VALUES (?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339Nano), actor, action, string(raw), remoteIP,
	)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}

	return nil
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, created_at, actor, action, COALESCE(details, ''), COALESCE(remote_ip, '')
		 FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	entries := []AuditEntry{}
	for rows.Next() {
		var entry AuditEntry
		var createdAt string
		var details string
		if err := rows.Scan(&entry.ID, &createdAt, &entry.Actor, &entry.Action, &details, &entry.RemoteIP); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		entry.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		if details != "" {
			entry.Details = json.RawMessage(details)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit entries: %w", err)
	}

	return entries, nil
}

func (s *Store) CreateAINote(ctx context.Context, note AINote) (AINote, error) {
	if s == nil {
		return note, nil
	}
	note = normalizeAINote(note)
	if note.ID == "" {
		note.ID = newStoreID()
	}
	now := time.Now().UTC()
	if note.CreatedAt.IsZero() {
		note.CreatedAt = now
	}
	note.UpdatedAt = now
	if len(note.Content) == 0 {
		note.Content = json.RawMessage(`{}`)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ai_notes (id, created_at, updated_at, kind, target_type, target_id, scope_id, model, prompt_hash, title, summary, content_json)
		 VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?)`,
		note.ID, note.CreatedAt.Format(time.RFC3339Nano), note.UpdatedAt.Format(time.RFC3339Nano),
		note.Kind, note.TargetType, note.TargetID, note.ScopeID, note.Model, note.PromptHash,
		note.Title, note.Summary, string(note.Content))
	if err != nil {
		return AINote{}, fmt.Errorf("insert ai note: %w", err)
	}
	return note, nil
}

func (s *Store) ListAINotes(ctx context.Context, filter AINoteFilter) ([]AINote, error) {
	if s == nil {
		return nil, nil
	}
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	where := []string{}
	args := []any{}
	if strings.TrimSpace(filter.TargetType) != "" {
		where = append(where, "target_type = ?")
		args = append(args, strings.TrimSpace(filter.TargetType))
	}
	if strings.TrimSpace(filter.TargetID) != "" {
		where = append(where, "target_id = ?")
		args = append(args, strings.TrimSpace(filter.TargetID))
	}
	if strings.TrimSpace(filter.ScopeID) != "" {
		scopeID := strings.TrimSpace(filter.ScopeID)
		if scopeID == "__out_of_scope__" {
			where = append(where, "(scope_id IS NULL OR scope_id = '')")
		} else {
			where = append(where, "scope_id = ?")
			args = append(args, scopeID)
		}
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, created_at, updated_at, kind, target_type, target_id, COALESCE(scope_id, ''), COALESCE(model, ''),
		 COALESCE(prompt_hash, ''), title, COALESCE(summary, ''), content_json
		 FROM ai_notes`+clause+` ORDER BY created_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("query ai notes: %w", err)
	}
	defer rows.Close()

	notes := []AINote{}
	for rows.Next() {
		note, err := scanAINote(rows)
		if err != nil {
			return nil, err
		}
		notes = append(notes, note)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ai notes: %w", err)
	}
	return notes, nil
}

func (s *Store) DeleteAINote(ctx context.Context, id string) error {
	if s == nil {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM ai_notes WHERE id = ?`, strings.TrimSpace(id)); err != nil {
		return fmt.Errorf("delete ai note: %w", err)
	}
	return nil
}

func (s *Store) SavePentestMap(ctx context.Context, m PentestMap, endpoints []PentestEndpoint, parameters []PentestParameter, observations []PentestObservation) (PentestMap, error) {
	if s == nil {
		return PentestMap{}, nil
	}
	now := time.Now().UTC()
	if strings.TrimSpace(m.ID) == "" {
		m.ID = newStoreID()
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = now
	}
	m.UpdatedAt = now
	if strings.TrimSpace(m.Name) == "" {
		m.Name = "Pentest map"
	}
	m.SourceFlowCount = maxInt(m.SourceFlowCount, 0)
	m.EndpointCount = len(endpoints)
	m.ParameterCount = len(parameters)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PentestMap{}, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO pentest_maps (id, scope_id, created_at, updated_at, name, source_flow_count, endpoint_count, parameter_count, include_out_of_scope)
		 VALUES (?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, strings.TrimSpace(m.ScopeID), m.CreatedAt.Format(time.RFC3339Nano), m.UpdatedAt.Format(time.RFC3339Nano), m.Name, m.SourceFlowCount, m.EndpointCount, m.ParameterCount, boolInt(m.IncludeOutOfScope)); err != nil {
		return PentestMap{}, fmt.Errorf("insert pentest map: %w", err)
	}

	for _, endpoint := range endpoints {
		if strings.TrimSpace(endpoint.ID) == "" {
			endpoint.ID = newStoreID()
		}
		endpoint.MapID = m.ID
		statusJSON, _ := json.Marshal(endpoint.StatusSummary)
		contentTypesJSON, _ := json.Marshal(endpoint.ContentTypes)
		proxyUsersJSON, _ := json.Marshal(endpoint.ProxyUsers)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO pentest_endpoints
			 (id, map_id, method, scheme, host, path, normalized_path, status_summary_json, content_types_json, has_auth, has_cookies, has_request_body, has_response_body, cache_hit, proxy_users_json, parameter_count, representative_flow_id)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''))`,
			endpoint.ID, endpoint.MapID, endpoint.Method, endpoint.Scheme, endpoint.Host, endpoint.Path, endpoint.NormalizedPath, string(statusJSON), string(contentTypesJSON),
			boolInt(endpoint.HasAuth), boolInt(endpoint.HasCookies), boolInt(endpoint.HasRequestBody), boolInt(endpoint.HasResponseBody), boolInt(endpoint.CacheHit),
			string(proxyUsersJSON), endpoint.ParameterCount, endpoint.RepresentativeFlowID); err != nil {
			return PentestMap{}, fmt.Errorf("insert pentest endpoint: %w", err)
		}
	}

	for _, parameter := range parameters {
		if strings.TrimSpace(parameter.ID) == "" {
			parameter.ID = newStoreID()
		}
		parameter.MapID = m.ID
		observedTypesJSON, _ := json.Marshal(parameter.ObservedTypes)
		examplesJSON, _ := json.Marshal(parameter.Examples)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO pentest_parameters
			 (id, map_id, endpoint_id, name, location, observed_types_json, examples_json, endpoint_count, reflected, interesting, representative_flow_id)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''))`,
			parameter.ID, parameter.MapID, parameter.EndpointID, parameter.Name, parameter.Location, string(observedTypesJSON), string(examplesJSON),
			parameter.EndpointCount, boolInt(parameter.Reflected), boolInt(parameter.Interesting), parameter.RepresentativeFlowID); err != nil {
			return PentestMap{}, fmt.Errorf("insert pentest parameter: %w", err)
		}
	}

	for _, observation := range observations {
		if strings.TrimSpace(observation.ID) == "" {
			observation.ID = newStoreID()
		}
		observation.MapID = m.ID
		evidence := observation.Evidence
		if len(evidence) == 0 {
			evidence = json.RawMessage(`{}`)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO pentest_observations
			 (id, map_id, endpoint_id, kind, severity, title, summary, evidence_json, representative_flow_id)
			 VALUES (?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, NULLIF(?, ''))`,
			observation.ID, observation.MapID, observation.EndpointID, observation.Kind, observation.Severity, observation.Title, observation.Summary, string(evidence), observation.RepresentativeFlowID); err != nil {
			return PentestMap{}, fmt.Errorf("insert pentest observation: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return PentestMap{}, err
	}
	return m, nil
}

func (s *Store) ListPentestMaps(ctx context.Context, scopeID string, includeOutOfScope bool) ([]PentestMap, error) {
	if s == nil {
		return nil, nil
	}
	where, args := pentestScopeWhere(scopeID, includeOutOfScope)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, COALESCE(scope_id, ''), created_at, updated_at, name, source_flow_count, endpoint_count, parameter_count, include_out_of_scope
		 FROM pentest_maps`+where+` ORDER BY updated_at DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("query pentest maps: %w", err)
	}
	defer rows.Close()
	var maps []PentestMap
	for rows.Next() {
		m, err := scanPentestMap(rows)
		if err != nil {
			return nil, err
		}
		maps = append(maps, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return maps, nil
}

func (s *Store) GetPentestMapDetail(ctx context.Context, id string) (PentestMapDetail, bool, error) {
	if s == nil {
		return PentestMapDetail{}, false, nil
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(scope_id, ''), created_at, updated_at, name, source_flow_count, endpoint_count, parameter_count, include_out_of_scope
		 FROM pentest_maps WHERE id = ?`, strings.TrimSpace(id))
	m, err := scanPentestMap(row)
	if err == sql.ErrNoRows {
		return PentestMapDetail{}, false, nil
	}
	if err != nil {
		return PentestMapDetail{}, false, err
	}
	endpoints, err := s.listPentestEndpoints(ctx, m.ID)
	if err != nil {
		return PentestMapDetail{}, false, err
	}
	parameters, err := s.listPentestParameters(ctx, m.ID)
	if err != nil {
		return PentestMapDetail{}, false, err
	}
	observations, err := s.listPentestObservations(ctx, m.ID)
	if err != nil {
		return PentestMapDetail{}, false, err
	}
	return PentestMapDetail{Map: m, Endpoints: endpoints, Parameters: parameters, Observations: observations}, true, nil
}

func (s *Store) GetPentestEndpoint(ctx context.Context, mapID, endpointID string) (PentestEndpoint, bool, error) {
	if s == nil {
		return PentestEndpoint{}, false, nil
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT id, map_id, method, scheme, host, path, normalized_path, status_summary_json, content_types_json, has_auth, has_cookies, has_request_body, has_response_body, cache_hit, proxy_users_json, parameter_count, COALESCE(representative_flow_id, '')
		 FROM pentest_endpoints WHERE map_id = ? AND id = ?`, strings.TrimSpace(mapID), strings.TrimSpace(endpointID))
	endpoint, err := scanPentestEndpoint(row)
	if err == sql.ErrNoRows {
		return PentestEndpoint{}, false, nil
	}
	if err != nil {
		return PentestEndpoint{}, false, err
	}
	return endpoint, true, nil
}

func (s *Store) DeletePentestMap(ctx context.Context, id string) error {
	if s == nil {
		return nil
	}
	id = strings.TrimSpace(id)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`DELETE FROM pentest_observations WHERE map_id = ?`,
		`DELETE FROM pentest_parameters WHERE map_id = ?`,
		`DELETE FROM pentest_endpoints WHERE map_id = ?`,
		`DELETE FROM pentest_maps WHERE id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, statement, id); err != nil {
			return fmt.Errorf("delete pentest map: %w", err)
		}
	}
	return tx.Commit()
}

func (s *Store) listPentestEndpoints(ctx context.Context, mapID string) ([]PentestEndpoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, map_id, method, scheme, host, path, normalized_path, status_summary_json, content_types_json, has_auth, has_cookies, has_request_body, has_response_body, cache_hit, proxy_users_json, parameter_count, COALESCE(representative_flow_id, '')
		 FROM pentest_endpoints WHERE map_id = ? ORDER BY host, normalized_path, method`, mapID)
	if err != nil {
		return nil, fmt.Errorf("query pentest endpoints: %w", err)
	}
	defer rows.Close()
	var endpoints []PentestEndpoint
	for rows.Next() {
		endpoint, err := scanPentestEndpoint(rows)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, rows.Err()
}

func (s *Store) listPentestParameters(ctx context.Context, mapID string) ([]PentestParameter, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, map_id, endpoint_id, name, location, observed_types_json, examples_json, endpoint_count, reflected, interesting, COALESCE(representative_flow_id, '')
		 FROM pentest_parameters WHERE map_id = ? ORDER BY interesting DESC, reflected DESC, name, location`, mapID)
	if err != nil {
		return nil, fmt.Errorf("query pentest parameters: %w", err)
	}
	defer rows.Close()
	var parameters []PentestParameter
	for rows.Next() {
		parameter, err := scanPentestParameter(rows)
		if err != nil {
			return nil, err
		}
		parameters = append(parameters, parameter)
	}
	return parameters, rows.Err()
}

func (s *Store) listPentestObservations(ctx context.Context, mapID string) ([]PentestObservation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, map_id, COALESCE(endpoint_id, ''), kind, severity, title, summary, evidence_json, COALESCE(representative_flow_id, '')
		 FROM pentest_observations WHERE map_id = ? ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, kind, title`, mapID)
	if err != nil {
		return nil, fmt.Errorf("query pentest observations: %w", err)
	}
	defer rows.Close()
	var observations []PentestObservation
	for rows.Next() {
		observation, err := scanPentestObservation(rows)
		if err != nil {
			return nil, err
		}
		observations = append(observations, observation)
	}
	return observations, rows.Err()
}

func normalizeAINote(note AINote) AINote {
	note.Kind = strings.TrimSpace(note.Kind)
	note.TargetType = strings.TrimSpace(note.TargetType)
	note.TargetID = strings.TrimSpace(note.TargetID)
	note.ScopeID = strings.TrimSpace(note.ScopeID)
	note.Model = strings.TrimSpace(note.Model)
	note.PromptHash = strings.TrimSpace(note.PromptHash)
	note.Title = strings.TrimSpace(note.Title)
	note.Summary = strings.TrimSpace(note.Summary)
	if note.Kind == "" {
		note.Kind = "manual"
	}
	if note.Title == "" {
		note.Title = "AI research note"
	}
	return note
}

func (s *Store) AddAdminUser(ctx context.Context, name, role string) (AdminUser, error) {
	if s == nil {
		return AdminUser{}, nil
	}
	if role == "" {
		role = "read"
	}
	createdAt := time.Now().UTC()
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_users (name, role, created_at) VALUES (?, ?, ?)`,
		name, role, createdAt.Format(time.RFC3339Nano))
	if err != nil {
		return AdminUser{}, fmt.Errorf("insert admin user: %w", err)
	}
	id, _ := result.LastInsertId()
	return AdminUser{ID: id, Name: name, Role: role, CreatedAt: createdAt}, nil
}

func (s *Store) ListAdminUsers(ctx context.Context) ([]AdminUser, error) {
	if s == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, COALESCE(role, 'read'), created_at FROM admin_users ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("query admin users: %w", err)
	}
	defer rows.Close()

	users := []AdminUser{}
	for rows.Next() {
		var user AdminUser
		var createdAt string
		if err := rows.Scan(&user.ID, &user.Name, &user.Role, &createdAt); err != nil {
			return nil, fmt.Errorf("scan admin user: %w", err)
		}
		user.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin users: %w", err)
	}
	return users, nil
}

func (s *Store) DeleteAdminUser(ctx context.Context, id int64) error {
	if s == nil {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM admin_users WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete admin user: %w", err)
	}
	return nil
}

func (s *Store) CreateProxyUser(ctx context.Context, user ProxyUser) (ProxyUser, error) {
	if s == nil {
		return ProxyUser{}, nil
	}
	now := time.Now().UTC()
	user.ID = strings.TrimSpace(user.ID)
	if user.ID == "" {
		user.ID = "proxy-user-" + newStoreID()
	}
	user.Username = strings.TrimSpace(user.Username)
	if user.Username == "" {
		return ProxyUser{}, fmt.Errorf("username is required")
	}
	if strings.TrimSpace(user.PasswordHash) == "" {
		return ProxyUser{}, fmt.Errorf("password hash is required")
	}
	user.CreatedAt = now
	user.UpdatedAt = now
	enabled := 0
	if user.Enabled {
		enabled = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO proxy_users (id, username, password_hash, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		user.ID, user.Username, user.PasswordHash, enabled, user.CreatedAt.Format(time.RFC3339Nano), user.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return ProxyUser{}, fmt.Errorf("insert proxy user: %w", err)
	}
	return user, nil
}

func (s *Store) ListProxyUsers(ctx context.Context) ([]ProxyUser, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, username, password_hash, enabled, created_at, updated_at, COALESCE(last_used_at, '')
		 FROM proxy_users ORDER BY username ASC`)
	if err != nil {
		return nil, fmt.Errorf("query proxy users: %w", err)
	}
	defer rows.Close()
	users := []ProxyUser{}
	for rows.Next() {
		user, err := scanProxyUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate proxy users: %w", err)
	}
	return users, nil
}

func (s *Store) GetProxyUser(ctx context.Context, id string) (ProxyUser, bool, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, enabled, created_at, updated_at, COALESCE(last_used_at, '')
		 FROM proxy_users WHERE id = ?`, id)
	user, err := scanProxyUser(row)
	if err == sql.ErrNoRows {
		return ProxyUser{}, false, nil
	}
	if err != nil {
		return ProxyUser{}, false, err
	}
	return user, true, nil
}

func (s *Store) GetProxyUserByUsername(ctx context.Context, username string) (ProxyUser, bool, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, enabled, created_at, updated_at, COALESCE(last_used_at, '')
		 FROM proxy_users WHERE username = ?`, strings.TrimSpace(username))
	user, err := scanProxyUser(row)
	if err == sql.ErrNoRows {
		return ProxyUser{}, false, nil
	}
	if err != nil {
		return ProxyUser{}, false, err
	}
	return user, true, nil
}

func (s *Store) UpdateProxyUser(ctx context.Context, user ProxyUser) (ProxyUser, error) {
	user.Username = strings.TrimSpace(user.Username)
	if user.ID == "" || user.Username == "" {
		return ProxyUser{}, fmt.Errorf("proxy user id and username are required")
	}
	enabled := 0
	if user.Enabled {
		enabled = 1
	}
	updatedAt := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE proxy_users SET username = ?, enabled = ?, updated_at = ? WHERE id = ?`,
		user.Username, enabled, updatedAt.Format(time.RFC3339Nano), user.ID)
	if err != nil {
		return ProxyUser{}, fmt.Errorf("update proxy user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ProxyUser{}, sql.ErrNoRows
	}
	stored, ok, err := s.GetProxyUser(ctx, user.ID)
	if err != nil {
		return ProxyUser{}, err
	}
	if !ok {
		return ProxyUser{}, sql.ErrNoRows
	}
	return stored, nil
}

func (s *Store) ResetProxyUserPassword(ctx context.Context, id, passwordHash string) (ProxyUser, error) {
	if strings.TrimSpace(passwordHash) == "" {
		return ProxyUser{}, fmt.Errorf("password hash is required")
	}
	updatedAt := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE proxy_users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		passwordHash, updatedAt.Format(time.RFC3339Nano), id)
	if err != nil {
		return ProxyUser{}, fmt.Errorf("reset proxy user password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ProxyUser{}, sql.ErrNoRows
	}
	user, ok, err := s.GetProxyUser(ctx, id)
	if err != nil {
		return ProxyUser{}, err
	}
	if !ok {
		return ProxyUser{}, sql.ErrNoRows
	}
	return user, nil
}

func (s *Store) TouchProxyUserLastUsed(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE proxy_users SET last_used_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("touch proxy user: %w", err)
	}
	return nil
}

func (s *Store) DeleteProxyUser(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM proxy_users WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete proxy user: %w", err)
	}
	return nil
}

func (s *Store) CreateProxyACLRule(ctx context.Context, rule ProxyACLRule) (ProxyACLRule, error) {
	rule = normalizeProxyACLRule(rule)
	now := time.Now().UTC()
	rule.ID = strings.TrimSpace(rule.ID)
	if rule.ID == "" {
		rule.ID = "proxy-acl-" + newStoreID()
	}
	rule.CreatedAt = now
	rule.UpdatedAt = now
	args, err := proxyACLRuleSQLArgs(rule)
	if err != nil {
		return ProxyACLRule{}, err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO proxy_acl_rules
		 (id, priority, enabled, action, name, description, users_json, source_ips_json, host_patterns_json, port_patterns_json, method_patterns_json, scope_ids_json, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...)
	if err != nil {
		return ProxyACLRule{}, fmt.Errorf("insert proxy acl rule: %w", err)
	}
	return rule, nil
}

func (s *Store) ListProxyACLRules(ctx context.Context) ([]ProxyACLRule, error) {
	rows, err := s.db.QueryContext(ctx, proxyACLRuleSelect()+` ORDER BY priority ASC, created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("query proxy acl rules: %w", err)
	}
	defer rows.Close()
	rules := []ProxyACLRule{}
	for rows.Next() {
		rule, err := scanProxyACLRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate proxy acl rules: %w", err)
	}
	return rules, nil
}

func (s *Store) GetProxyACLRule(ctx context.Context, id string) (ProxyACLRule, bool, error) {
	row := s.db.QueryRowContext(ctx, proxyACLRuleSelect()+` WHERE id = ?`, id)
	rule, err := scanProxyACLRule(row)
	if err == sql.ErrNoRows {
		return ProxyACLRule{}, false, nil
	}
	if err != nil {
		return ProxyACLRule{}, false, err
	}
	return rule, true, nil
}

func (s *Store) UpdateProxyACLRule(ctx context.Context, rule ProxyACLRule) (ProxyACLRule, error) {
	rule = normalizeProxyACLRule(rule)
	rule.UpdatedAt = time.Now().UTC()
	args, err := proxyACLRuleSQLArgs(rule)
	if err != nil {
		return ProxyACLRule{}, err
	}
	updateArgs := []any{args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[13], rule.ID}
	res, err := s.db.ExecContext(ctx,
		`UPDATE proxy_acl_rules
		 SET priority = ?, enabled = ?, action = ?, name = ?, description = ?, users_json = ?, source_ips_json = ?, host_patterns_json = ?, port_patterns_json = ?, method_patterns_json = ?, scope_ids_json = ?, updated_at = ?
		 WHERE id = ?`, updateArgs...)
	if err != nil {
		return ProxyACLRule{}, fmt.Errorf("update proxy acl rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ProxyACLRule{}, sql.ErrNoRows
	}
	stored, ok, err := s.GetProxyACLRule(ctx, rule.ID)
	if err != nil {
		return ProxyACLRule{}, err
	}
	if !ok {
		return ProxyACLRule{}, sql.ErrNoRows
	}
	return stored, nil
}

func (s *Store) DeleteProxyACLRule(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM proxy_acl_rules WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete proxy acl rule: %w", err)
	}
	return nil
}

func (s *Store) RecordEvent(ctx context.Context, event events.Event) error {
	if s == nil {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	switch event.Topic {
	case events.TopicTrafficRequestStarted:
		return s.recordTrafficStarted(ctx, event)
	case events.TopicTrafficResponseCompleted:
		return s.recordTrafficCompleted(ctx, event)
	case events.TopicTrafficTunnelOpened:
		return s.recordTunnelOpened(ctx, event)
	case events.TopicTrafficBlocked:
		return s.recordTrafficBlocked(ctx, event)
	case events.TopicTrafficBodyCaptured:
		return s.recordTrafficBody(ctx, event)
	case events.TopicCertGenerated:
		return s.recordCertificate(ctx, event)
	default:
		return nil
	}
}

func (s *Store) ListTraffic(ctx context.Context, limit int) ([]TrafficFlow, error) {
	return s.ListTrafficScoped(ctx, limit, "", true)
}

func (s *Store) ListTrafficScoped(ctx context.Context, limit int, scopeID string, includeOutOfScope bool) ([]TrafficFlow, error) {
	return s.ListTrafficScopedPage(ctx, limit, 0, scopeID, includeOutOfScope, "")
}

func (s *Store) ListTrafficScopedPage(ctx context.Context, limit, offset int, scopeID string, includeOutOfScope bool, search string) ([]TrafficFlow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	where, args := scopedWhere(scopeID, includeOutOfScope)
	if search = strings.TrimSpace(search); search != "" {
		searchWhere := `(LOWER(COALESCE(method, '')) LIKE ? OR LOWER(COALESCE(url, '')) LIKE ? OR LOWER(COALESCE(host, '')) LIKE ? OR CAST(COALESCE(status, 0) AS TEXT) LIKE ? OR LOWER(COALESCE(protocol, '')) LIKE ? OR LOWER(COALESCE(mime_type, '')) LIKE ? OR LOWER(COALESCE(rule_id, '')) LIKE ? OR LOWER(COALESCE(proxy_user, '')) LIKE ?)`
		if where == "" {
			where = " WHERE " + searchWhere
		} else {
			where += " AND " + searchWhere
		}
		term := "%" + strings.ToLower(search) + "%"
		args = append(args, term, term, term, term, term, term, term, term)
	}
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, created_at, COALESCE(method, ''), COALESCE(url, ''), COALESCE(host, ''),
		 COALESCE(status, 0), COALESCE(protocol, ''), COALESCE(mime_type, ''), COALESCE(remote_ip, ''),
		 COALESCE(duration_ms, 0), COALESCE(bytes, 0), cache_hit, blocked, COALESCE(rule_id, ''), COALESCE(scope_id, ''), COALESCE(proxy_user, '')
		 FROM traffic_flows`+where+` ORDER BY created_at DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("query traffic flows: %w", err)
	}
	defer rows.Close()

	flows := []TrafficFlow{}
	for rows.Next() {
		flow, err := scanTrafficFlow(rows)
		if err != nil {
			return nil, err
		}
		flows = append(flows, flow)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate traffic flows: %w", err)
	}
	return flows, nil
}

func scopedWhere(scopeID string, includeOutOfScope bool) (string, []any) {
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		return "", nil
	}
	if scopeID == "__out_of_scope__" {
		return " WHERE COALESCE(scope_id, '') = ''", nil
	}
	if includeOutOfScope {
		return " WHERE (scope_id = ? OR COALESCE(scope_id, '') = '')", []any{scopeID}
	}
	return " WHERE scope_id = ?", []any{scopeID}
}

func pentestScopeWhere(scopeID string, includeOutOfScope bool) (string, []any) {
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		return "", nil
	}
	if scopeID == "__out_of_scope__" {
		return " WHERE COALESCE(scope_id, '') = ''", nil
	}
	if includeOutOfScope {
		return " WHERE (scope_id = ? OR COALESCE(scope_id, '') = '')", []any{scopeID}
	}
	return " WHERE scope_id = ?", []any{scopeID}
}

func (s *Store) GetTraffic(ctx context.Context, id string) (TrafficFlow, bool, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, created_at, COALESCE(method, ''), COALESCE(url, ''), COALESCE(host, ''),
		 COALESCE(status, 0), COALESCE(protocol, ''), COALESCE(mime_type, ''), COALESCE(remote_ip, ''),
		 COALESCE(duration_ms, 0), COALESCE(bytes, 0), cache_hit, blocked, COALESCE(rule_id, ''), COALESCE(scope_id, ''), COALESCE(proxy_user, '')
		 FROM traffic_flows WHERE id = ?`, id)

	flow, err := scanTrafficFlow(row)
	if err == sql.ErrNoRows {
		return TrafficFlow{}, false, nil
	}
	if err != nil {
		return TrafficFlow{}, false, err
	}
	return flow, true, nil
}

func (s *Store) GetTrafficDetail(ctx context.Context, id string) (TrafficDetail, bool, error) {
	flow, ok, err := s.GetTraffic(ctx, id)
	if err != nil || !ok {
		return TrafficDetail{}, ok, err
	}

	headers, err := s.ListTrafficHeaders(ctx, id)
	if err != nil {
		return TrafficDetail{}, false, err
	}
	detail := TrafficDetail{
		TrafficFlow: flow,
		Headers:     headers,
		QueryParams: map[string][]string{},
		Cookies:     map[string]string{},
	}
	if parsed, err := url.Parse(flow.URL); err == nil {
		detail.QueryParams = parsed.Query()
	}
	detail.RequestBody, detail.ResponseBody, _ = s.getTrafficBodies(ctx, id)
	for _, header := range headers {
		if header.Direction != "request" || !strings.EqualFold(header.Name, "Cookie") {
			continue
		}
		for _, part := range strings.Split(header.Value, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && name != "" {
				detail.Cookies[name] = value
			}
		}
	}
	return detail, true, nil
}

func (s *Store) getTrafficBodies(ctx context.Context, id string) (string, string, error) {
	var requestBody, responseBody []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(request_body, ''), COALESCE(response_body, '') FROM traffic_bodies WHERE flow_id = ?`, id).
		Scan(&requestBody, &responseBody)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("query traffic bodies: %w", err)
	}
	return string(requestBody), string(responseBody), nil
}

func (s *Store) ListTrafficHeaders(ctx context.Context, flowID string) ([]HeaderRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT direction, name, value FROM traffic_headers WHERE flow_id = ? ORDER BY id ASC`, flowID)
	if err != nil {
		return nil, fmt.Errorf("query traffic headers: %w", err)
	}
	defer rows.Close()

	headers := []HeaderRecord{}
	for rows.Next() {
		var header HeaderRecord
		if err := rows.Scan(&header.Direction, &header.Name, &header.Value); err != nil {
			return nil, fmt.Errorf("scan traffic header: %w", err)
		}
		headers = append(headers, header)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate traffic headers: %w", err)
	}
	return headers, nil
}

func (s *Store) ClearTraffic(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM traffic_headers`); err != nil {
		return fmt.Errorf("clear traffic headers: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM traffic_bodies`); err != nil {
		return fmt.Errorf("clear traffic bodies: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM traffic_flows`); err != nil {
		return fmt.Errorf("clear traffic flows: %w", err)
	}
	return nil
}

func (s *Store) PurgeResearchData(ctx context.Context, includeCache bool) error {
	if s == nil {
		return nil
	}
	tables := []string{
		"traffic_headers",
		"traffic_bodies",
		"traffic_flows",
		"certificates",
		"blocked_ports",
		"blocked_domains",
		"blocked_ips",
		"deployments",
		"audit_log",
		"threat_events",
		"threat_verdict_cache",
		"threat_rules",
		"repeater_runs",
		"repeater_cases",
		"research_scopes",
		"ai_notes",
		"pentest_observations",
		"pentest_parameters",
		"pentest_endpoints",
		"pentest_maps",
	}
	if includeCache {
		tables = append(tables, "cache_entries", "proxy_acl_rules", "proxy_users")
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	for _, table := range tables {
		if _, err := s.db.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return fmt.Errorf("purge %s: %w", table, err)
		}
	}
	return nil
}

func (s *Store) ListCertificates(ctx context.Context, limit int) ([]CertificateRecord, error) {
	page, err := s.ListCertificatesPage(ctx, limit, 0, "")
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (s *Store) ListCertificatesPage(ctx context.Context, limit, offset int, search string) (CertificatePage, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	where, args := certificateSearchWhere(search)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM certificates`+where, args...).Scan(&total); err != nil {
		return CertificatePage{}, fmt.Errorf("count certificates: %w", err)
	}

	queryArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, COALESCE(host, ''), COALESCE(subject, ''), COALESCE(fingerprint, ''),
		 COALESCE(created_at, ''), COALESCE(expires_at, '')
		 FROM certificates`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return CertificatePage{}, fmt.Errorf("query certificates: %w", err)
	}
	defer rows.Close()

	records := []CertificateRecord{}
	for rows.Next() {
		var record CertificateRecord
		var createdAt, expiresAt string
		if err := rows.Scan(&record.ID, &record.Host, &record.Subject, &record.Fingerprint, &createdAt, &expiresAt); err != nil {
			return CertificatePage{}, fmt.Errorf("scan certificate: %w", err)
		}
		record.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		record.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return CertificatePage{}, fmt.Errorf("iterate certificates: %w", err)
	}
	return CertificatePage{Items: records, Total: total, HasMore: offset+len(records) < total}, nil
}

func certificateSearchWhere(search string) (string, []any) {
	term := strings.ToLower(strings.TrimSpace(search))
	if term == "" {
		return "", nil
	}
	like := "%" + term + "%"
	return ` WHERE lower(COALESCE(host, '')) LIKE ?
		OR lower(COALESCE(subject, '')) LIKE ?
		OR lower(COALESCE(fingerprint, '')) LIKE ?
		OR lower(COALESCE(created_at, '')) LIKE ?
		OR lower(COALESCE(expires_at, '')) LIKE ?`, []any{like, like, like, like, like}
}

func (s *Store) TrafficStats(ctx context.Context) (TrafficStats, error) {
	var stats TrafficStats
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(blocked), 0), COALESCE(SUM(cache_hit), 0) FROM traffic_flows`).
		Scan(&stats.Total, &stats.Blocked, &stats.CacheHit)
	if err != nil {
		return TrafficStats{}, fmt.Errorf("query traffic stats: %w", err)
	}
	return stats, nil
}

func (s *Store) SetSetting(ctx context.Context, key string, value any) error {
	if s == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal setting: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, string(encoded))
	if err != nil {
		return fmt.Errorf("store setting: %w", err)
	}
	return nil
}

func (s *Store) CreateResearchScope(ctx context.Context, scope ResearchScope) (ResearchScope, error) {
	if s == nil {
		return scope, nil
	}
	if scope.ID == "" {
		scope.ID = newStoreID()
	}
	now := time.Now().UTC()
	if scope.CreatedAt.IsZero() {
		scope.CreatedAt = now
	}
	scope.UpdatedAt = now
	scope = normalizeScope(scope)
	hostJSON, urlJSON, methodJSON, err := marshalScopePatterns(scope)
	if err != nil {
		return ResearchScope{}, err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO research_scopes (id, name, description, created_at, updated_at, enabled, host_patterns_json, url_patterns_json, method_patterns_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scope.ID, scope.Name, scope.Description, scope.CreatedAt.Format(time.RFC3339Nano), scope.UpdatedAt.Format(time.RFC3339Nano),
		boolInt(scope.Enabled), hostJSON, urlJSON, methodJSON)
	if err != nil {
		return ResearchScope{}, fmt.Errorf("insert research scope: %w", err)
	}
	return scope, nil
}

func (s *Store) UpdateResearchScope(ctx context.Context, scope ResearchScope) (ResearchScope, error) {
	if s == nil {
		return scope, nil
	}
	scope.UpdatedAt = time.Now().UTC()
	scope = normalizeScope(scope)
	hostJSON, urlJSON, methodJSON, err := marshalScopePatterns(scope)
	if err != nil {
		return ResearchScope{}, err
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE research_scopes
		 SET name = ?, description = ?, updated_at = ?, enabled = ?, host_patterns_json = ?, url_patterns_json = ?, method_patterns_json = ?
		 WHERE id = ?`,
		scope.Name, scope.Description, scope.UpdatedAt.Format(time.RFC3339Nano), boolInt(scope.Enabled), hostJSON, urlJSON, methodJSON, scope.ID)
	if err != nil {
		return ResearchScope{}, fmt.Errorf("update research scope: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return ResearchScope{}, sql.ErrNoRows
	}
	stored, ok, err := s.GetResearchScope(ctx, scope.ID)
	if err != nil || !ok {
		return ResearchScope{}, err
	}
	return stored, nil
}

func (s *Store) ListResearchScopes(ctx context.Context) ([]ResearchScope, error) {
	if s == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, COALESCE(description, ''), created_at, updated_at, enabled,
		 host_patterns_json, url_patterns_json, method_patterns_json
		 FROM research_scopes ORDER BY updated_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("query research scopes: %w", err)
	}
	defer rows.Close()

	scopes := []ResearchScope{}
	for rows.Next() {
		scope, err := scanResearchScope(rows)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate research scopes: %w", err)
	}
	return scopes, nil
}

func (s *Store) GetResearchScope(ctx context.Context, id string) (ResearchScope, bool, error) {
	if s == nil {
		return ResearchScope{}, false, nil
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, COALESCE(description, ''), created_at, updated_at, enabled,
		 host_patterns_json, url_patterns_json, method_patterns_json
		 FROM research_scopes WHERE id = ?`, id)
	scope, err := scanResearchScope(row)
	if err == sql.ErrNoRows {
		return ResearchScope{}, false, nil
	}
	if err != nil {
		return ResearchScope{}, false, err
	}
	return scope, true, nil
}

func (s *Store) DeleteResearchScope(ctx context.Context, id string) error {
	if s == nil {
		return nil
	}
	for _, statement := range []string{
		`UPDATE traffic_flows SET scope_id = NULL WHERE scope_id = ?`,
		`UPDATE repeater_cases SET scope_id = NULL WHERE scope_id = ?`,
		`UPDATE threat_events SET scope_id = NULL WHERE scope_id = ?`,
		`UPDATE ai_notes SET scope_id = NULL WHERE scope_id = ?`,
		`UPDATE pentest_maps SET scope_id = NULL WHERE scope_id = ?`,
		`DELETE FROM research_scopes WHERE id = ?`,
	} {
		if _, err := s.db.ExecContext(ctx, statement, id); err != nil {
			return fmt.Errorf("delete research scope: %w", err)
		}
	}
	return nil
}

func (s *Store) AssignTrafficScope(ctx context.Context, flowID, scopeID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE traffic_flows SET scope_id = NULLIF(?, '') WHERE id = ?`, strings.TrimSpace(scopeID), flowID)
	if err != nil {
		return fmt.Errorf("assign traffic scope: %w", err)
	}
	return nil
}

func (s *Store) AssignRepeaterScope(ctx context.Context, caseID, scopeID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE repeater_cases SET scope_id = NULLIF(?, ''), updated_at = ? WHERE id = ?`,
		strings.TrimSpace(scopeID), time.Now().UTC().Format(time.RFC3339Nano), caseID)
	if err != nil {
		return fmt.Errorf("assign repeater scope: %w", err)
	}
	return nil
}

func (s *Store) MatchResearchScope(ctx context.Context, method, rawURL, host string) (string, error) {
	scopes, err := s.ListResearchScopes(ctx)
	if err != nil {
		return "", err
	}
	for _, scope := range scopes {
		if scope.Enabled && scopeMatches(scope, method, rawURL, host) {
			return scope.ID, nil
		}
	}
	return "", nil
}

func scopeMatches(scope ResearchScope, method, rawURL, host string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		if parsed, err := url.Parse(rawURL); err == nil {
			host = strings.ToLower(parsed.Hostname())
		}
	}
	if len(scope.MethodPatterns) > 0 && !containsFold(scope.MethodPatterns, method) {
		return false
	}
	hostMatch := len(scope.HostPatterns) == 0
	for _, pattern := range scope.HostPatterns {
		if matchHostPattern(pattern, host) {
			hostMatch = true
			break
		}
	}
	urlMatch := len(scope.URLPatterns) == 0
	for _, pattern := range scope.URLPatterns {
		if strings.Contains(strings.ToLower(rawURL), strings.ToLower(strings.TrimSpace(pattern))) {
			urlMatch = true
			break
		}
	}
	return hostMatch && urlMatch
}

func matchHostPattern(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == "" || host == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		return strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

func normalizeScope(scope ResearchScope) ResearchScope {
	scope.Name = strings.TrimSpace(scope.Name)
	scope.Description = strings.TrimSpace(scope.Description)
	scope.HostPatterns = cleanPatterns(scope.HostPatterns, false)
	scope.URLPatterns = cleanPatterns(scope.URLPatterns, false)
	scope.MethodPatterns = cleanPatterns(scope.MethodPatterns, true)
	return scope
}

func cleanPatterns(values []string, upper bool) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if upper {
			value = strings.ToUpper(value)
		}
		key := strings.ToLower(value)
		if !seen[key] {
			seen[key] = true
			out = append(out, value)
		}
	}
	return out
}

func marshalScopePatterns(scope ResearchScope) (string, string, string, error) {
	hostJSON, err := json.Marshal(scope.HostPatterns)
	if err != nil {
		return "", "", "", fmt.Errorf("marshal scope host patterns: %w", err)
	}
	urlJSON, err := json.Marshal(scope.URLPatterns)
	if err != nil {
		return "", "", "", fmt.Errorf("marshal scope url patterns: %w", err)
	}
	methodJSON, err := json.Marshal(scope.MethodPatterns)
	if err != nil {
		return "", "", "", fmt.Errorf("marshal scope method patterns: %w", err)
	}
	return string(hostJSON), string(urlJSON), string(methodJSON), nil
}

func (s *Store) CreateRepeaterCase(ctx context.Context, c RepeaterCase) (RepeaterCase, error) {
	if s == nil {
		return c, nil
	}
	if c.ID == "" {
		c.ID = newStoreID()
	}
	now := time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	if c.Headers == nil {
		c.Headers = map[string][]string{}
	}
	headers, err := json.Marshal(c.Headers)
	if err != nil {
		return RepeaterCase{}, fmt.Errorf("marshal repeater headers: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO repeater_cases (id, created_at, updated_at, source_flow_id, name, method, url, headers_json, body, timeout_ms, scope_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''))`,
		c.ID, c.CreatedAt.Format(time.RFC3339Nano), c.UpdatedAt.Format(time.RFC3339Nano), c.SourceFlowID,
		c.Name, c.Method, c.URL, string(headers), []byte(c.Body), c.TimeoutMS, strings.TrimSpace(c.ScopeID))
	if err != nil {
		return RepeaterCase{}, fmt.Errorf("insert repeater case: %w", err)
	}
	return c, nil
}

func (s *Store) UpdateRepeaterCase(ctx context.Context, c RepeaterCase) (RepeaterCase, error) {
	if s == nil {
		return c, nil
	}
	c.UpdatedAt = time.Now().UTC()
	if c.Headers == nil {
		c.Headers = map[string][]string{}
	}
	headers, err := json.Marshal(c.Headers)
	if err != nil {
		return RepeaterCase{}, fmt.Errorf("marshal repeater headers: %w", err)
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE repeater_cases
		 SET updated_at = ?, name = ?, method = ?, url = ?, headers_json = ?, body = ?, timeout_ms = ?, scope_id = NULLIF(?, '')
		 WHERE id = ?`,
		c.UpdatedAt.Format(time.RFC3339Nano), c.Name, c.Method, c.URL, string(headers), []byte(c.Body), c.TimeoutMS, strings.TrimSpace(c.ScopeID), c.ID)
	if err != nil {
		return RepeaterCase{}, fmt.Errorf("update repeater case: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return RepeaterCase{}, sql.ErrNoRows
	}
	stored, ok, err := s.GetRepeaterCase(ctx, c.ID)
	if err != nil || !ok {
		return RepeaterCase{}, err
	}
	return stored, nil
}

func (s *Store) ListRepeaterCases(ctx context.Context, limit int) ([]RepeaterCase, error) {
	return s.ListRepeaterCasesScoped(ctx, limit, "", true)
}

func (s *Store) ListRepeaterCasesScoped(ctx context.Context, limit int, scopeID string, includeOutOfScope bool) ([]RepeaterCase, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	where, args := scopedWhere(scopeID, includeOutOfScope)
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, created_at, updated_at, COALESCE(source_flow_id, ''), name, method, url, headers_json, COALESCE(body, ''), timeout_ms, COALESCE(scope_id, '')
		 FROM repeater_cases`+where+` ORDER BY updated_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("query repeater cases: %w", err)
	}
	defer rows.Close()

	cases := []RepeaterCase{}
	for rows.Next() {
		c, err := scanRepeaterCase(rows)
		if err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate repeater cases: %w", err)
	}
	return cases, nil
}

func (s *Store) GetRepeaterCase(ctx context.Context, id string) (RepeaterCase, bool, error) {
	if s == nil {
		return RepeaterCase{}, false, nil
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT id, created_at, updated_at, COALESCE(source_flow_id, ''), name, method, url, headers_json, COALESCE(body, ''), timeout_ms, COALESCE(scope_id, '')
		 FROM repeater_cases WHERE id = ?`, id)
	c, err := scanRepeaterCase(row)
	if err == sql.ErrNoRows {
		return RepeaterCase{}, false, nil
	}
	if err != nil {
		return RepeaterCase{}, false, err
	}
	return c, true, nil
}

func (s *Store) DeleteRepeaterCase(ctx context.Context, id string) error {
	if s == nil {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM repeater_runs WHERE case_id = ?`, id); err != nil {
		return fmt.Errorf("delete repeater runs: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM repeater_cases WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete repeater case: %w", err)
	}
	return nil
}

func (s *Store) AddRepeaterRun(ctx context.Context, run RepeaterRun) (RepeaterRun, error) {
	if s == nil {
		return run, nil
	}
	if run.ID == "" {
		run.ID = newStoreID()
	}
	if run.CreatedAt.IsZero() {
		run.CreatedAt = time.Now().UTC()
	}
	if run.ResponseHeaders == nil {
		run.ResponseHeaders = map[string][]string{}
	}
	headers, err := json.Marshal(run.ResponseHeaders)
	if err != nil {
		return RepeaterRun{}, fmt.Errorf("marshal repeater response headers: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO repeater_runs (id, case_id, created_at, status, duration_ms, bytes, response_headers_json, response_body, error)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID, run.CaseID, run.CreatedAt.Format(time.RFC3339Nano), run.Status, run.DurationMS, run.Bytes,
		string(headers), []byte(run.ResponseBody), run.Error)
	if err != nil {
		return RepeaterRun{}, fmt.Errorf("insert repeater run: %w", err)
	}
	return run, nil
}

func (s *Store) ListRepeaterRuns(ctx context.Context, caseID string, limit int) ([]RepeaterRun, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, case_id, created_at, COALESCE(status, 0), COALESCE(duration_ms, 0), COALESCE(bytes, 0),
		 response_headers_json, COALESCE(response_body, ''), COALESCE(error, '')
		 FROM repeater_runs WHERE case_id = ? ORDER BY created_at DESC LIMIT ?`, caseID, limit)
	if err != nil {
		return nil, fmt.Errorf("query repeater runs: %w", err)
	}
	defer rows.Close()

	runs := []RepeaterRun{}
	for rows.Next() {
		run, err := scanRepeaterRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate repeater runs: %w", err)
	}
	return runs, nil
}

type trafficScanner interface {
	Scan(dest ...any) error
}

func scanRepeaterCase(row trafficScanner) (RepeaterCase, error) {
	var c RepeaterCase
	var createdAt, updatedAt, headersJSON string
	var body []byte
	if err := row.Scan(&c.ID, &createdAt, &updatedAt, &c.SourceFlowID, &c.Name, &c.Method, &c.URL, &headersJSON, &body, &c.TimeoutMS, &c.ScopeID); err != nil {
		return RepeaterCase{}, err
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	c.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	c.Body = string(body)
	if headersJSON != "" {
		_ = json.Unmarshal([]byte(headersJSON), &c.Headers)
	}
	if c.Headers == nil {
		c.Headers = map[string][]string{}
	}
	return c, nil
}

func scanResearchScope(row trafficScanner) (ResearchScope, error) {
	var scope ResearchScope
	var createdAt, updatedAt string
	var enabled int
	var hostJSON, urlJSON, methodJSON string
	if err := row.Scan(&scope.ID, &scope.Name, &scope.Description, &createdAt, &updatedAt, &enabled, &hostJSON, &urlJSON, &methodJSON); err != nil {
		return ResearchScope{}, err
	}
	scope.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	scope.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	scope.Enabled = enabled != 0
	_ = json.Unmarshal([]byte(hostJSON), &scope.HostPatterns)
	_ = json.Unmarshal([]byte(urlJSON), &scope.URLPatterns)
	_ = json.Unmarshal([]byte(methodJSON), &scope.MethodPatterns)
	return normalizeScope(scope), nil
}

func scanRepeaterRun(row trafficScanner) (RepeaterRun, error) {
	var run RepeaterRun
	var createdAt, headersJSON string
	var body []byte
	if err := row.Scan(&run.ID, &run.CaseID, &createdAt, &run.Status, &run.DurationMS, &run.Bytes, &headersJSON, &body, &run.Error); err != nil {
		return RepeaterRun{}, err
	}
	run.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	run.ResponseBody = string(body)
	if headersJSON != "" {
		_ = json.Unmarshal([]byte(headersJSON), &run.ResponseHeaders)
	}
	if run.ResponseHeaders == nil {
		run.ResponseHeaders = map[string][]string{}
	}
	return run, nil
}

func scanAINote(row trafficScanner) (AINote, error) {
	var note AINote
	var createdAt, updatedAt, content string
	if err := row.Scan(&note.ID, &createdAt, &updatedAt, &note.Kind, &note.TargetType, &note.TargetID,
		&note.ScopeID, &note.Model, &note.PromptHash, &note.Title, &note.Summary, &content); err != nil {
		return AINote{}, err
	}
	note.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	note.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	if strings.TrimSpace(content) == "" {
		content = "{}"
	}
	note.Content = json.RawMessage(content)
	return normalizeAINote(note), nil
}

func scanPentestMap(row trafficScanner) (PentestMap, error) {
	var m PentestMap
	var createdAt, updatedAt string
	var includeOutOfScope int
	if err := row.Scan(&m.ID, &m.ScopeID, &createdAt, &updatedAt, &m.Name, &m.SourceFlowCount, &m.EndpointCount, &m.ParameterCount, &includeOutOfScope); err != nil {
		return PentestMap{}, err
	}
	m.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	m.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	m.IncludeOutOfScope = includeOutOfScope != 0
	return m, nil
}

func scanPentestEndpoint(row trafficScanner) (PentestEndpoint, error) {
	var endpoint PentestEndpoint
	var statusJSON, contentTypesJSON, proxyUsersJSON string
	var hasAuth, hasCookies, hasRequestBody, hasResponseBody, cacheHit int
	if err := row.Scan(&endpoint.ID, &endpoint.MapID, &endpoint.Method, &endpoint.Scheme, &endpoint.Host, &endpoint.Path, &endpoint.NormalizedPath,
		&statusJSON, &contentTypesJSON, &hasAuth, &hasCookies, &hasRequestBody, &hasResponseBody, &cacheHit, &proxyUsersJSON, &endpoint.ParameterCount, &endpoint.RepresentativeFlowID); err != nil {
		return PentestEndpoint{}, err
	}
	_ = json.Unmarshal([]byte(statusJSON), &endpoint.StatusSummary)
	_ = json.Unmarshal([]byte(contentTypesJSON), &endpoint.ContentTypes)
	_ = json.Unmarshal([]byte(proxyUsersJSON), &endpoint.ProxyUsers)
	if endpoint.StatusSummary == nil {
		endpoint.StatusSummary = map[string]int{}
	}
	endpoint.HasAuth = hasAuth != 0
	endpoint.HasCookies = hasCookies != 0
	endpoint.HasRequestBody = hasRequestBody != 0
	endpoint.HasResponseBody = hasResponseBody != 0
	endpoint.CacheHit = cacheHit != 0
	return endpoint, nil
}

func scanPentestParameter(row trafficScanner) (PentestParameter, error) {
	var parameter PentestParameter
	var observedTypesJSON, examplesJSON string
	var reflected, interesting int
	if err := row.Scan(&parameter.ID, &parameter.MapID, &parameter.EndpointID, &parameter.Name, &parameter.Location, &observedTypesJSON, &examplesJSON,
		&parameter.EndpointCount, &reflected, &interesting, &parameter.RepresentativeFlowID); err != nil {
		return PentestParameter{}, err
	}
	_ = json.Unmarshal([]byte(observedTypesJSON), &parameter.ObservedTypes)
	_ = json.Unmarshal([]byte(examplesJSON), &parameter.Examples)
	parameter.Reflected = reflected != 0
	parameter.Interesting = interesting != 0
	return parameter, nil
}

func scanPentestObservation(row trafficScanner) (PentestObservation, error) {
	var observation PentestObservation
	var evidence string
	if err := row.Scan(&observation.ID, &observation.MapID, &observation.EndpointID, &observation.Kind, &observation.Severity, &observation.Title, &observation.Summary, &evidence, &observation.RepresentativeFlowID); err != nil {
		return PentestObservation{}, err
	}
	if strings.TrimSpace(evidence) == "" {
		evidence = "{}"
	}
	observation.Evidence = json.RawMessage(evidence)
	return observation, nil
}

func scanProxyUser(row trafficScanner) (ProxyUser, error) {
	var user ProxyUser
	var enabled int
	var createdAt, updatedAt, lastUsedAt string
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &enabled, &createdAt, &updatedAt, &lastUsedAt); err != nil {
		return ProxyUser{}, err
	}
	user.Enabled = enabled != 0
	user.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	user.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	if parsed, err := time.Parse(time.RFC3339Nano, lastUsedAt); err == nil {
		user.LastUsedAt = &parsed
	}
	return user, nil
}

func proxyACLRuleSelect() string {
	return `SELECT id, priority, enabled, action, name, COALESCE(description, ''), users_json, source_ips_json, host_patterns_json, port_patterns_json, method_patterns_json, scope_ids_json, created_at, updated_at FROM proxy_acl_rules`
}

func scanProxyACLRule(row trafficScanner) (ProxyACLRule, error) {
	var rule ProxyACLRule
	var enabled int
	var usersJSON, sourceIPsJSON, hostJSON, portJSON, methodJSON, scopeJSON string
	var createdAt, updatedAt string
	if err := row.Scan(&rule.ID, &rule.Priority, &enabled, &rule.Action, &rule.Name, &rule.Description, &usersJSON, &sourceIPsJSON, &hostJSON, &portJSON, &methodJSON, &scopeJSON, &createdAt, &updatedAt); err != nil {
		return ProxyACLRule{}, err
	}
	rule.Enabled = enabled != 0
	rule.Users = unmarshalStringList(usersJSON)
	rule.SourceIPs = unmarshalStringList(sourceIPsJSON)
	rule.HostPatterns = unmarshalStringList(hostJSON)
	rule.PortPatterns = unmarshalStringList(portJSON)
	rule.MethodPatterns = unmarshalStringList(methodJSON)
	rule.ScopeIDs = unmarshalStringList(scopeJSON)
	rule.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	rule.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return normalizeProxyACLRule(rule), nil
}

func normalizeProxyACLRule(rule ProxyACLRule) ProxyACLRule {
	rule.ID = strings.TrimSpace(rule.ID)
	rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
	if rule.Action == "" {
		rule.Action = "deny"
	}
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		rule.Name = rule.Action + " rule"
	}
	rule.Description = strings.TrimSpace(rule.Description)
	rule.Users = normalizeStringList(rule.Users, false)
	rule.SourceIPs = normalizeStringList(rule.SourceIPs, false)
	rule.HostPatterns = normalizeStringList(rule.HostPatterns, true)
	rule.PortPatterns = normalizeStringList(rule.PortPatterns, false)
	rule.MethodPatterns = normalizeStringList(rule.MethodPatterns, true)
	rule.ScopeIDs = normalizeStringList(rule.ScopeIDs, false)
	return rule
}

func normalizeStringList(values []string, upper bool) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if upper {
			value = strings.ToUpper(value)
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func proxyACLRuleSQLArgs(rule ProxyACLRule) ([]any, error) {
	if rule.Action != "allow" && rule.Action != "deny" {
		return nil, fmt.Errorf("proxy ACL action must be allow or deny")
	}
	lists := [][]string{rule.Users, rule.SourceIPs, rule.HostPatterns, rule.PortPatterns, rule.MethodPatterns, rule.ScopeIDs}
	encoded := make([]string, 0, len(lists))
	for _, list := range lists {
		raw, err := json.Marshal(list)
		if err != nil {
			return nil, fmt.Errorf("marshal proxy ACL rule: %w", err)
		}
		encoded = append(encoded, string(raw))
	}
	enabled := 0
	if rule.Enabled {
		enabled = 1
	}
	return []any{
		rule.ID, rule.Priority, enabled, rule.Action, rule.Name, rule.Description,
		encoded[0], encoded[1], encoded[2], encoded[3], encoded[4], encoded[5],
		rule.CreatedAt.Format(time.RFC3339Nano), rule.UpdatedAt.Format(time.RFC3339Nano),
	}, nil
}

func unmarshalStringList(raw string) []string {
	out := []string{}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func scanTrafficFlow(row trafficScanner) (TrafficFlow, error) {
	var flow TrafficFlow
	var createdAt string
	var cacheHit, blocked int
	if err := row.Scan(&flow.ID, &createdAt, &flow.Method, &flow.URL, &flow.Host, &flow.Status, &flow.Protocol, &flow.MIMEType, &flow.RemoteIP, &flow.DurationMS, &flow.Bytes, &cacheHit, &blocked, &flow.RuleID, &flow.ScopeID, &flow.ProxyUser); err != nil {
		return TrafficFlow{}, err
	}
	flow.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	flow.CacheHit = cacheHit != 0
	flow.Blocked = blocked != 0
	return flow, nil
}

func (s *Store) recordTrafficStarted(ctx context.Context, event events.Event) error {
	method := stringPayload(event, "method")
	rawURL := stringPayload(event, "url")
	host := stringPayload(event, "host")
	scopeID, err := s.MatchResearchScope(ctx, method, rawURL, host)
	if err != nil {
		return fmt.Errorf("match traffic scope: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO traffic_flows (id, created_at, method, url, host, protocol, remote_ip, scope_id, proxy_user)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''))
		 ON CONFLICT(id) DO UPDATE SET method=excluded.method, url=excluded.url, host=excluded.host, protocol=excluded.protocol, remote_ip=excluded.remote_ip, scope_id=excluded.scope_id, proxy_user=COALESCE(excluded.proxy_user, traffic_flows.proxy_user)`,
		flowID(event), event.Time.Format(time.RFC3339Nano), method, rawURL, host, stringPayload(event, "protocol"), stringPayload(event, "remote_ip"), scopeID, stringPayload(event, "proxy_user"))
	if err != nil {
		return fmt.Errorf("record traffic start: %w", err)
	}
	if err := s.recordHeaders(ctx, flowID(event), "request", event.Payload["request_headers"]); err != nil {
		return err
	}
	return nil
}

func (s *Store) recordTrafficCompleted(ctx context.Context, event events.Event) error {
	method := stringPayload(event, "method")
	rawURL := stringPayload(event, "url")
	host := stringPayload(event, "host")
	scopeID, err := s.MatchResearchScope(ctx, method, rawURL, host)
	if err != nil {
		return fmt.Errorf("match traffic scope: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO traffic_flows (id, created_at, method, url, host, status, mime_type, duration_ms, bytes, cache_hit, scope_id, proxy_user)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''))
		 ON CONFLICT(id) DO UPDATE SET status=excluded.status, mime_type=excluded.mime_type, duration_ms=excluded.duration_ms, bytes=excluded.bytes, cache_hit=excluded.cache_hit, scope_id=COALESCE(excluded.scope_id, traffic_flows.scope_id), proxy_user=COALESCE(excluded.proxy_user, traffic_flows.proxy_user)`,
		flowID(event), event.Time.Format(time.RFC3339Nano), method, rawURL, host, intPayload(event, "status"), stringPayload(event, "mime_type"), intPayload(event, "duration_ms"), intPayload(event, "bytes"), boolPayload(event, "cache_hit"), scopeID, stringPayload(event, "proxy_user"))
	if err != nil {
		return fmt.Errorf("record traffic completion: %w", err)
	}
	if err := s.recordHeaders(ctx, flowID(event), "response", event.Payload["response_headers"]); err != nil {
		return err
	}
	return nil
}

func (s *Store) recordTunnelOpened(ctx context.Context, event events.Event) error {
	target := stringPayload(event, "target")
	host := target
	if parsed, err := url.Parse("//" + target); err == nil {
		host = parsed.Hostname()
	}
	scopeID, err := s.MatchResearchScope(ctx, "CONNECT", target, host)
	if err != nil {
		return fmt.Errorf("match tunnel scope: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO traffic_flows (id, created_at, method, url, host, protocol, remote_ip, scope_id, proxy_user)
		 VALUES (?, ?, 'CONNECT', ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''))`,
		flowID(event), event.Time.Format(time.RFC3339Nano), target, host, stringPayload(event, "protocol"), stringPayload(event, "remote_ip"), scopeID, stringPayload(event, "proxy_user"))
	if err != nil {
		return fmt.Errorf("record tunnel: %w", err)
	}
	return nil
}

func (s *Store) recordHeaders(ctx context.Context, flowID, direction string, value any) error {
	headers, ok := value.(map[string]any)
	if !ok {
		return nil
	}

	for name, rawValues := range headers {
		switch values := rawValues.(type) {
		case []string:
			for _, headerValue := range values {
				if err := s.insertHeader(ctx, flowID, direction, name, headerValue); err != nil {
					return err
				}
			}
		case []any:
			for _, headerValue := range values {
				if err := s.insertHeader(ctx, flowID, direction, name, fmt.Sprint(headerValue)); err != nil {
					return err
				}
			}
		case string:
			if err := s.insertHeader(ctx, flowID, direction, name, values); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) insertHeader(ctx context.Context, flowID, direction, name, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO traffic_headers (flow_id, direction, name, value) VALUES (?, ?, ?, ?)`,
		flowID, direction, name, value)
	if err != nil {
		return fmt.Errorf("record traffic header: %w", err)
	}
	return nil
}

func (s *Store) recordTrafficBlocked(ctx context.Context, event events.Event) error {
	method := stringPayload(event, "method")
	rawURL := firstStringPayload(event, "url", "target")
	host := stringPayload(event, "host")
	scopeID, err := s.MatchResearchScope(ctx, method, rawURL, host)
	if err != nil {
		return fmt.Errorf("match blocked traffic scope: %w", err)
	}
	status := intPayload(event, "status")
	if status == 0 {
		status = 403
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO traffic_flows (id, created_at, method, url, host, blocked, rule_id, status, scope_id, proxy_user, remote_ip)
		 VALUES (?, ?, ?, ?, ?, 1, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''))
		 ON CONFLICT(id) DO UPDATE SET blocked=1, rule_id=excluded.rule_id, status=excluded.status, scope_id=excluded.scope_id, proxy_user=COALESCE(excluded.proxy_user, traffic_flows.proxy_user), remote_ip=COALESCE(excluded.remote_ip, traffic_flows.remote_ip)`,
		flowID(event), event.Time.Format(time.RFC3339Nano), method, rawURL, host, stringPayload(event, "rule_id"), status, scopeID, stringPayload(event, "proxy_user"), stringPayload(event, "remote_ip"))
	if err != nil {
		return fmt.Errorf("record blocked traffic: %w", err)
	}
	return nil
}

func (s *Store) recordTrafficBody(ctx context.Context, event events.Event) error {
	flowID := flowID(event)
	direction := stringPayload(event, "direction")
	body := []byte(stringPayload(event, "body"))

	column := "request_body"
	if direction == "response" {
		column = "response_body"
	}

	_, err := s.db.ExecContext(ctx,
		fmt.Sprintf(`INSERT INTO traffic_bodies (flow_id, %s) VALUES (?, ?)
		 ON CONFLICT(flow_id) DO UPDATE SET %s=excluded.%s`, column, column, column),
		flowID, body)
	if err != nil {
		return fmt.Errorf("record traffic body: %w", err)
	}
	return nil
}

func (s *Store) recordCertificate(ctx context.Context, event events.Event) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO certificates (host, subject, fingerprint, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(host) DO UPDATE SET
			subject=excluded.subject,
			fingerprint=excluded.fingerprint,
			created_at=excluded.created_at,
			expires_at=excluded.expires_at`,
		stringPayload(event, "host"), stringPayload(event, "subject"), stringPayload(event, "fingerprint"), stringPayload(event, "created_at"), stringPayload(event, "expires_at"))
	if err != nil {
		return fmt.Errorf("record certificate: %w", err)
	}
	return nil
}

func flowID(event events.Event) string {
	if event.RequestID != "" {
		return event.RequestID
	}
	return event.ID
}

func stringPayload(event events.Event, key string) string {
	value, ok := event.Payload[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func firstStringPayload(event events.Event, keys ...string) string {
	for _, key := range keys {
		if value := stringPayload(event, key); value != "" {
			return value
		}
	}
	return ""
}

func intPayload(event events.Event, key string) int64 {
	value, ok := event.Payload[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

func boolPayload(event events.Event, key string) int {
	value, ok := event.Payload[key]
	if !ok || value == nil {
		return 0
	}
	if typed, ok := value.(bool); ok && typed {
		return 1
	}
	return 0
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func newStoreID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
