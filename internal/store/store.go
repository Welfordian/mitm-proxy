package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
	_ = s.addColumnIfMissing(ctx, "repeater_cases", "scope_id", "TEXT")
	_ = s.addColumnIfMissing(ctx, "threat_events", "scope_id", "TEXT")
	_ = s.addColumnIfMissing(ctx, "admin_users", "role", "TEXT NOT NULL DEFAULT 'read'")

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
		searchWhere := `(LOWER(COALESCE(method, '')) LIKE ? OR LOWER(COALESCE(url, '')) LIKE ? OR LOWER(COALESCE(host, '')) LIKE ? OR CAST(COALESCE(status, 0) AS TEXT) LIKE ? OR LOWER(COALESCE(protocol, '')) LIKE ? OR LOWER(COALESCE(mime_type, '')) LIKE ? OR LOWER(COALESCE(rule_id, '')) LIKE ?)`
		if where == "" {
			where = " WHERE " + searchWhere
		} else {
			where += " AND " + searchWhere
		}
		term := "%" + strings.ToLower(search) + "%"
		args = append(args, term, term, term, term, term, term, term)
	}
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, created_at, COALESCE(method, ''), COALESCE(url, ''), COALESCE(host, ''),
		 COALESCE(status, 0), COALESCE(protocol, ''), COALESCE(mime_type, ''), COALESCE(remote_ip, ''),
		 COALESCE(duration_ms, 0), COALESCE(bytes, 0), cache_hit, blocked, COALESCE(rule_id, ''), COALESCE(scope_id, '')
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

func (s *Store) GetTraffic(ctx context.Context, id string) (TrafficFlow, bool, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, created_at, COALESCE(method, ''), COALESCE(url, ''), COALESCE(host, ''),
		 COALESCE(status, 0), COALESCE(protocol, ''), COALESCE(mime_type, ''), COALESCE(remote_ip, ''),
		 COALESCE(duration_ms, 0), COALESCE(bytes, 0), cache_hit, blocked, COALESCE(rule_id, ''), COALESCE(scope_id, '')
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

func (s *Store) ListCertificates(ctx context.Context, limit int) ([]CertificateRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, COALESCE(host, ''), COALESCE(subject, ''), COALESCE(fingerprint, ''),
		 COALESCE(created_at, ''), COALESCE(expires_at, '')
		 FROM certificates ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query certificates: %w", err)
	}
	defer rows.Close()

	records := []CertificateRecord{}
	for rows.Next() {
		var record CertificateRecord
		var createdAt, expiresAt string
		if err := rows.Scan(&record.ID, &record.Host, &record.Subject, &record.Fingerprint, &createdAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		record.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		record.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate certificates: %w", err)
	}
	return records, nil
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

func scanTrafficFlow(row trafficScanner) (TrafficFlow, error) {
	var flow TrafficFlow
	var createdAt string
	var cacheHit, blocked int
	if err := row.Scan(&flow.ID, &createdAt, &flow.Method, &flow.URL, &flow.Host, &flow.Status, &flow.Protocol, &flow.MIMEType, &flow.RemoteIP, &flow.DurationMS, &flow.Bytes, &cacheHit, &blocked, &flow.RuleID, &flow.ScopeID); err != nil {
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
		`INSERT INTO traffic_flows (id, created_at, method, url, host, protocol, remote_ip, scope_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''))
		 ON CONFLICT(id) DO UPDATE SET method=excluded.method, url=excluded.url, host=excluded.host, protocol=excluded.protocol, remote_ip=excluded.remote_ip, scope_id=excluded.scope_id`,
		flowID(event), event.Time.Format(time.RFC3339Nano), method, rawURL, host, stringPayload(event, "protocol"), stringPayload(event, "remote_ip"), scopeID)
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
		`INSERT INTO traffic_flows (id, created_at, method, url, host, status, mime_type, duration_ms, bytes, cache_hit, scope_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''))
		 ON CONFLICT(id) DO UPDATE SET status=excluded.status, mime_type=excluded.mime_type, duration_ms=excluded.duration_ms, bytes=excluded.bytes, cache_hit=excluded.cache_hit, scope_id=COALESCE(excluded.scope_id, traffic_flows.scope_id)`,
		flowID(event), event.Time.Format(time.RFC3339Nano), method, rawURL, host, intPayload(event, "status"), stringPayload(event, "mime_type"), intPayload(event, "duration_ms"), intPayload(event, "bytes"), boolPayload(event, "cache_hit"), scopeID)
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
		`INSERT INTO traffic_flows (id, created_at, method, url, host, protocol, remote_ip, scope_id)
		 VALUES (?, ?, 'CONNECT', ?, ?, ?, ?, NULLIF(?, ''))`,
		flowID(event), event.Time.Format(time.RFC3339Nano), target, host, stringPayload(event, "protocol"), stringPayload(event, "remote_ip"), scopeID)
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
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO traffic_flows (id, created_at, method, url, host, blocked, rule_id, status, scope_id)
		 VALUES (?, ?, ?, ?, ?, 1, ?, 403, NULLIF(?, ''))
		 ON CONFLICT(id) DO UPDATE SET blocked=1, rule_id=excluded.rule_id, status=excluded.status, scope_id=excluded.scope_id`,
		flowID(event), event.Time.Format(time.RFC3339Nano), method, rawURL, host, stringPayload(event, "rule_id"), scopeID)
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
		 VALUES (?, ?, ?, ?, ?)`,
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

func newStoreID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
