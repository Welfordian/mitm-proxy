package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/events"
)

type RequestMatch struct {
	Method  string `json:"method"`
	URL     string `json:"url"`
	Host    string `json:"host"`
	ScopeID string `json:"scope_id,omitempty"`
}

type FaultInjectionRule struct {
	ID                     string              `json:"id"`
	CreatedAt              time.Time           `json:"created_at"`
	UpdatedAt              time.Time           `json:"updated_at"`
	Name                   string              `json:"name"`
	Enabled                bool                `json:"enabled"`
	Priority               int                 `json:"priority"`
	Phase                  string              `json:"phase"`
	Action                 string              `json:"action"`
	HostPatterns           []string            `json:"host_patterns"`
	URLPatterns            []string            `json:"url_patterns"`
	MethodPatterns         []string            `json:"method_patterns"`
	ScopeIDs               []string            `json:"scope_ids"`
	DelayMS                int                 `json:"delay_ms"`
	ThrottleBytesPerSecond int                 `json:"throttle_bytes_per_second"`
	CorruptProbability     float64             `json:"corrupt_probability"`
	CorruptMode            string              `json:"corrupt_mode"`
	SyntheticStatus        int                 `json:"synthetic_status"`
	SyntheticHeaders       map[string][]string `json:"synthetic_headers"`
	SyntheticBody          string              `json:"synthetic_body"`
}

type HostProfile struct {
	ID             string               `json:"id"`
	CreatedAt      time.Time            `json:"created_at"`
	UpdatedAt      time.Time            `json:"updated_at"`
	Name           string               `json:"name"`
	Enabled        bool                 `json:"enabled"`
	Priority       int                  `json:"priority"`
	HostPatterns   []string             `json:"host_patterns"`
	URLPatterns    []string             `json:"url_patterns"`
	MethodPatterns []string             `json:"method_patterns"`
	Overrides      HostProfileOverrides `json:"overrides"`
}

type HostProfileOverrides struct {
	EnableMITM      *bool                       `json:"enable_mitm,omitempty"`
	EnableFaults    *bool                       `json:"enable_faults,omitempty"`
	ExcludedDomains []string                    `json:"excluded_domains,omitempty"`
	Cache           *cfgpkg.CacheConfig         `json:"cache,omitempty"`
	TrafficCapture  *cfgpkg.TrafficCaptureConfig `json:"traffic_capture,omitempty"`
	ThreatScanner   *cfgpkg.ThreatScannerConfig `json:"threat_scanner,omitempty"`
	UpstreamProxy   *cfgpkg.UpstreamProxyConfig `json:"upstream_proxy,omitempty"`
	BlockedPorts    []int                       `json:"blocked_ports,omitempty"`
	BlockedDomains  []string                    `json:"blocked_domains,omitempty"`
	BlockedIPs      []string                    `json:"blocked_ips,omitempty"`
	VerboseLogging  *bool                       `json:"verbose_logging,omitempty"`
	LogRequests     *bool                       `json:"log_requests,omitempty"`
}

func (s *Store) CreateFaultInjectionRule(ctx context.Context, rule FaultInjectionRule) (FaultInjectionRule, error) {
	rule = normalizeFaultRule(rule)
	now := time.Now().UTC()
	if rule.ID == "" {
		rule.ID = newStoreID()
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	rule.UpdatedAt = now
	args, err := faultRuleSQLArgs(rule)
	if err != nil {
		return FaultInjectionRule{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO fault_injection_rules
		(id, created_at, updated_at, name, enabled, priority, phase, action, host_patterns_json, url_patterns_json, method_patterns_json, scope_ids_json,
		 delay_ms, throttle_bytes_per_second, corrupt_probability, corrupt_mode, synthetic_status, synthetic_headers_json, synthetic_body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...)
	if err != nil {
		return FaultInjectionRule{}, fmt.Errorf("insert fault rule: %w", err)
	}
	return rule, nil
}

func (s *Store) UpdateFaultInjectionRule(ctx context.Context, rule FaultInjectionRule) (FaultInjectionRule, error) {
	rule = normalizeFaultRule(rule)
	rule.UpdatedAt = time.Now().UTC()
	args, err := faultRuleSQLArgs(rule)
	if err != nil {
		return FaultInjectionRule{}, err
	}
	args = append(args, rule.ID)
	res, err := s.db.ExecContext(ctx, `UPDATE fault_injection_rules SET
		id = ?, created_at = ?, updated_at = ?, name = ?, enabled = ?, priority = ?, phase = ?, action = ?,
		host_patterns_json = ?, url_patterns_json = ?, method_patterns_json = ?, scope_ids_json = ?,
		delay_ms = ?, throttle_bytes_per_second = ?, corrupt_probability = ?, corrupt_mode = ?, synthetic_status = ?, synthetic_headers_json = ?, synthetic_body = ?
		WHERE id = ?`, args...)
	if err != nil {
		return FaultInjectionRule{}, fmt.Errorf("update fault rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return FaultInjectionRule{}, sql.ErrNoRows
	}
	return rule, nil
}

func (s *Store) ListFaultInjectionRules(ctx context.Context) ([]FaultInjectionRule, error) {
	rows, err := s.db.QueryContext(ctx, faultRuleSelect()+` ORDER BY priority ASC, created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("query fault rules: %w", err)
	}
	defer rows.Close()
	out := []FaultInjectionRule{}
	for rows.Next() {
		rule, err := scanFaultRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

func (s *Store) DeleteFaultInjectionRule(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM fault_injection_rules WHERE id = ?`, id)
	return err
}

func (s *Store) MatchFaultInjectionRule(ctx context.Context, phase string, in RequestMatch) (FaultInjectionRule, bool, error) {
	rules, err := s.ListFaultInjectionRules(ctx)
	if err != nil {
		return FaultInjectionRule{}, false, err
	}
	phase = strings.ToLower(strings.TrimSpace(phase))
	for _, rule := range rules {
		if !rule.Enabled || rule.Phase != phase || !ruleMatches(rule.HostPatterns, rule.URLPatterns, rule.MethodPatterns, rule.ScopeIDs, in) {
			continue
		}
		return rule, true, nil
	}
	return FaultInjectionRule{}, false, nil
}

func (s *Store) CreateHostProfile(ctx context.Context, profile HostProfile) (HostProfile, error) {
	profile = normalizeHostProfile(profile)
	now := time.Now().UTC()
	if profile.ID == "" {
		profile.ID = newStoreID()
	}
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = now
	}
	profile.UpdatedAt = now
	args, err := hostProfileSQLArgs(profile)
	if err != nil {
		return HostProfile{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO host_profiles
		(id, created_at, updated_at, name, enabled, priority, host_patterns_json, url_patterns_json, method_patterns_json, overrides_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...)
	if err != nil {
		return HostProfile{}, fmt.Errorf("insert host profile: %w", err)
	}
	return profile, nil
}

func (s *Store) UpdateHostProfile(ctx context.Context, profile HostProfile) (HostProfile, error) {
	profile = normalizeHostProfile(profile)
	profile.UpdatedAt = time.Now().UTC()
	args, err := hostProfileSQLArgs(profile)
	if err != nil {
		return HostProfile{}, err
	}
	args = append(args, profile.ID)
	res, err := s.db.ExecContext(ctx, `UPDATE host_profiles SET
		id = ?, created_at = ?, updated_at = ?, name = ?, enabled = ?, priority = ?,
		host_patterns_json = ?, url_patterns_json = ?, method_patterns_json = ?, overrides_json = ?
		WHERE id = ?`, args...)
	if err != nil {
		return HostProfile{}, fmt.Errorf("update host profile: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return HostProfile{}, sql.ErrNoRows
	}
	return profile, nil
}

func (s *Store) ListHostProfiles(ctx context.Context) ([]HostProfile, error) {
	rows, err := s.db.QueryContext(ctx, hostProfileSelect()+` ORDER BY priority ASC, created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("query host profiles: %w", err)
	}
	defer rows.Close()
	out := []HostProfile{}
	for rows.Next() {
		profile, err := scanHostProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, profile)
	}
	return out, rows.Err()
}

func (s *Store) DeleteHostProfile(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM host_profiles WHERE id = ?`, id)
	return err
}

func (s *Store) MatchHostProfile(ctx context.Context, in RequestMatch) (HostProfile, bool, error) {
	profiles, err := s.ListHostProfiles(ctx)
	if err != nil {
		return HostProfile{}, false, err
	}
	for _, profile := range profiles {
		if !profile.Enabled || !ruleMatches(profile.HostPatterns, profile.URLPatterns, profile.MethodPatterns, nil, in) {
			continue
		}
		return profile, true, nil
	}
	return HostProfile{}, false, nil
}

func (s *Store) AddTimelineEntry(ctx context.Context, entry TimelineEntry) (TimelineEntry, error) {
	if entry.ID == "" {
		entry.ID = newStoreID()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	if entry.Metadata == nil {
		entry.Metadata = json.RawMessage(`{}`)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO timeline_entries
		(id, created_at, kind, topic, request_id, flow_id, connection_id, scope_id, host, method, url, status, duration_ms, summary, severity, metadata_json)
		VALUES (?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, NULLIF(?, ''), ?)`,
		entry.ID, entry.CreatedAt.Format(time.RFC3339Nano), entry.Kind, entry.Topic, entry.RequestID, entry.FlowID, entry.ConnectionID, entry.ScopeID,
		entry.Host, entry.Method, entry.URL, entry.Status, entry.DurationMS, entry.Summary, entry.Severity, string(entry.Metadata))
	if err != nil {
		return TimelineEntry{}, fmt.Errorf("insert timeline entry: %w", err)
	}
	return entry, nil
}

func (s *Store) RecordTimelineEvent(ctx context.Context, event events.Event) (TimelineEntry, bool, error) {
	entry, ok := timelineEntryFromEvent(event)
	if !ok {
		return TimelineEntry{}, false, nil
	}
	if entry.ScopeID == "" && (entry.URL != "" || entry.Host != "") {
		scopeID, _ := s.MatchResearchScope(ctx, entry.Method, entry.URL, entry.Host)
		entry.ScopeID = scopeID
	}
	created, err := s.AddTimelineEntry(ctx, entry)
	return created, true, err
}

func (s *Store) ListTimelineEntries(ctx context.Context, filter TimelineFilter) ([]TimelineEntry, error) {
	if filter.Limit <= 0 || filter.Limit > 1000 {
		filter.Limit = 200
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	clauses := []string{}
	args := []any{}
	if filter.ScopeID != "" {
		if filter.ScopeID == "__out_of_scope__" {
			clauses = append(clauses, `COALESCE(scope_id, '') = ''`)
		} else {
			clauses = append(clauses, `scope_id = ?`)
			args = append(args, filter.ScopeID)
		}
	}
	if filter.Kind != "" {
		clauses = append(clauses, `kind = ?`)
		args = append(args, filter.Kind)
	}
	if filter.Host != "" {
		clauses = append(clauses, `LOWER(COALESCE(host, '')) LIKE ?`)
		args = append(args, "%"+strings.ToLower(filter.Host)+"%")
	}
	if filter.RequestID != "" {
		clauses = append(clauses, `(request_id = ? OR flow_id = ?)`)
		args = append(args, filter.RequestID, filter.RequestID)
	}
	if q := strings.ToLower(strings.TrimSpace(filter.Query)); q != "" {
		like := "%" + q + "%"
		clauses = append(clauses, `(LOWER(kind) LIKE ? OR LOWER(topic) LIKE ? OR LOWER(COALESCE(host, '')) LIKE ? OR LOWER(COALESCE(method, '')) LIKE ? OR LOWER(COALESCE(url, '')) LIKE ? OR LOWER(summary) LIKE ? OR LOWER(COALESCE(severity, '')) LIKE ?)`)
		args = append(args, like, like, like, like, like, like, like)
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	args = append(args, filter.Limit, filter.Offset)
	rows, err := s.db.QueryContext(ctx, timelineSelect()+where+` ORDER BY created_at DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("query timeline: %w", err)
	}
	defer rows.Close()
	out := []TimelineEntry{}
	for rows.Next() {
		entry, err := scanTimelineEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func normalizeFaultRule(rule FaultInjectionRule) FaultInjectionRule {
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		rule.Name = "Fault rule"
	}
	if rule.Priority == 0 {
		rule.Priority = 100
	}
	rule.Phase = strings.ToLower(strings.TrimSpace(rule.Phase))
	if rule.Phase == "" {
		rule.Phase = "request"
	}
	rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
	if rule.Action == "" {
		rule.Action = "delay"
	}
	if rule.CorruptMode == "" {
		rule.CorruptMode = "flip_byte"
	}
	if rule.SyntheticHeaders == nil {
		rule.SyntheticHeaders = map[string][]string{}
	}
	return rule
}

func normalizeHostProfile(profile HostProfile) HostProfile {
	profile.Name = strings.TrimSpace(profile.Name)
	if profile.Name == "" {
		profile.Name = "Host profile"
	}
	if profile.Priority == 0 {
		profile.Priority = 100
	}
	return profile
}

func ruleMatches(hostPatterns, urlPatterns, methodPatterns, scopeIDs []string, in RequestMatch) bool {
	host := in.Host
	if host == "" && in.URL != "" {
		if parsed, err := url.Parse(in.URL); err == nil {
			host = parsed.Host
		}
	}
	if len(hostPatterns) > 0 && !matchAnyTextPattern(hostPatterns, host) {
		return false
	}
	if len(urlPatterns) > 0 && !matchAnyTextPattern(urlPatterns, in.URL) {
		return false
	}
	if len(methodPatterns) > 0 && !matchAnyTextPattern(methodPatterns, strings.ToUpper(in.Method)) {
		return false
	}
	if len(scopeIDs) > 0 && !containsFold(scopeIDs, in.ScopeID) {
		return false
	}
	return true
}

func faultRuleSQLArgs(rule FaultInjectionRule) ([]any, error) {
	hostPatterns, err := marshalJSON(rule.HostPatterns)
	if err != nil {
		return nil, err
	}
	urlPatterns, err := marshalJSON(rule.URLPatterns)
	if err != nil {
		return nil, err
	}
	methodPatterns, err := marshalJSON(rule.MethodPatterns)
	if err != nil {
		return nil, err
	}
	scopeIDs, err := marshalJSON(rule.ScopeIDs)
	if err != nil {
		return nil, err
	}
	headers, err := marshalJSON(rule.SyntheticHeaders)
	if err != nil {
		return nil, err
	}
	return []any{
		rule.ID, rule.CreatedAt.Format(time.RFC3339Nano), rule.UpdatedAt.Format(time.RFC3339Nano), rule.Name, boolInt(rule.Enabled),
		rule.Priority, rule.Phase, rule.Action, hostPatterns, urlPatterns, methodPatterns, scopeIDs, rule.DelayMS, rule.ThrottleBytesPerSecond,
		rule.CorruptProbability, rule.CorruptMode, rule.SyntheticStatus, headers, rule.SyntheticBody,
	}, nil
}

func hostProfileSQLArgs(profile HostProfile) ([]any, error) {
	hostPatterns, err := marshalJSON(profile.HostPatterns)
	if err != nil {
		return nil, err
	}
	urlPatterns, err := marshalJSON(profile.URLPatterns)
	if err != nil {
		return nil, err
	}
	methodPatterns, err := marshalJSON(profile.MethodPatterns)
	if err != nil {
		return nil, err
	}
	overrides, err := marshalJSON(profile.Overrides)
	if err != nil {
		return nil, err
	}
	return []any{
		profile.ID, profile.CreatedAt.Format(time.RFC3339Nano), profile.UpdatedAt.Format(time.RFC3339Nano), profile.Name, boolInt(profile.Enabled),
		profile.Priority, hostPatterns, urlPatterns, methodPatterns, overrides,
	}, nil
}

func faultRuleSelect() string {
	return `SELECT id, created_at, updated_at, name, enabled, priority, phase, action, host_patterns_json, url_patterns_json, method_patterns_json, scope_ids_json,
		delay_ms, throttle_bytes_per_second, corrupt_probability, COALESCE(corrupt_mode, ''), synthetic_status, synthetic_headers_json, COALESCE(synthetic_body, '')
		FROM fault_injection_rules`
}

func hostProfileSelect() string {
	return `SELECT id, created_at, updated_at, name, enabled, priority, host_patterns_json, url_patterns_json, method_patterns_json, overrides_json FROM host_profiles`
}

func timelineSelect() string {
	return `SELECT id, created_at, kind, topic, COALESCE(request_id, ''), COALESCE(flow_id, ''), COALESCE(connection_id, ''), COALESCE(scope_id, ''),
		COALESCE(host, ''), COALESCE(method, ''), COALESCE(url, ''), COALESCE(status, 0), COALESCE(duration_ms, 0), summary, COALESCE(severity, ''), metadata_json
		FROM timeline_entries`
}

func scanFaultRule(row any) (FaultInjectionRule, error) {
	scanner := row.(interface{ Scan(...any) error })
	var rule FaultInjectionRule
	var createdAt, updatedAt, hostPatterns, urlPatterns, methodPatterns, scopeIDs, headers string
	var enabled int
	if err := scanner.Scan(&rule.ID, &createdAt, &updatedAt, &rule.Name, &enabled, &rule.Priority, &rule.Phase, &rule.Action, &hostPatterns, &urlPatterns, &methodPatterns, &scopeIDs,
		&rule.DelayMS, &rule.ThrottleBytesPerSecond, &rule.CorruptProbability, &rule.CorruptMode, &rule.SyntheticStatus, &headers, &rule.SyntheticBody); err != nil {
		return FaultInjectionRule{}, err
	}
	rule.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	rule.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	rule.Enabled = enabled != 0
	rule.HostPatterns = unmarshalStringList(hostPatterns)
	rule.URLPatterns = unmarshalStringList(urlPatterns)
	rule.MethodPatterns = unmarshalStringList(methodPatterns)
	rule.ScopeIDs = unmarshalStringList(scopeIDs)
	rule.SyntheticHeaders = map[string][]string{}
	_ = json.Unmarshal([]byte(headers), &rule.SyntheticHeaders)
	return rule, nil
}

func scanHostProfile(row any) (HostProfile, error) {
	scanner := row.(interface{ Scan(...any) error })
	var profile HostProfile
	var createdAt, updatedAt, hostPatterns, urlPatterns, methodPatterns, overrides string
	var enabled int
	if err := scanner.Scan(&profile.ID, &createdAt, &updatedAt, &profile.Name, &enabled, &profile.Priority, &hostPatterns, &urlPatterns, &methodPatterns, &overrides); err != nil {
		return HostProfile{}, err
	}
	profile.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	profile.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	profile.Enabled = enabled != 0
	profile.HostPatterns = unmarshalStringList(hostPatterns)
	profile.URLPatterns = unmarshalStringList(urlPatterns)
	profile.MethodPatterns = unmarshalStringList(methodPatterns)
	_ = json.Unmarshal([]byte(overrides), &profile.Overrides)
	return profile, nil
}

func scanTimelineEntry(row any) (TimelineEntry, error) {
	scanner := row.(interface{ Scan(...any) error })
	var entry TimelineEntry
	var createdAt, metadata string
	if err := scanner.Scan(&entry.ID, &createdAt, &entry.Kind, &entry.Topic, &entry.RequestID, &entry.FlowID, &entry.ConnectionID, &entry.ScopeID,
		&entry.Host, &entry.Method, &entry.URL, &entry.Status, &entry.DurationMS, &entry.Summary, &entry.Severity, &metadata); err != nil {
		return TimelineEntry{}, err
	}
	entry.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	entry.Metadata = json.RawMessage(metadata)
	return entry, nil
}

func marshalJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func timelineEntryFromEvent(event events.Event) (TimelineEntry, bool) {
	entry := TimelineEntry{
		CreatedAt: event.Time,
		Topic:     event.Topic,
		RequestID: event.RequestID,
		FlowID:    event.RequestID,
		Host:      firstStringPayload(event, "host", "target"),
		Method:    stringPayload(event, "method"),
		URL:       firstStringPayload(event, "url", "target"),
		Status:    int(intPayload(event, "status")),
		DurationMS: intPayload(event, "duration_ms"),
	}
	meta, _ := json.Marshal(event.Payload)
	entry.Metadata = meta
	switch event.Topic {
	case events.TopicTrafficRequestStarted:
		entry.Kind = "traffic"
		entry.Summary = strings.TrimSpace(entry.Method + " " + entry.URL + " started")
	case events.TopicTrafficResponseCompleted:
		entry.Kind = "traffic"
		entry.Summary = fmt.Sprintf("%s %s completed with %d", entry.Method, entry.URL, entry.Status)
	case events.TopicTrafficTunnelOpened:
		entry.Kind = "tunnel"
		entry.Summary = "CONNECT tunnel opened to " + entry.URL
	case events.TopicTrafficBlocked:
		entry.Kind = "blocked"
		entry.Severity = "warn"
		entry.Summary = "Blocked " + firstNonEmpty(entry.URL, entry.Host)
	case events.TopicCacheHit:
		entry.Kind = "cache"
		entry.Summary = "Cache hit for " + entry.URL
	case events.TopicCacheMiss:
		entry.Kind = "cache"
		entry.Summary = "Cache miss for " + entry.URL
	case events.TopicInterceptPending:
		entry.Kind = "intercept"
		entry.Severity = "warn"
		entry.Summary = "Intercept pending"
	case events.TopicInterceptResolved:
		entry.Kind = "intercept"
		entry.Summary = "Intercept resolved"
	case events.TopicWebSocketConnection:
		entry.Kind = "websocket"
		entry.ConnectionID = stringPayload(event, "id")
		entry.Summary = "WebSocket connected to " + entry.Host
	case events.TopicWebSocketFrame:
		entry.Kind = "websocket"
		entry.ConnectionID = stringPayload(event, "connection_id")
		entry.Summary = "WebSocket frame"
	case events.TopicFaultInjected:
		entry.Kind = "fault"
		entry.Severity = "warn"
		entry.Summary = stringPayload(event, "action") + " fault injected for " + firstNonEmpty(entry.URL, entry.Host)
	case events.TopicConfigUpdated:
		entry.Kind = "config"
		entry.Summary = "Configuration updated"
	case events.TopicHostProfileMatched:
		entry.Kind = "profile"
		entry.Summary = "Host profile matched " + firstNonEmpty(stringPayload(event, "profile_name"), stringPayload(event, "profile_id"))
	default:
		return TimelineEntry{}, false
	}
	if entry.Summary == "" {
		entry.Summary = event.Topic
	}
	return entry, true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
