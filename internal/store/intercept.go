package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type TrafficQueryError struct {
	Message string `json:"error"`
}

func (e TrafficQueryError) Error() string { return e.Message }

type BreakpointMatch struct {
	Direction   string
	Method      string
	URL         string
	Host        string
	Status      int
	ScopeID     string
	ContentType string
}

func (s *Store) CreateInterceptRule(ctx context.Context, rule InterceptRule) (InterceptRule, error) {
	rule = normalizeInterceptRule(rule)
	now := time.Now().UTC()
	if rule.ID == "" {
		rule.ID = newStoreID()
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	rule.UpdatedAt = now
	args, err := interceptRuleSQLArgs(rule)
	if err != nil {
		return InterceptRule{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO intercept_rules
		(id, created_at, updated_at, name, enabled, priority, direction, host_patterns_json, method_patterns_json, status_patterns_json, scope_ids_json, content_type_patterns_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...)
	if err != nil {
		return InterceptRule{}, fmt.Errorf("insert intercept rule: %w", err)
	}
	return rule, nil
}

func (s *Store) UpdateInterceptRule(ctx context.Context, rule InterceptRule) (InterceptRule, error) {
	rule = normalizeInterceptRule(rule)
	rule.UpdatedAt = time.Now().UTC()
	args, err := interceptRuleSQLArgs(rule)
	if err != nil {
		return InterceptRule{}, err
	}
	args = append(args, rule.ID)
	res, err := s.db.ExecContext(ctx, `UPDATE intercept_rules SET
		id = ?, created_at = ?, updated_at = ?, name = ?, enabled = ?, priority = ?, direction = ?,
		host_patterns_json = ?, method_patterns_json = ?, status_patterns_json = ?, scope_ids_json = ?, content_type_patterns_json = ?
		WHERE id = ?`, args...)
	if err != nil {
		return InterceptRule{}, fmt.Errorf("update intercept rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return InterceptRule{}, sql.ErrNoRows
	}
	return rule, nil
}

func (s *Store) ListInterceptRules(ctx context.Context) ([]InterceptRule, error) {
	rows, err := s.db.QueryContext(ctx, interceptRuleSelect()+` ORDER BY priority ASC, created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("query intercept rules: %w", err)
	}
	defer rows.Close()
	rules := []InterceptRule{}
	for rows.Next() {
		rule, err := scanInterceptRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (s *Store) DeleteInterceptRule(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM intercept_pending WHERE rule_id = ?`, id); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("delete intercept pending for rule: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM intercept_rules WHERE id = ?`, id); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("delete intercept rule: %w", err)
	}
	return tx.Commit()
}

func (s *Store) MatchInterceptRule(ctx context.Context, in BreakpointMatch) (InterceptRule, bool, error) {
	rules, err := s.ListInterceptRules(ctx)
	if err != nil {
		return InterceptRule{}, false, err
	}
	for _, rule := range rules {
		if !rule.Enabled || rule.Direction != strings.ToLower(in.Direction) {
			continue
		}
		if len(rule.HostPatterns) > 0 && !matchAnyTextPattern(rule.HostPatterns, in.Host) {
			continue
		}
		if len(rule.MethodPatterns) > 0 && !matchAnyTextPattern(rule.MethodPatterns, strings.ToUpper(in.Method)) {
			continue
		}
		if len(rule.StatusPatterns) > 0 && !matchAnyStatusPattern(rule.StatusPatterns, in.Status) {
			continue
		}
		if len(rule.ScopeIDs) > 0 && !containsFold(rule.ScopeIDs, in.ScopeID) {
			continue
		}
		if len(rule.ContentTypePatterns) > 0 && !matchAnyTextPattern(rule.ContentTypePatterns, in.ContentType) {
			continue
		}
		return rule, true, nil
	}
	return InterceptRule{}, false, nil
}

func (s *Store) CreatePendingIntercept(ctx context.Context, pending PendingIntercept) (PendingIntercept, error) {
	now := time.Now().UTC()
	if pending.ID == "" {
		pending.ID = newStoreID()
	}
	if pending.CreatedAt.IsZero() {
		pending.CreatedAt = now
	}
	pending.UpdatedAt = now
	if pending.State == "" {
		pending.State = "pending"
	}
	orig, _ := json.Marshal(pending.Original)
	edited, _ := json.Marshal(pending.Edited)
	_, err := s.db.ExecContext(ctx, `INSERT INTO intercept_pending
		(id, created_at, updated_at, request_id, rule_id, direction, state, timeout_at, timeout_action, original_json, edited_json, resolution_note)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		pending.ID, pending.CreatedAt.Format(time.RFC3339Nano), pending.UpdatedAt.Format(time.RFC3339Nano), pending.RequestID,
		pending.RuleID, pending.Direction, pending.State, pending.TimeoutAt.Format(time.RFC3339Nano), pending.TimeoutAction,
		string(orig), string(edited), pending.ResolutionNote)
	if err != nil {
		return PendingIntercept{}, fmt.Errorf("insert pending intercept: %w", err)
	}
	return pending, nil
}

func (s *Store) ListPendingIntercepts(ctx context.Context, state string, limit int) ([]PendingIntercept, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	clauses := []string{`(COALESCE(rule_id, '') = '' OR EXISTS (SELECT 1 FROM intercept_rules ir WHERE ir.id = intercept_pending.rule_id))`}
	args := []any{}
	if state = strings.TrimSpace(state); state != "" {
		clauses = append(clauses, "state = ?")
		args = append(args, state)
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, interceptPendingSelect()+` WHERE `+strings.Join(clauses, " AND ")+` ORDER BY created_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("query pending intercepts: %w", err)
	}
	defer rows.Close()
	out := []PendingIntercept{}
	for rows.Next() {
		pending, err := scanPendingIntercept(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pending)
	}
	return out, rows.Err()
}

func (s *Store) GetPendingIntercept(ctx context.Context, id string) (PendingIntercept, bool, error) {
	row := s.db.QueryRowContext(ctx, interceptPendingSelect()+` WHERE id = ?`, id)
	pending, err := scanPendingIntercept(row)
	if err == sql.ErrNoRows {
		return PendingIntercept{}, false, nil
	}
	if err != nil {
		return PendingIntercept{}, false, err
	}
	return pending, true, nil
}

func (s *Store) ResolvePendingIntercept(ctx context.Context, id, state, note string, edited InterceptMessage) (PendingIntercept, bool, error) {
	current, ok, err := s.GetPendingIntercept(ctx, id)
	if err != nil || !ok {
		return PendingIntercept{}, ok, err
	}
	if strings.TrimSpace(state) == "" {
		state = current.State
	}
	current.State = state
	current.ResolutionNote = note
	if edited.Headers != nil || edited.Body != "" || edited.Status != 0 {
		current.Edited = mergeInterceptMessage(current.Edited, edited)
	}
	current.UpdatedAt = time.Now().UTC()
	raw, _ := json.Marshal(current.Edited)
	_, err = s.db.ExecContext(ctx, `UPDATE intercept_pending SET state = ?, updated_at = ?, edited_json = ?, resolution_note = ? WHERE id = ?`,
		current.State, current.UpdatedAt.Format(time.RFC3339Nano), string(raw), current.ResolutionNote, id)
	if err != nil {
		return PendingIntercept{}, false, fmt.Errorf("resolve pending intercept: %w", err)
	}
	return current, true, nil
}

func (s *Store) CreateWebSocketConnection(ctx context.Context, c WebSocketConnection) (WebSocketConnection, error) {
	if c.ID == "" {
		c.ID = newStoreID()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	scopeID, _ := s.MatchResearchScope(ctx, "GET", c.URL, c.Host)
	if c.ScopeID == "" {
		c.ScopeID = scopeID
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO websocket_connections
		(id, created_at, closed_at, url, host, protocol, remote_ip, scope_id, proxy_user)
		VALUES (?, ?, NULL, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''))`,
		c.ID, c.CreatedAt.Format(time.RFC3339Nano), c.URL, c.Host, c.Protocol, c.RemoteIP, c.ScopeID, c.ProxyUser)
	return c, err
}

func (s *Store) CloseWebSocketConnection(ctx context.Context, id string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `UPDATE websocket_connections SET closed_at = COALESCE(closed_at, ?) WHERE id = ?`, now, id)
	return err
}

func (s *Store) AddWebSocketFrame(ctx context.Context, f WebSocketFrame) (WebSocketFrame, error) {
	if f.ID == "" {
		f.ID = newStoreID()
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	if f.OpcodeName == "" {
		f.OpcodeName = websocketOpcodeName(f.Opcode)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO websocket_frames
		(id, connection_id, created_at, direction, opcode, opcode_name, payload, payload_bytes, truncated, injected)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.ConnectionID, f.CreatedAt.Format(time.RFC3339Nano), f.Direction, f.Opcode, f.OpcodeName,
		f.Payload, f.PayloadBytes, boolInt(f.Truncated), boolInt(f.Injected))
	return f, err
}

func (s *Store) ListWebSocketConnections(ctx context.Context, limit int) ([]WebSocketConnection, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT c.id, c.created_at, COALESCE(c.closed_at, ''), c.url, c.host, c.protocol, COALESCE(c.remote_ip, ''), COALESCE(c.scope_id, ''), COALESCE(c.proxy_user, ''), COUNT(f.id)
		FROM websocket_connections c LEFT JOIN websocket_frames f ON f.connection_id = c.id
		GROUP BY c.id ORDER BY c.created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WebSocketConnection{}
	for rows.Next() {
		c, err := scanWebSocketConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetWebSocketConnection(ctx context.Context, id string) (WebSocketConnection, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT c.id, c.created_at, COALESCE(c.closed_at, ''), c.url, c.host, c.protocol, COALESCE(c.remote_ip, ''), COALESCE(c.scope_id, ''), COALESCE(c.proxy_user, ''), COUNT(f.id)
		FROM websocket_connections c LEFT JOIN websocket_frames f ON f.connection_id = c.id WHERE c.id = ? GROUP BY c.id`, id)
	c, err := scanWebSocketConnection(row)
	if err == sql.ErrNoRows {
		return WebSocketConnection{}, false, nil
	}
	if err != nil {
		return WebSocketConnection{}, false, err
	}
	return c, true, nil
}

func (s *Store) ListWebSocketFrames(ctx context.Context, connectionID string, limit, offset int, search string) ([]WebSocketFrame, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	where := ` WHERE connection_id = ?`
	args := []any{connectionID}
	if search = strings.TrimSpace(search); search != "" {
		where += ` AND (LOWER(COALESCE(payload, '')) LIKE ? OR LOWER(opcode_name) LIKE ? OR LOWER(direction) LIKE ?)`
		term := "%" + strings.ToLower(search) + "%"
		args = append(args, term, term, term)
	}
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, `SELECT id, connection_id, created_at, direction, opcode, opcode_name, COALESCE(payload, ''), payload_bytes, truncated, injected FROM websocket_frames`+where+` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WebSocketFrame{}
	for rows.Next() {
		f, err := scanWebSocketFrame(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) PurgeInterceptAndWebSockets(ctx context.Context) error {
	for _, table := range []string{"intercept_pending", "intercept_rules", "websocket_frames", "websocket_connections"} {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM `+table); err != nil {
			return err
		}
	}
	return nil
}

func interceptRuleSelect() string {
	return `SELECT id, created_at, updated_at, name, enabled, priority, direction, host_patterns_json, method_patterns_json, status_patterns_json, scope_ids_json, content_type_patterns_json FROM intercept_rules`
}

func interceptRuleSQLArgs(rule InterceptRule) ([]any, error) {
	lists := [][]string{rule.HostPatterns, rule.MethodPatterns, rule.StatusPatterns, rule.ScopeIDs, rule.ContentTypePatterns}
	encoded := make([]string, 0, len(lists))
	for _, list := range lists {
		raw, err := json.Marshal(list)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, string(raw))
	}
	return []any{
		rule.ID, rule.CreatedAt.Format(time.RFC3339Nano), rule.UpdatedAt.Format(time.RFC3339Nano), rule.Name,
		boolInt(rule.Enabled), rule.Priority, rule.Direction, encoded[0], encoded[1], encoded[2], encoded[3], encoded[4],
	}, nil
}

func normalizeInterceptRule(rule InterceptRule) InterceptRule {
	rule.ID = strings.TrimSpace(rule.ID)
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		rule.Name = "Breakpoint rule"
	}
	rule.Direction = strings.ToLower(strings.TrimSpace(rule.Direction))
	if rule.Direction != "response" {
		rule.Direction = "request"
	}
	if rule.Priority == 0 {
		rule.Priority = 100
	}
	rule.HostPatterns = normalizeStringList(rule.HostPatterns, false)
	rule.MethodPatterns = normalizeStringList(rule.MethodPatterns, true)
	rule.StatusPatterns = normalizeStringList(rule.StatusPatterns, false)
	rule.ScopeIDs = normalizeStringList(rule.ScopeIDs, false)
	rule.ContentTypePatterns = normalizeStringList(rule.ContentTypePatterns, false)
	return rule
}

func scanInterceptRule(row trafficScanner) (InterceptRule, error) {
	var rule InterceptRule
	var createdAt, updatedAt, hostJSON, methodJSON, statusJSON, scopeJSON, contentTypeJSON string
	var enabled int
	if err := row.Scan(&rule.ID, &createdAt, &updatedAt, &rule.Name, &enabled, &rule.Priority, &rule.Direction, &hostJSON, &methodJSON, &statusJSON, &scopeJSON, &contentTypeJSON); err != nil {
		return InterceptRule{}, err
	}
	rule.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	rule.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	rule.Enabled = enabled != 0
	rule.HostPatterns = unmarshalStringList(hostJSON)
	rule.MethodPatterns = unmarshalStringList(methodJSON)
	rule.StatusPatterns = unmarshalStringList(statusJSON)
	rule.ScopeIDs = unmarshalStringList(scopeJSON)
	rule.ContentTypePatterns = unmarshalStringList(contentTypeJSON)
	return normalizeInterceptRule(rule), nil
}

func interceptPendingSelect() string {
	return `SELECT id, created_at, updated_at, request_id, COALESCE(rule_id, ''), direction, state, timeout_at, timeout_action, original_json, edited_json, COALESCE(resolution_note, '') FROM intercept_pending`
}

func scanPendingIntercept(row trafficScanner) (PendingIntercept, error) {
	var p PendingIntercept
	var createdAt, updatedAt, timeoutAt, originalJSON, editedJSON string
	if err := row.Scan(&p.ID, &createdAt, &updatedAt, &p.RequestID, &p.RuleID, &p.Direction, &p.State, &timeoutAt, &p.TimeoutAction, &originalJSON, &editedJSON, &p.ResolutionNote); err != nil {
		return PendingIntercept{}, err
	}
	p.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	p.TimeoutAt, _ = time.Parse(time.RFC3339Nano, timeoutAt)
	_ = json.Unmarshal([]byte(originalJSON), &p.Original)
	_ = json.Unmarshal([]byte(editedJSON), &p.Edited)
	return p, nil
}

func mergeInterceptMessage(base, patch InterceptMessage) InterceptMessage {
	if patch.Method != "" {
		base.Method = patch.Method
	}
	if patch.URL != "" {
		base.URL = patch.URL
	}
	if patch.Host != "" {
		base.Host = patch.Host
	}
	if patch.Status != 0 {
		base.Status = patch.Status
	}
	if patch.Headers != nil {
		base.Headers = patch.Headers
	}
	if patch.Body != "" {
		base.Body = patch.Body
	}
	if patch.MIMEType != "" {
		base.MIMEType = patch.MIMEType
	}
	return base
}

func scanWebSocketConnection(row trafficScanner) (WebSocketConnection, error) {
	var c WebSocketConnection
	var createdAt, closedAt string
	if err := row.Scan(&c.ID, &createdAt, &closedAt, &c.URL, &c.Host, &c.Protocol, &c.RemoteIP, &c.ScopeID, &c.ProxyUser, &c.FrameCount); err != nil {
		return WebSocketConnection{}, err
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	if parsed, err := time.Parse(time.RFC3339Nano, closedAt); err == nil {
		c.ClosedAt = &parsed
	}
	return c, nil
}

func scanWebSocketFrame(row trafficScanner) (WebSocketFrame, error) {
	var f WebSocketFrame
	var createdAt string
	var truncated, injected int
	if err := row.Scan(&f.ID, &f.ConnectionID, &createdAt, &f.Direction, &f.Opcode, &f.OpcodeName, &f.Payload, &f.PayloadBytes, &truncated, &injected); err != nil {
		return WebSocketFrame{}, err
	}
	f.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	f.Truncated = truncated != 0
	f.Injected = injected != 0
	return f, nil
}

func websocketOpcodeName(opcode int) string {
	switch opcode {
	case 1:
		return "text"
	case 2:
		return "binary"
	case 8:
		return "close"
	case 9:
		return "ping"
	case 10:
		return "pong"
	default:
		return "continuation"
	}
}

func matchAnyTextPattern(patterns []string, value string) bool {
	value = strings.ToLower(value)
	for _, pattern := range patterns {
		p := strings.ToLower(strings.TrimSpace(pattern))
		if p == "" {
			continue
		}
		if p == "*" || strings.Contains(value, strings.Trim(p, "*")) {
			return true
		}
	}
	return false
}

func matchAnyStatusPattern(patterns []string, status int) bool {
	rawStatus := strconv.Itoa(status)
	for _, pattern := range patterns {
		p := strings.TrimSpace(pattern)
		if p == "" || p == "*" || p == rawStatus {
			return true
		}
		if strings.HasPrefix(p, ">=") {
			n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(p, ">=")))
			if status >= n {
				return true
			}
		}
		if strings.HasPrefix(p, "<=") {
			n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(p, "<=")))
			if status <= n {
				return true
			}
		}
	}
	return false
}

func (s *Store) ListTrafficAdvanced(ctx context.Context, limit, offset int, scopeID string, includeOutOfScope bool, query string) ([]TrafficFlow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	where, args := scopedWhere(scopeID, includeOutOfScope)
	searchWhere, searchArgs, err := trafficSearchWhere(query)
	if err != nil {
		return nil, err
	}
	if searchWhere != "" {
		if where == "" {
			where = " WHERE " + searchWhere
		} else {
			where += " AND " + searchWhere
		}
		args = append(args, searchArgs...)
	}
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT tf.id, tf.created_at, COALESCE(tf.method, ''), COALESCE(tf.url, ''), COALESCE(tf.host, ''),
		 COALESCE(tf.status, 0), COALESCE(tf.protocol, ''), COALESCE(tf.mime_type, ''), COALESCE(tf.remote_ip, ''),
		 COALESCE(tf.duration_ms, 0), COALESCE(tf.bytes, 0), tf.cache_hit, tf.blocked, COALESCE(tf.rule_id, ''), COALESCE(tf.scope_id, ''), COALESCE(tf.proxy_user, '')
		 FROM traffic_flows tf`+where+` ORDER BY tf.created_at DESC LIMIT ? OFFSET ?`, args...)
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
	return flows, rows.Err()
}

func trafficSearchWhere(query string) (string, []any, error) {
	tokens, err := splitSearchTokens(query)
	if err != nil {
		return "", nil, err
	}
	var clauses []string
	var args []any
	for _, token := range tokens {
		field, value, hasField := strings.Cut(token, ":")
		if !hasField {
			term := "%" + strings.ToLower(token) + "%"
			clauses = append(clauses, `(LOWER(COALESCE(tf.method, '')) LIKE ? OR LOWER(COALESCE(tf.url, '')) LIKE ? OR LOWER(COALESCE(tf.host, '')) LIKE ? OR CAST(COALESCE(tf.status, 0) AS TEXT) LIKE ? OR LOWER(COALESCE(tf.protocol, '')) LIKE ? OR LOWER(COALESCE(tf.mime_type, '')) LIKE ? OR LOWER(COALESCE(tf.rule_id, '')) LIKE ? OR LOWER(COALESCE(tf.proxy_user, '')) LIKE ?)`)
			args = append(args, term, term, term, term, term, term, term, term)
			continue
		}
		field = strings.ToLower(strings.TrimSpace(field))
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if value == "" {
			return "", nil, TrafficQueryError{Message: "search filter " + field + " requires a value"}
		}
		term := "%" + strings.ToLower(value) + "%"
		switch field {
		case "host":
			clauses = append(clauses, `LOWER(COALESCE(tf.host, '')) LIKE ?`)
			args = append(args, term)
		case "method":
			clauses = append(clauses, `UPPER(COALESCE(tf.method, '')) = ?`)
			args = append(args, strings.ToUpper(value))
		case "status":
			clause, val, err := statusSearchClause(value)
			if err != nil {
				return "", nil, err
			}
			clauses = append(clauses, clause)
			args = append(args, val)
		case "scope":
			clauses = append(clauses, `COALESCE(tf.scope_id, '') = ?`)
			args = append(args, value)
		case "user":
			clauses = append(clauses, `LOWER(COALESCE(tf.proxy_user, '')) LIKE ?`)
			args = append(args, term)
		case "header":
			clauses = append(clauses, `EXISTS (SELECT 1 FROM traffic_headers th WHERE th.flow_id = tf.id AND (LOWER(th.name) LIKE ? OR LOWER(th.value) LIKE ?))`)
			args = append(args, term, term)
		case "cookie":
			clauses = append(clauses, `EXISTS (SELECT 1 FROM traffic_headers th WHERE th.flow_id = tf.id AND LOWER(th.name) IN ('cookie', 'set-cookie') AND LOWER(th.value) LIKE ?)`)
			args = append(args, term)
		case "body":
			clauses = append(clauses, `EXISTS (SELECT 1 FROM traffic_bodies tb WHERE tb.flow_id = tf.id AND (LOWER(COALESCE(tb.request_body, '')) LIKE ? OR LOWER(COALESCE(tb.response_body, '')) LIKE ?))`)
			args = append(args, term, term)
		case "threat":
			clauses = append(clauses, `EXISTS (SELECT 1 FROM threat_events te WHERE (te.url = tf.url OR te.host = tf.host) AND (LOWER(te.action) LIKE ? OR LOWER(te.category) LIKE ? OR LOWER(te.reason) LIKE ?))`)
			args = append(args, term, term, term)
		default:
			return "", nil, TrafficQueryError{Message: "unknown search field: " + field}
		}
	}
	return strings.Join(clauses, " AND "), args, nil
}

func statusSearchClause(value string) (string, any, error) {
	for _, op := range []string{">=", "<=", ">", "<"} {
		if strings.HasPrefix(value, op) {
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(value, op)))
			if err != nil {
				return "", nil, TrafficQueryError{Message: "status filter requires a numeric value"}
			}
			return "COALESCE(tf.status, 0) " + op + " ?", n, nil
		}
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return "", nil, TrafficQueryError{Message: "status filter requires a numeric value"}
	}
	return "COALESCE(tf.status, 0) = ?", n, nil
}

func splitSearchTokens(query string) ([]string, error) {
	var tokens []string
	var b strings.Builder
	inQuote := false
	for _, r := range query {
		switch {
		case r == '"':
			inQuote = !inQuote
			b.WriteRune(r)
		case (r == ' ' || r == '\t' || r == '\n') && !inQuote:
			if strings.TrimSpace(b.String()) != "" {
				tokens = append(tokens, strings.TrimSpace(b.String()))
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if inQuote {
		return nil, TrafficQueryError{Message: "unterminated quote in search query"}
	}
	if strings.TrimSpace(b.String()) != "" {
		tokens = append(tokens, strings.TrimSpace(b.String()))
	}
	return tokens, nil
}

func headerFromMap(values map[string][]string) http.Header {
	h := http.Header{}
	for key, vals := range values {
		for _, val := range vals {
			h.Add(key, val)
		}
	}
	return h
}
