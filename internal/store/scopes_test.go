package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"mitm-proxy/internal/events"
)

func TestResearchScopeMigrationCreatesTableAndColumns(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	var table string
	if err := s.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name='research_scopes'`).Scan(&table); err != nil {
		t.Fatalf("expected research_scopes table: %v", err)
	}
	for _, tc := range []struct {
		table  string
		column string
	}{
		{"traffic_flows", "scope_id"},
		{"repeater_cases", "scope_id"},
		{"threat_events", "scope_id"},
	} {
		if !columnExists(t, s, tc.table, tc.column) {
			t.Fatalf("expected %s.%s column", tc.table, tc.column)
		}
	}
}

func TestResearchScopeCRUDAndDeleteNullsReferences(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	scope, err := s.CreateResearchScope(ctx, ResearchScope{
		Name:           "Target",
		Description:    "primary target",
		Enabled:        true,
		HostPatterns:   []string{" example.test ", "example.test"},
		URLPatterns:    []string{"/api"},
		MethodPatterns: []string{"post"},
	})
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	if scope.ID == "" || len(scope.HostPatterns) != 1 || scope.MethodPatterns[0] != "POST" {
		t.Fatalf("scope was not normalized: %+v", scope)
	}

	scopes, err := s.ListResearchScopes(ctx)
	if err != nil || len(scopes) != 1 {
		t.Fatalf("list scopes len=%d err=%v", len(scopes), err)
	}
	got, ok, err := s.GetResearchScope(ctx, scope.ID)
	if err != nil || !ok {
		t.Fatalf("get scope ok=%v err=%v", ok, err)
	}
	got.Name = "Target updated"
	got.URLPatterns = append(got.URLPatterns, "/login")
	updated, err := s.UpdateResearchScope(ctx, got)
	if err != nil {
		t.Fatalf("update scope: %v", err)
	}
	if updated.Name != "Target updated" || len(updated.URLPatterns) != 2 {
		t.Fatalf("unexpected updated scope: %+v", updated)
	}

	flowID := seedScopedStoreTraffic(t, s, "https://example.test/api/login", "example.test", "POST")
	repeaterCase, err := s.CreateRepeaterCase(ctx, RepeaterCase{
		Name:      "probe",
		Method:    "GET",
		URL:       "https://example.test/",
		Headers:   map[string][]string{},
		TimeoutMS: 30000,
		ScopeID:   scope.ID,
	})
	if err != nil {
		t.Fatalf("create repeater case: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO threat_events (id, timestamp, target, verdict, confidence, action, ai_used, blocked, scope_id)
		 VALUES ('threat-1', ?, 'https://example.test/', '{}', 0, 'allow', 0, 0, ?)`,
		time.Now().UTC().Format(time.RFC3339Nano), scope.ID); err != nil {
		t.Fatalf("insert threat event: %v", err)
	}

	if err := s.DeleteResearchScope(ctx, scope.ID); err != nil {
		t.Fatalf("delete scope: %v", err)
	}
	flow, _, err := s.GetTraffic(ctx, flowID)
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	if flow.ScopeID != "" {
		t.Fatalf("expected traffic scope cleared, got %q", flow.ScopeID)
	}
	storedCase, _, err := s.GetRepeaterCase(ctx, repeaterCase.ID)
	if err != nil {
		t.Fatalf("get repeater case: %v", err)
	}
	if storedCase.ScopeID != "" {
		t.Fatalf("expected repeater scope cleared, got %q", storedCase.ScopeID)
	}
	var threatScope string
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(scope_id, '') FROM threat_events WHERE id = 'threat-1'`).Scan(&threatScope); err != nil {
		t.Fatalf("get threat scope: %v", err)
	}
	if threatScope != "" {
		t.Fatalf("expected threat scope cleared, got %q", threatScope)
	}
}

func TestResearchScopeMatcherAndTrafficFilters(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	disabled, err := s.CreateResearchScope(ctx, ResearchScope{Name: "Disabled", Enabled: false, HostPatterns: []string{"target.test"}})
	if err != nil {
		t.Fatalf("create disabled scope: %v", err)
	}
	first, err := s.CreateResearchScope(ctx, ResearchScope{Name: "First", Enabled: true, HostPatterns: []string{"*.target.test"}, URLPatterns: []string{"/scoped"}, MethodPatterns: []string{"GET"}})
	if err != nil {
		t.Fatalf("create first scope: %v", err)
	}
	second, err := s.CreateResearchScope(ctx, ResearchScope{Name: "Second", Enabled: true, HostPatterns: []string{"api.target.test"}, URLPatterns: []string{"/scoped"}, MethodPatterns: []string{"GET"}})
	if err != nil {
		t.Fatalf("create second scope: %v", err)
	}
	time.Sleep(time.Millisecond)
	second.Description = "newer"
	second, err = s.UpdateResearchScope(ctx, second)
	if err != nil {
		t.Fatalf("update second scope: %v", err)
	}

	for _, tc := range []struct {
		name   string
		method string
		url    string
		host   string
		want   string
	}{
		{"newest tie wins", "GET", "https://api.target.test/scoped/users", "api.target.test", second.ID},
		{"wildcard subdomain", "GET", "https://cdn.target.test/scoped/users", "cdn.target.test", first.ID},
		{"wildcard excludes apex", "GET", "https://target.test/scoped/users", "target.test", ""},
		{"method mismatch", "POST", "https://api.target.test/scoped/users", "api.target.test", ""},
		{"url mismatch", "GET", "https://api.target.test/home", "api.target.test", ""},
		{"disabled ignored", "GET", "https://target.test/", "target.test", ""},
	} {
		got, err := s.MatchResearchScope(ctx, tc.method, tc.url, tc.host)
		if err != nil {
			t.Fatalf("%s match: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s got %q want %q (disabled id %q)", tc.name, got, tc.want, disabled.ID)
		}
	}

	scopedID := seedScopedStoreTraffic(t, s, "https://api.target.test/scoped/users", "api.target.test", "GET")
	outID := seedScopedStoreTraffic(t, s, "https://other.test/", "other.test", "GET")
	flows, err := s.ListTrafficScoped(ctx, 10, second.ID, false)
	if err != nil {
		t.Fatalf("list scoped traffic: %v", err)
	}
	if len(flows) != 1 || flows[0].ID != scopedID || flows[0].ScopeID != second.ID {
		t.Fatalf("unexpected scoped flows: %+v", flows)
	}
	flows, err = s.ListTrafficScoped(ctx, 10, "__out_of_scope__", false)
	if err != nil {
		t.Fatalf("list out of scope traffic: %v", err)
	}
	if len(flows) != 1 || flows[0].ID != outID {
		t.Fatalf("unexpected out-of-scope flows: %+v", flows)
	}
}

func TestConcurrentTrafficRecordingDoesNotReturnBusy(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := newStoreID()
			errs <- s.RecordEvent(ctx, events.Event{
				Topic:     events.TopicTrafficRequestStarted,
				RequestID: id,
				Time:      time.Now().UTC().Add(time.Duration(i) * time.Millisecond),
				Payload: map[string]any{
					"method": "GET",
					"url":    "https://busy.test/path",
					"host":   "busy.test",
					"request_headers": map[string]any{
						"X-Test": []string{"yes"},
					},
				},
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("record concurrent traffic: %v", err)
		}
	}
	flows, err := s.ListTraffic(ctx, 200)
	if err != nil {
		t.Fatalf("list traffic: %v", err)
	}
	if len(flows) != 100 {
		t.Fatalf("expected 100 recorded flows, got %d", len(flows))
	}
}

func columnExists(t *testing.T, s *Store, table, column string) bool {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(), `PRAGMA table_info(`+table+`)`)
	if err != nil {
		t.Fatalf("table info %s: %v", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatalf("scan table info: %v", err)
		}
		if name == column {
			return true
		}
	}
	return false
}

func seedScopedStoreTraffic(t *testing.T, s *Store, rawURL, host, method string) string {
	t.Helper()
	id := newStoreID()
	if err := s.RecordEvent(context.Background(), events.Event{
		Topic:     events.TopicTrafficRequestStarted,
		RequestID: id,
		Time:      time.Now().UTC(),
		Payload: map[string]any{
			"method": method,
			"url":    rawURL,
			"host":   host,
		},
	}); err != nil {
		t.Fatalf("seed traffic: %v", err)
	}
	return id
}
