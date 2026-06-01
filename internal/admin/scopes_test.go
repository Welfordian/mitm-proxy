package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"mitm-proxy/internal/store"
)

func TestScopesAPIAndReadOnlyToken(t *testing.T) {
	st := openAdminTestStore(t)
	s := newTestServer(st)

	data := postJSONForTest(t, s, "/api/scopes", map[string]any{
		"name":            "Example",
		"description":     "research target",
		"enabled":         true,
		"host_patterns":   []string{"example.test"},
		"url_patterns":    []string{"/api"},
		"method_patterns": []string{"POST"},
	})
	var scope store.ResearchScope
	if err := json.Unmarshal(data, &scope); err != nil {
		t.Fatalf("decode scope: %v", err)
	}
	if scope.ID == "" || !scope.Enabled || scope.MethodPatterns[0] != "POST" {
		t.Fatalf("unexpected scope: %+v", scope)
	}

	scope.Description = "updated"
	putJSONForTest(t, s, "/api/scopes/"+scope.ID, scope)
	gotData := getForTest(t, s, "/api/scopes/"+scope.ID)
	var got store.ResearchScope
	if err := json.Unmarshal(gotData, &got); err != nil {
		t.Fatalf("decode fetched scope: %v", err)
	}
	if got.Description != "updated" {
		t.Fatalf("scope was not updated: %+v", got)
	}

	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, "/api/scopes", map[string]any{"name": "Denied", "enabled": true}},
		{http.MethodPut, "/api/scopes/" + scope.ID, scope},
		{http.MethodDelete, "/api/scopes/" + scope.ID, nil},
	} {
		reqBody, _ := json.Marshal(tc.body)
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(reqBody))
		req.Header.Set("Authorization", "Bearer read-token")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s with read token got %d", tc.method, tc.path, rr.Code)
		}
	}
}

func TestScopedTrafficRepeaterFiltersAndAssignments(t *testing.T) {
	st := openAdminTestStore(t)
	s := newTestServer(st)
	scopeData := postJSONForTest(t, s, "/api/scopes", map[string]any{
		"name":            "Example",
		"enabled":         true,
		"host_patterns":   []string{"example.test"},
		"url_patterns":    []string{"/scoped"},
		"method_patterns": []string{"POST"},
	})
	var scope store.ResearchScope
	if err := json.Unmarshal(scopeData, &scope); err != nil {
		t.Fatalf("decode scope: %v", err)
	}

	scopedFlowID := seedTrafficFlowWithURL(t, st, "https://example.test/scoped", "body=1")
	outFlowID := seedTrafficFlowWithURL(t, st, "https://outside.test/path", "")

	var scopedFlows []store.TrafficFlow
	if err := json.Unmarshal(getForTest(t, s, "/api/traffic?scope_id="+scope.ID), &scopedFlows); err != nil {
		t.Fatalf("decode scoped traffic: %v", err)
	}
	if len(scopedFlows) != 1 || scopedFlows[0].ID != scopedFlowID || scopedFlows[0].ScopeID != scope.ID {
		t.Fatalf("unexpected scoped traffic: %+v", scopedFlows)
	}
	var outFlows []store.TrafficFlow
	if err := json.Unmarshal(getForTest(t, s, "/api/traffic?scope_id=__out_of_scope__"), &outFlows); err != nil {
		t.Fatalf("decode out traffic: %v", err)
	}
	if len(outFlows) != 1 || outFlows[0].ID != outFlowID {
		t.Fatalf("unexpected out-of-scope traffic: %+v", outFlows)
	}

	cloneData := postJSONForTest(t, s, "/api/repeater/cases", map[string]any{"source_flow_id": scopedFlowID})
	var cloned store.RepeaterCase
	if err := json.Unmarshal(cloneData, &cloned); err != nil {
		t.Fatalf("decode cloned case: %v", err)
	}
	if cloned.ScopeID != scope.ID {
		t.Fatalf("expected cloned case to inherit scope %q, got %+v", scope.ID, cloned)
	}

	manualData := postJSONForTest(t, s, "/api/repeater/cases", map[string]any{
		"name":       "manual",
		"method":     "GET",
		"url":        "https://outside.test/",
		"headers":    map[string][]string{},
		"timeout_ms": 30000,
	})
	var manual store.RepeaterCase
	if err := json.Unmarshal(manualData, &manual); err != nil {
		t.Fatalf("decode manual case: %v", err)
	}
	postForTest(t, s, "/api/scopes/"+scope.ID+"/assign/repeater/"+manual.ID, "admin-token")
	storedManual, _, err := st.GetRepeaterCase(context.Background(), manual.ID)
	if err != nil {
		t.Fatalf("get assigned case: %v", err)
	}
	if storedManual.ScopeID != scope.ID {
		t.Fatalf("expected assigned repeater scope %q, got %+v", scope.ID, storedManual)
	}

	postForTest(t, s, "/api/scopes/"+scope.ID+"/assign/traffic/"+outFlowID, "admin-token")
	storedFlow, _, err := st.GetTraffic(context.Background(), outFlowID)
	if err != nil {
		t.Fatalf("get assigned flow: %v", err)
	}
	if storedFlow.ScopeID != scope.ID {
		t.Fatalf("expected assigned traffic scope %q, got %+v", scope.ID, storedFlow)
	}

	var scopedCases []store.RepeaterCase
	if err := json.Unmarshal(getForTest(t, s, "/api/repeater/cases?scope_id="+scope.ID), &scopedCases); err != nil {
		t.Fatalf("decode scoped cases: %v", err)
	}
	if len(scopedCases) != 2 {
		t.Fatalf("expected two scoped cases, got %+v", scopedCases)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/scopes/"+scope.ID+"/assign/traffic/"+scopedFlowID, nil)
	req.Header.Set("Authorization", "Bearer read-token")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("read token should not assign scope, got %d", rr.Code)
	}
}

func getForTest(t *testing.T, s *Server, path string) []byte {
	t.Helper()
	return getRecorderForTest(t, s, path).Body.Bytes()
}

func getRecorderForTest(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("GET %s got %d: %s", path, rr.Code, rr.Body.String())
	}
	return rr
}
