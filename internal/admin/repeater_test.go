package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/store"
)

var adminTestFlowSeq atomic.Int64

func TestRepeaterCloneFromTrafficAndSend(t *testing.T) {
	st := openAdminTestStore(t)
	flowID := seedTrafficFlow(t, st, "body=1")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Probe"); got != "yes" {
			t.Fatalf("missing cloned header: %q", got)
		}
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		if body.String() != "body=1" {
			t.Fatalf("missing cloned body: %q", body.String())
		}
		w.Header().Set("X-Result", "ok")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer upstream.Close()

	s := newTestServer(st)
	clone := postJSONForTest(t, s, "/api/repeater/cases", map[string]any{"source_flow_id": flowID})
	var c store.RepeaterCase
	if err := json.Unmarshal(clone, &c); err != nil {
		t.Fatalf("decode clone: %v", err)
	}
	if c.Body != "body=1" || c.Headers["X-Probe"][0] != "yes" {
		t.Fatalf("clone did not preserve captured request: %+v", c)
	}
	c.URL = upstream.URL
	putJSONForTest(t, s, "/api/repeater/cases/"+c.ID, c)
	runData := postForTest(t, s, "/api/repeater/cases/"+c.ID+"/send", "admin-token")
	var run store.RepeaterRun
	if err := json.Unmarshal(runData, &run); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if run.Status != http.StatusCreated || run.ResponseBody != "created" || run.ResponseHeaders["X-Result"][0] != "ok" {
		t.Fatalf("unexpected run: %+v", run)
	}
}

func TestRepeaterCloneWithoutCapturedBodyLeavesBodyEmpty(t *testing.T) {
	st := openAdminTestStore(t)
	flowID := seedTrafficFlow(t, st, "")
	s := newTestServer(st)
	data := postJSONForTest(t, s, "/api/repeater/cases", map[string]any{"source_flow_id": flowID})
	var c store.RepeaterCase
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("decode clone: %v", err)
	}
	if c.Body != "" {
		t.Fatalf("expected empty body, got %q", c.Body)
	}
}

func TestRepeaterValidationAndReadOnlyToken(t *testing.T) {
	st := openAdminTestStore(t)
	s := newTestServer(st)
	for _, body := range []map[string]any{
		{"method": "", "url": "http://example.com/", "headers": map[string][]string{}, "timeout_ms": 30000},
		{"method": "CONNECT", "url": "http://example.com/", "headers": map[string][]string{}, "timeout_ms": 30000},
		{"method": "GET", "url": "://bad", "headers": map[string][]string{}, "timeout_ms": 30000},
		{"method": "GET", "url": "http://example.com/", "headers": map[string][]string{}, "timeout_ms": 1},
	} {
		reqBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/repeater/cases", bytes.NewReader(reqBody))
		req.Header.Set("Authorization", "Bearer admin-token")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		s.server.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected bad request for %+v, got %d", body, rr.Code)
		}
	}

	reqBody, _ := json.Marshal(map[string]any{"method": "GET", "url": "http://example.com/", "headers": map[string][]string{}, "timeout_ms": 30000})
	req := httptest.NewRequest(http.MethodPost, "/api/repeater/cases", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer read-token")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("read token should not create repeater case, got %d", rr.Code)
	}
}

func TestLegacyTrafficReplayStillWorks(t *testing.T) {
	st := openAdminTestStore(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("legacy"))
	}))
	defer upstream.Close()
	flowID := seedTrafficFlowWithURL(t, st, upstream.URL, "")
	s := newTestServer(st)
	data := postForTest(t, s, "/api/traffic/"+flowID+"/replay", "admin-token")
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode replay: %v", err)
	}
	if int(payload["status"].(float64)) != http.StatusAccepted || strings.TrimSpace(payload["body"].(string)) != "legacy" {
		t.Fatalf("unexpected replay payload: %+v", payload)
	}
}

func TestTrafficListSupportsLimitAndOffset(t *testing.T) {
	st := openAdminTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Minute)
	for i := 0; i < 25; i++ {
		id := fmt.Sprintf("page-flow-%02d", i)
		host := "page.test"
		if i%2 == 0 {
			host = "match.test"
		}
		if err := st.RecordEvent(ctx, events.Event{
			Topic:     events.TopicTrafficRequestStarted,
			RequestID: id,
			Time:      base.Add(time.Duration(i) * time.Second),
			Payload: map[string]any{
				"method": "GET",
				"url":    fmt.Sprintf("https://%s/%02d", host, i),
				"host":   host,
			},
		}); err != nil {
			t.Fatalf("seed flow %d: %v", i, err)
		}
	}

	s := newTestServer(st)
	var first []store.TrafficFlow
	if err := json.Unmarshal(getForTest(t, s, "/api/traffic?limit=10&offset=0"), &first); err != nil {
		t.Fatalf("decode first page: %v", err)
	}
	var second []store.TrafficFlow
	if err := json.Unmarshal(getForTest(t, s, "/api/traffic?limit=10&offset=10"), &second); err != nil {
		t.Fatalf("decode second page: %v", err)
	}
	if len(first) != 10 || len(second) != 10 {
		t.Fatalf("expected 10 rows per page, got first=%d second=%d", len(first), len(second))
	}
	seen := map[string]bool{}
	for _, flow := range first {
		seen[flow.ID] = true
	}
	for _, flow := range second {
		if seen[flow.ID] {
			t.Fatalf("pagination returned duplicate flow %q", flow.ID)
		}
	}

	var matches []store.TrafficFlow
	if err := json.Unmarshal(getForTest(t, s, "/api/traffic?limit=10&offset=0&q=match.test"), &matches); err != nil {
		t.Fatalf("decode search page: %v", err)
	}
	if len(matches) != 10 {
		t.Fatalf("expected first search page to return 10 matches, got %d", len(matches))
	}
	for _, flow := range matches {
		if flow.Host != "match.test" {
			t.Fatalf("search returned non-matching flow: %+v", flow)
		}
	}

	var nextMatches []store.TrafficFlow
	if err := json.Unmarshal(getForTest(t, s, "/api/traffic?limit=10&offset=10&q=match.test"), &nextMatches); err != nil {
		t.Fatalf("decode second search page: %v", err)
	}
	if len(nextMatches) != 3 {
		t.Fatalf("expected second search page to return remaining 3 matches, got %d", len(nextMatches))
	}
}

func TestTrafficExportsDownloadAsFiles(t *testing.T) {
	st := openAdminTestStore(t)
	flowID := seedTrafficFlow(t, st, "body=1")
	s := newTestServer(st)

	jsonRR := getRecorderForTest(t, s, "/api/traffic/"+flowID+"/export")
	if disposition := jsonRR.Header().Get("Content-Disposition"); !strings.Contains(disposition, "attachment") || !strings.Contains(disposition, ".json") {
		t.Fatalf("expected JSON attachment disposition, got %q", disposition)
	}
	var detail store.TrafficDetail
	if err := json.Unmarshal(jsonRR.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode detail export: %v", err)
	}
	if detail.ID != flowID || detail.RequestBody != "body=1" {
		t.Fatalf("unexpected detail export: %+v", detail)
	}

	harRR := getRecorderForTest(t, s, "/api/traffic/"+flowID+"/export?format=har")
	if disposition := harRR.Header().Get("Content-Disposition"); !strings.Contains(disposition, "attachment") || !strings.Contains(disposition, ".har") {
		t.Fatalf("expected HAR attachment disposition, got %q", disposition)
	}
	var har map[string]any
	if err := json.Unmarshal(harRR.Body.Bytes(), &har); err != nil {
		t.Fatalf("decode har export: %v", err)
	}
	entries := har["log"].(map[string]any)["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("expected one HAR entry, got %d", len(entries))
	}
	request := entries[0].(map[string]any)["request"].(map[string]any)
	if request["method"] != "POST" || request["postData"].(map[string]any)["text"] != "body=1" {
		t.Fatalf("unexpected HAR request: %+v", request)
	}

	allRR := getRecorderForTest(t, s, "/api/traffic/export?format=har")
	if disposition := allRR.Header().Get("Content-Disposition"); !strings.Contains(disposition, "attachment") || !strings.Contains(disposition, "traffic.har") {
		t.Fatalf("expected all HAR attachment disposition, got %q", disposition)
	}
}

func newTestServer(st *store.Store) *Server {
	return New(Options{
		Token:     "admin-token",
		ReadToken: "read-token",
		Store:     st,
		Config:    func() *cfgpkg.Config { return &cfgpkg.Config{} },
	})
}

func openAdminTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/dashboard.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func seedTrafficFlow(t *testing.T, st *store.Store, body string) string {
	return seedTrafficFlowWithURL(t, st, "https://example.test/path", body)
}

func seedTrafficFlowWithURL(t *testing.T, st *store.Store, rawURL, body string) string {
	t.Helper()
	id := fmt.Sprintf("%s-%d", time.Now().Format("20060102150405.000000000"), adminTestFlowSeq.Add(1))
	ctx := context.Background()
	if err := st.RecordEvent(ctx, events.Event{
		Topic:     events.TopicTrafficRequestStarted,
		RequestID: id,
		Time:      time.Now().UTC(),
		Payload: map[string]any{
			"method": "POST",
			"url":    rawURL,
			"host":   "example.test",
			"request_headers": map[string]any{
				"X-Probe": []string{"yes"},
			},
		},
	}); err != nil {
		t.Fatalf("seed traffic: %v", err)
	}
	if body != "" {
		if err := st.RecordEvent(ctx, events.Event{
			Topic:     events.TopicTrafficBodyCaptured,
			RequestID: id,
			Time:      time.Now().UTC(),
			Payload: map[string]any{
				"direction": "request",
				"body":      body,
			},
		}); err != nil {
			t.Fatalf("seed body: %v", err)
		}
	}
	return id
}

func postJSONForTest(t *testing.T, s *Server, path string, body any) []byte {
	t.Helper()
	encoded, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("POST %s got %d: %s", path, rr.Code, rr.Body.String())
	}
	return rr.Body.Bytes()
}

func putJSONForTest(t *testing.T, s *Server, path string, body any) {
	t.Helper()
	encoded, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(encoded))
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("PUT %s got %d: %s", path, rr.Code, rr.Body.String())
	}
}

func postForTest(t *testing.T, s *Server, path, token string) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code < 200 || rr.Code >= 300 {
		t.Fatalf("POST %s got %d: %s", path, rr.Code, rr.Body.String())
	}
	return rr.Body.Bytes()
}
