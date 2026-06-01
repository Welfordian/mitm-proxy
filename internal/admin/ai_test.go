package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/copilot"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/store"
)

type fakeCopilotClient struct {
	called   int
	evidence any
}

func (f *fakeCopilotClient) Generate(ctx context.Context, cfg cfgpkg.AICopilotConfig, kind string, evidence any) (copilot.Result, error) {
	f.called++
	f.evidence = evidence
	content := json.RawMessage(`{"summary":"AI summary","interesting_observations":["review headers"],"risk_notes":[],"recommended_manual_review":["check auth assumptions"]}`)
	if kind == copilot.KindTestSuggestions {
		content = json.RawMessage(`{"summary":"AI suggestions","safe_manual_tests":["vary an allowed parameter"],"parameters_to_review":["id"],"headers_to_review":["accept"],"scope_warning":""}`)
	}
	if kind == copilot.KindRunComparison {
		content = json.RawMessage(`{"summary":"AI comparison","meaningful_differences":["status changed"],"possible_causes":["server state"],"next_manual_checks":["confirm reproducibility"]}`)
	}
	return copilot.Result{Kind: kind, Title: "AI result", Summary: "AI summary", Content: content, Model: "fake-model", PromptHash: "fake-hash"}, nil
}

func TestAITrafficExplainRedactsAndStoresNote(t *testing.T) {
	st := openAdminTestStore(t)
	flowID := seedSensitiveTrafficFlow(t, st)
	fake := &fakeCopilotClient{}
	s := newAITestServer(st, fake)

	data := postForTest(t, s, "/api/ai/traffic/"+flowID+"/explain", "admin-token")
	var note store.AINote
	if err := json.Unmarshal(data, &note); err != nil {
		t.Fatalf("decode note: %v", err)
	}
	if note.Kind != copilot.KindExplanation || note.TargetType != "traffic" || note.TargetID != flowID || note.Model != "fake-model" {
		t.Fatalf("unexpected note: %+v", note)
	}
	if fake.called != 1 {
		t.Fatalf("expected fake copilot to be called once, got %d", fake.called)
	}
	evidence, _ := json.Marshal(fake.evidence)
	for _, secret := range []string{"Bearer secret-token", "session=secret", "dev@example.com", "eyJabc.def.ghi"} {
		if strings.Contains(string(evidence), secret) {
			t.Fatalf("AI evidence leaked %q: %s", secret, evidence)
		}
	}
	notes, err := st.ListAINotes(context.Background(), store.AINoteFilter{TargetType: "traffic", TargetID: flowID})
	if err != nil {
		t.Fatalf("list notes: %v", err)
	}
	if len(notes) != 1 || notes[0].ID != note.ID {
		t.Fatalf("expected stored note, got %+v", notes)
	}
}

func TestAIOutOfScopeSuggestionsDoNotCallModel(t *testing.T) {
	st := openAdminTestStore(t)
	flowID := seedSensitiveTrafficFlow(t, st)
	fake := &fakeCopilotClient{}
	s := newAITestServer(st, fake)

	data := postForTest(t, s, "/api/ai/traffic/"+flowID+"/suggest-tests", "admin-token")
	var note store.AINote
	if err := json.Unmarshal(data, &note); err != nil {
		t.Fatalf("decode note: %v", err)
	}
	if fake.called != 0 {
		t.Fatalf("out-of-scope suggestions should not call model, got %d calls", fake.called)
	}
	if !strings.Contains(string(note.Content), "Out-of-scope") {
		t.Fatalf("expected out-of-scope guidance, got %s", note.Content)
	}
}

func TestAIReadOnlyTokenCannotGenerateOrDelete(t *testing.T) {
	st := openAdminTestStore(t)
	flowID := seedSensitiveTrafficFlow(t, st)
	fake := &fakeCopilotClient{}
	s := newAITestServer(st, fake)

	req := httptest.NewRequest(http.MethodPost, "/api/ai/traffic/"+flowID+"/explain", nil)
	req.Header.Set("Authorization", "Bearer read-token")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("read token should not generate AI notes, got %d", rr.Code)
	}

	note, err := st.CreateAINote(context.Background(), store.AINote{TargetType: "traffic", TargetID: flowID, Content: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("create note: %v", err)
	}
	req = httptest.NewRequest(http.MethodDelete, "/api/ai/notes/"+note.ID, nil)
	req.Header.Set("Authorization", "Bearer read-token")
	rr = httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("read token should not delete AI notes, got %d", rr.Code)
	}
}

func TestAIRepeaterCompareRunsStoresNote(t *testing.T) {
	st := openAdminTestStore(t)
	c, err := st.CreateRepeaterCase(context.Background(), store.RepeaterCase{
		Name:      "case",
		Method:    "GET",
		URL:       "https://example.test/",
		Headers:   map[string][]string{},
		TimeoutMS: 30000,
		ScopeID:   "scope-1",
	})
	if err != nil {
		t.Fatalf("create case: %v", err)
	}
	for _, status := range []int{http.StatusOK, http.StatusCreated} {
		if _, err := st.AddRepeaterRun(context.Background(), store.RepeaterRun{
			CaseID:          c.ID,
			Status:          status,
			ResponseHeaders: map[string][]string{"Content-Type": []string{"text/plain"}},
			ResponseBody:    "body",
		}); err != nil {
			t.Fatalf("add run: %v", err)
		}
	}
	fake := &fakeCopilotClient{}
	s := newAITestServer(st, fake)
	data := postForTest(t, s, "/api/ai/repeater/cases/"+c.ID+"/compare-runs", "admin-token")
	var note store.AINote
	if err := json.Unmarshal(data, &note); err != nil {
		t.Fatalf("decode note: %v", err)
	}
	if note.Kind != copilot.KindRunComparison || note.TargetID != c.ID || fake.called != 1 {
		t.Fatalf("unexpected comparison note/calls: %+v calls=%d", note, fake.called)
	}
}

func newAITestServer(st *store.Store, client *fakeCopilotClient) *Server {
	cfg := &cfgpkg.Config{
		AICopilot: cfgpkg.AICopilotConfig{
			Enabled:         true,
			Provider:        "openai",
			Model:           "fake-model",
			TimeoutMS:       1000,
			MaxBodyBytes:    32768,
			RedactBeforeAI:  true,
			OpenAIAPIKeyEnv: "OPENAI_API_KEY",
		},
	}
	return New(Options{
		Token:         "admin-token",
		ReadToken:     "read-token",
		Store:         st,
		Config:        func() *cfgpkg.Config { return cfg },
		CopilotClient: client,
	})
}

func seedSensitiveTrafficFlow(t *testing.T, st *store.Store) string {
	t.Helper()
	id := "ai-flow"
	if err := st.RecordEvent(context.Background(), events.Event{
		Topic:     events.TopicTrafficRequestStarted,
		RequestID: id,
		Payload: map[string]any{
			"method": "POST",
			"url":    "https://example.test/login?email=dev@example.com",
			"host":   "example.test",
			"request_headers": map[string]any{
				"Authorization": []string{"Bearer secret-token"},
				"Cookie":        []string{"session=secret"},
				"Accept":        []string{"application/json"},
			},
		},
	}); err != nil {
		t.Fatalf("record start: %v", err)
	}
	if err := st.RecordEvent(context.Background(), events.Event{
		Topic:     events.TopicTrafficBodyCaptured,
		RequestID: id,
		Payload: map[string]any{
			"direction": "request",
			"body":      "email=dev@example.com&token=eyJabc.def.ghi",
		},
	}); err != nil {
		t.Fatalf("record body: %v", err)
	}
	if err := st.RecordEvent(context.Background(), events.Event{
		Topic:     events.TopicTrafficResponseCompleted,
		RequestID: id,
		Payload: map[string]any{
			"status":           200,
			"response_headers": map[string]any{"Set-Cookie": []string{"server=secret"}},
		},
	}); err != nil {
		t.Fatalf("record completion: %v", err)
	}
	return id
}

func TestAINotesReadOnlyCanList(t *testing.T) {
	st := openAdminTestStore(t)
	if _, err := st.CreateAINote(context.Background(), store.AINote{TargetType: "traffic", TargetID: "flow", Content: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("create note: %v", err)
	}
	s := newAITestServer(st, &fakeCopilotClient{})
	req := httptest.NewRequest(http.MethodGet, "/api/ai/notes", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer read-token")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("read token should list notes, got %d: %s", rr.Code, rr.Body.String())
	}
}
