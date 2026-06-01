package copilot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cfgpkg "mitm-proxy/internal/config"
)

func TestOpenAIClientParsesStructuredResponse(t *testing.T) {
	t.Setenv("COPILOT_TEST_KEY", "test-key")
	var sawPrompt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("unexpected auth header: %q", r.Header.Get("Authorization"))
		}
		var payload struct {
			Input []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		sawPrompt = payload.Input[len(payload.Input)-1].Content
		_, _ = w.Write([]byte(`{"output_text":"{\"summary\":\"ok\",\"interesting_observations\":[\"one\"],\"risk_notes\":[],\"recommended_manual_review\":[]}"}`))
	}))
	defer server.Close()

	client := &OpenAIClient{HTTPClient: server.Client(), Endpoint: server.URL}
	result, err := client.Generate(context.Background(), cfgpkg.AICopilotConfig{
		Provider:        "openai",
		Model:           "gpt-test",
		TimeoutMS:       1000,
		OpenAIAPIKeyEnv: "COPILOT_TEST_KEY",
	}, KindExplanation, map[string]any{"url": "https://example.test/"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if result.Summary != "ok" || result.Model != "gpt-test" || result.PromptHash == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !strings.Contains(sawPrompt, "https://example.test/") {
		t.Fatalf("prompt did not include context: %s", sawPrompt)
	}
}

func TestOpenAIClientReportsTimeoutClearly(t *testing.T) {
	t.Setenv("COPILOT_TEST_KEY", "test-key")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer server.Close()

	client := &OpenAIClient{HTTPClient: server.Client(), Endpoint: server.URL}
	_, err := client.Generate(context.Background(), cfgpkg.AICopilotConfig{
		Provider:        "openai",
		Model:           "gpt-test",
		TimeoutMS:       1,
		OpenAIAPIKeyEnv: "COPILOT_TEST_KEY",
	}, KindExplanation, map[string]any{"url": "https://example.test/"})
	if err == nil || !strings.Contains(err.Error(), "timed out after 1 ms") {
		t.Fatalf("expected clear timeout error, got %v", err)
	}
}

func TestOpenAIClientErrors(t *testing.T) {
	client := &OpenAIClient{Endpoint: "http://127.0.0.1:1"}
	if _, err := client.Generate(context.Background(), cfgpkg.AICopilotConfig{Provider: "openai", OpenAIAPIKeyEnv: "MISSING_COPILOT_KEY"}, KindExplanation, nil); err == nil {
		t.Fatal("expected missing API key error")
	}
	if _, err := client.Generate(context.Background(), cfgpkg.AICopilotConfig{Provider: "openai", OpenAIAPIKeyEnv: "sk-test-secret"}, KindExplanation, nil); err == nil || !strings.Contains(err.Error(), "not the API key value") {
		t.Fatalf("expected API key value configuration error, got %v", err)
	}

	t.Setenv("COPILOT_TEST_KEY", "test-key")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusBadGateway)
	}))
	defer server.Close()
	client = &OpenAIClient{HTTPClient: server.Client(), Endpoint: server.URL}
	if _, err := client.Generate(context.Background(), cfgpkg.AICopilotConfig{Provider: "openai", OpenAIAPIKeyEnv: "COPILOT_TEST_KEY"}, KindExplanation, nil); err == nil {
		t.Fatal("expected non-2xx error")
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"output_text":"not json"}`))
	}))
	defer badJSON.Close()
	client = &OpenAIClient{HTTPClient: badJSON.Client(), Endpoint: badJSON.URL}
	if _, err := client.Generate(context.Background(), cfgpkg.AICopilotConfig{Provider: "openai", OpenAIAPIKeyEnv: "COPILOT_TEST_KEY"}, KindExplanation, nil); err == nil {
		t.Fatal("expected malformed JSON error")
	}
}
