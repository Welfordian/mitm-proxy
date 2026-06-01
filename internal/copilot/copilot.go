package copilot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	cfgpkg "mitm-proxy/internal/config"
)

const defaultEndpoint = "https://api.openai.com/v1/responses"

const (
	KindExplanation     = "explanation"
	KindTestSuggestions = "test_suggestions"
	KindRunComparison   = "run_comparison"
)

type Client interface {
	Generate(ctx context.Context, cfg cfgpkg.AICopilotConfig, kind string, context any) (Result, error)
}

type Result struct {
	Kind       string          `json:"kind"`
	Title      string          `json:"title"`
	Summary    string          `json:"summary"`
	Content    json.RawMessage `json:"content_json"`
	Model      string          `json:"model"`
	PromptHash string          `json:"prompt_hash"`
}

type OpenAIClient struct {
	HTTPClient *http.Client
	Endpoint   string
}

func NewOpenAIClient() *OpenAIClient {
	return &OpenAIClient{HTTPClient: &http.Client{}, Endpoint: defaultEndpoint}
}

func (c *OpenAIClient) Generate(ctx context.Context, cfg cfgpkg.AICopilotConfig, kind string, evidence any) (Result, error) {
	if cfg.Provider != "" && cfg.Provider != "openai" {
		return Result{}, fmt.Errorf("unsupported AI copilot provider %q", cfg.Provider)
	}
	keyEnv := cfg.OpenAIAPIKeyEnv
	if keyEnv == "" {
		keyEnv = "OPENAI_API_KEY"
	}
	if looksLikeAPIKey(keyEnv) {
		return Result{}, fmt.Errorf("openai_api_key_env must be the name of an environment variable such as OPENAI_API_KEY, not the API key value")
	}
	apiKey := os.Getenv(keyEnv)
	if apiKey == "" {
		return Result{}, fmt.Errorf("OpenAI API key environment variable %s is not configured", keyEnv)
	}
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		model = "gpt-5.4-nano"
	}
	timeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	prompt, err := BuildPrompt(kind, evidence)
	if err != nil {
		return Result{}, err
	}
	promptHash := hashPrompt(prompt)
	schema, err := schemaForKind(kind)
	if err != nil {
		return Result{}, err
	}
	reqBody := map[string]any{
		"model": model,
		"input": []map[string]string{
			{
				"role": "system",
				"content": "You are an AI research copilot for an authorized security researcher using a local MITM proxy dashboard. " +
					"Explain observations and suggest careful manual review steps only. Never claim to execute actions. " +
					"If context is out of scope, do not suggest active tests, payloads, replay, fuzzing, bypasses, or exploitation. Return JSON only.",
			},
			{"role": "user", "content": prompt},
		},
		"temperature": 0,
		"text": map[string]any{
			"format": map[string]any{
				"type":   "json_schema",
				"name":   schemaName(kind),
				"schema": schema,
			},
		},
	}
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return Result{}, err
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, fmt.Errorf("AI copilot request timed out after %d ms; increase ai_copilot.timeout_ms or try again: %w", cfg.TimeoutMS, err)
		}
		return Result{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Result{}, fmt.Errorf("openai responses api status %d: %s", resp.StatusCode, string(data))
	}
	content, err := parseOpenAIResponse(data)
	if err != nil {
		return Result{}, err
	}
	summary := summaryFromContent(content)
	return Result{
		Kind:       kind,
		Title:      titleForKind(kind),
		Summary:    summary,
		Content:    content,
		Model:      model,
		PromptHash: promptHash,
	}, nil
}

func looksLikeAPIKey(value string) bool {
	trimmed := strings.TrimSpace(value)
	return strings.HasPrefix(trimmed, "sk-") || strings.HasPrefix(trimmed, "sk_")
}

func BuildPrompt(kind string, evidence any) (string, error) {
	payload, err := json.MarshalIndent(map[string]any{
		"task":     kind,
		"evidence": evidence,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	switch kind {
	case KindExplanation:
		return "Explain the captured HTTP traffic for a security researcher. Focus on what is observable, what might deserve manual review, and what evidence is missing.\n\nContext JSON:\n" + string(payload), nil
	case KindTestSuggestions:
		return "Suggest safe, manual next tests for this request. If out_of_scope is true, provide passive review guidance only and no active testing steps.\n\nContext JSON:\n" + string(payload), nil
	case KindRunComparison:
		return "Compare these Repeater runs and summarize meaningful response differences, plausible causes, and careful manual checks.\n\nContext JSON:\n" + string(payload), nil
	default:
		return "", fmt.Errorf("unknown copilot task %q", kind)
	}
}

func hashPrompt(prompt string) string {
	sum := sha256.Sum256([]byte(prompt))
	return hex.EncodeToString(sum[:])
}

func parseOpenAIResponse(data []byte) (json.RawMessage, error) {
	var raw struct {
		OutputText string `json:"output_text"`
		Output     []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	text := strings.TrimSpace(raw.OutputText)
	if text == "" {
		for _, out := range raw.Output {
			for _, content := range out.Content {
				if strings.TrimSpace(content.Text) != "" {
					text = strings.TrimSpace(content.Text)
					break
				}
			}
			if text != "" {
				break
			}
		}
	}
	if text == "" {
		return nil, fmt.Errorf("openai response did not include output text")
	}
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		return nil, err
	}
	normalized, err := json.Marshal(decoded)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(normalized), nil
}

func summaryFromContent(content json.RawMessage) string {
	var payload map[string]any
	if err := json.Unmarshal(content, &payload); err != nil {
		return ""
	}
	if summary, ok := payload["summary"].(string); ok {
		return strings.TrimSpace(summary)
	}
	return ""
}

func titleForKind(kind string) string {
	switch kind {
	case KindExplanation:
		return "AI explanation"
	case KindTestSuggestions:
		return "AI test suggestions"
	case KindRunComparison:
		return "AI run comparison"
	default:
		return "AI research note"
	}
}

func schemaName(kind string) string {
	return strings.ReplaceAll(kind, "-", "_")
}

func schemaForKind(kind string) (map[string]any, error) {
	stringArray := map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	properties := map[string]any{"summary": map[string]any{"type": "string"}}
	required := []string{"summary"}
	switch kind {
	case KindExplanation:
		properties["interesting_observations"] = stringArray
		properties["risk_notes"] = stringArray
		properties["recommended_manual_review"] = stringArray
		required = append(required, "interesting_observations", "risk_notes", "recommended_manual_review")
	case KindTestSuggestions:
		properties["safe_manual_tests"] = stringArray
		properties["parameters_to_review"] = stringArray
		properties["headers_to_review"] = stringArray
		properties["scope_warning"] = map[string]any{"type": "string"}
		required = append(required, "safe_manual_tests", "parameters_to_review", "headers_to_review", "scope_warning")
	case KindRunComparison:
		properties["meaningful_differences"] = stringArray
		properties["possible_causes"] = stringArray
		properties["next_manual_checks"] = stringArray
		required = append(required, "meaningful_differences", "possible_causes", "next_manual_checks")
	default:
		return nil, fmt.Errorf("unknown copilot task %q", kind)
	}
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             required,
		"properties":           properties,
	}, nil
}
