package threats

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	cfgpkg "mitm-proxy/internal/config"
)

type AIClient interface {
	Classify(ctx context.Context, cfg cfgpkg.ThreatScannerConfig, input ScanInput, evidence EvidenceBundle) (ThreatVerdict, string, error)
}

type OpenAIClient struct {
	httpClient *http.Client
}

func NewOpenAIClient() *OpenAIClient {
	return &OpenAIClient{httpClient: &http.Client{}}
}

func (c *OpenAIClient) Classify(ctx context.Context, cfg cfgpkg.ThreatScannerConfig, input ScanInput, evidence EvidenceBundle) (ThreatVerdict, string, error) {
	keyEnv := cfg.OpenAIAPIKeyEnv
	if keyEnv == "" {
		keyEnv = "OPENAI_API_KEY"
	}
	apiKey := os.Getenv(keyEnv)
	if apiKey == "" {
		return ThreatVerdict{}, "", fmt.Errorf("OpenAI API key environment variable %s is not configured", keyEnv)
	}

	timeout := time.Duration(cfg.AITimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 750 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	prompt := buildPrompt(input, evidence)
	reqBody := map[string]any{
		"model": cfg.Model,
		"input": []map[string]string{
			{
				"role":    "system",
				"content": "You are a network threat classifier for a defensive MITM proxy. Decide whether the provided HTTP request or response should be allowed, warned, blocked, or quarantined. Block only when the evidence shows a real threat, not merely because local heuristics are suspicious. Detect phishing, malware delivery, credential theft, command-and-control, exploit payloads, suspicious script injection, data exfiltration, scam or impersonation pages. Return JSON only.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0,
		"text": map[string]any{
			"format": map[string]any{
				"type": "json_schema",
				"name": "threat_verdict",
				"schema": map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"required":             []string{"threat", "confidence", "category", "reason", "action", "signals", "confirmed_signals", "disputed_signals"},
					"properties": map[string]any{
						"threat":            map[string]any{"type": "boolean"},
						"confidence":        map[string]any{"type": "number"},
						"category":          map[string]any{"type": "string"},
						"reason":            map[string]any{"type": "string"},
						"action":            map[string]any{"type": "string", "enum": []string{ActionAllow, ActionWarn, ActionBlock, ActionQuarantine}},
						"signals":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						"confirmed_signals": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						"disputed_signals":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					},
				},
			},
		},
	}

	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return ThreatVerdict{}, cfg.Model, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.openai.com/v1/responses", bytes.NewReader(encoded))
	if err != nil {
		return ThreatVerdict{}, cfg.Model, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ThreatVerdict{}, cfg.Model, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ThreatVerdict{}, cfg.Model, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ThreatVerdict{}, cfg.Model, fmt.Errorf("openai responses api status %d: %s", resp.StatusCode, string(data))
	}

	verdict, err := parseOpenAIResponse(data)
	if err != nil {
		return ThreatVerdict{}, cfg.Model, err
	}
	normalizeVerdict(&verdict, cfg)
	return verdict, cfg.Model, nil
}

func buildPrompt(input ScanInput, evidence EvidenceBundle) string {
	payload, _ := json.MarshalIndent(map[string]any{
		"target":   input.Target,
		"evidence": evidence,
	}, "", "  ")
	return "Analyze this HTTP traffic sample and determine if it is truly malicious.\n\nUse all available evidence: URL, host, method, status, content type, redacted headers, response/request body sample, form actions, scripts, redirects, credential collection, exfiltration behavior, local rule signals, quarantine indicators, threat-intel hits, and brand impersonation.\n\nReturn block or quarantine only if the evidence confirms content should be prevented from reaching the user or upstream service. If local heuristics are suspicious but evidence is insufficient, return warn or allow and list disputed_signals.\n\nEvidence bundle JSON:\n" + string(payload)
}

func BuildPromptForTest(input ScanInput, evidence EvidenceBundle) string {
	return buildPrompt(input, evidence)
}

func parseOpenAIResponse(data []byte) (ThreatVerdict, error) {
	var raw struct {
		OutputText string `json:"output_text"`
		Output     []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return ThreatVerdict{}, err
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
		return ThreatVerdict{}, fmt.Errorf("openai response did not include output text")
	}

	var verdict ThreatVerdict
	if err := json.Unmarshal([]byte(text), &verdict); err != nil {
		return ThreatVerdict{}, err
	}
	return verdict, nil
}
