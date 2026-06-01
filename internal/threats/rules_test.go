package threats

import (
	"strings"
	"testing"

	cfgpkg "mitm-proxy/internal/config"
)

func TestEvaluateHeuristicsExtractsPhishingSignals(t *testing.T) {
	cfg := cfgpkg.ThreatScannerConfig{TrustedDomains: []string{"accounts.google.com"}}
	result := EvaluateHeuristics(phishingResponseInput(), cfg)
	if result.Score < 70 {
		t.Fatalf("expected high phishing score, got %d (%s)", result.Score, ScanSummary(result))
	}
	assertSignal(t, result, "html.external_credential_form")
	assertSignal(t, result, "html.brand_impersonation")
	assertSignal(t, result, "js.cookie_exfiltration")
}

func TestTrustedDomainSuppressesLowConfidenceSignals(t *testing.T) {
	cfg := cfgpkg.ThreatScannerConfig{TrustedDomains: []string{"example.test"}}
	result := EvaluateHeuristics(ScanInput{
		Method:     "GET",
		URL:        "https://example.test/login",
		Host:       "example.test",
		BodySample: []byte(`<form action="/login"><input type="password"></form>`),
	}, cfg)
	if result.Suppressed != true {
		t.Fatalf("expected trusted domain suppression, got %#v", result)
	}
	if result.RecommendedAction != ActionAllow {
		t.Fatalf("expected allow after suppression, got %s", result.RecommendedAction)
	}
}

func TestDownloadQuarantineSignal(t *testing.T) {
	result := EvaluateHeuristics(ScanInput{
		Target:      ScanResponse,
		Method:      "GET",
		URL:         "https://download.example/tool.exe",
		Host:        "download.example",
		ContentType: "application/octet-stream",
	}, cfgpkg.ThreatScannerConfig{})
	assertSignal(t, result, "download.executable")
	if result.RecommendedAction == ActionAllow {
		t.Fatalf("expected suspicious download to warn or block, got %#v", result)
	}
}

func TestEvidenceBundleRedactsAndIncludesExtractedFeatures(t *testing.T) {
	local := EvaluateHeuristics(phishingResponseInput(), cfgpkg.ThreatScannerConfig{})
	evidence := BuildEvidence(phishingResponseInput(), cfgpkg.ThreatScannerConfig{RedactBeforeAI: true, MaxAIBodyBytes: 4096}, local)
	if !evidence.Extracted.HTML.HasCredentialCollection {
		t.Fatalf("expected extracted credential collection")
	}
	if !evidence.Extracted.HTML.HasCookieExfiltration {
		t.Fatalf("expected extracted cookie exfiltration")
	}
	if strings.Contains(evidence.BodySample, "dev@example.com") {
		t.Fatalf("expected body sample to be redacted")
	}
}

func assertSignal(t *testing.T, result HeuristicResult, id string) {
	t.Helper()
	for _, signal := range result.Signals {
		if signal.ID == id {
			return
		}
	}
	t.Fatalf("expected signal %s in %#v", id, result.Signals)
}
