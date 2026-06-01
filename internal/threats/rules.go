package threats

import (
	"fmt"
	"strings"
	"sync"
	"time"

	cfgpkg "mitm-proxy/internal/config"
)

const rulesVersion = "rules-v1"

type RuleDefinition struct {
	ID       string
	Name     string
	Category string
	Severity Severity
	Weight   int
	Source   string
}

type RuleRuntime struct {
	Definition             RuleDefinition
	Hits                   uint64
	FalsePositiveOverrides uint64
	LastTriggered          time.Time
}

var ruleDefinitions = []RuleDefinition{
	{ID: "url.ip_host", Name: "IP literal host", Category: "url", Severity: SeverityLow, Weight: 10, Source: "url_rules"},
	{ID: "url.private_target", Name: "Private network target", Category: "network", Severity: SeverityHigh, Weight: 40, Source: "network_rules"},
	{ID: "url.loopback_target", Name: "Loopback target", Category: "network", Severity: SeverityMedium, Weight: 20, Source: "network_rules"},
	{ID: "url.suspicious_tld", Name: "Suspicious top-level domain", Category: "url", Severity: SeverityMedium, Weight: 15, Source: "url_rules"},
	{ID: "url.credential_theme", Name: "Credential-themed URL", Category: "url", Severity: SeverityLow, Weight: 10, Source: "url_rules"},
	{ID: "url.external_redirect", Name: "External redirect parameter", Category: "url", Severity: SeverityMedium, Weight: 20, Source: "url_rules"},
	{ID: "url.high_entropy", Name: "High-entropy URL", Category: "url", Severity: SeverityLow, Weight: 10, Source: "url_rules"},
	{ID: "url.punycode_or_homoglyph", Name: "Punycode or homoglyph-like host", Category: "url", Severity: SeverityMedium, Weight: 20, Source: "url_rules"},
	{ID: "html.credential_form", Name: "Credential collection form", Category: "phishing", Severity: SeverityMedium, Weight: 30, Source: "html_rules"},
	{ID: "html.external_credential_form", Name: "External credential form action", Category: "phishing", Severity: SeverityHigh, Weight: 45, Source: "html_rules"},
	{ID: "html.brand_impersonation", Name: "Brand impersonation with credential collection", Category: "phishing", Severity: SeverityHigh, Weight: 40, Source: "html_rules"},
	{ID: "html.test_phishing_marker", Name: "Threat scanner phishing test marker", Category: "phishing", Severity: SeverityCritical, Weight: 70, Source: "html_rules"},
	{ID: "js.cookie_exfiltration", Name: "Client-side cookie exfiltration", Category: "exfiltration", Severity: SeverityCritical, Weight: 60, Source: "js_rules"},
	{ID: "js.storage_exfiltration", Name: "Client-side storage exfiltration", Category: "exfiltration", Severity: SeverityHigh, Weight: 50, Source: "js_rules"},
	{ID: "js.obfuscation", Name: "Obfuscated JavaScript", Category: "malware", Severity: SeverityMedium, Weight: 25, Source: "js_rules"},
	{ID: "js.dynamic_script", Name: "Dynamic script loading", Category: "malware", Severity: SeverityMedium, Weight: 20, Source: "js_rules"},
	{ID: "js.beacon_like", Name: "Beacon-like external endpoint", Category: "command_and_control", Severity: SeverityHigh, Weight: 40, Source: "js_rules"},
	{ID: "payload.command_injection", Name: "Command injection payload", Category: "exploit", Severity: SeverityCritical, Weight: 55, Source: "payload_rules"},
	{ID: "payload.ssrf", Name: "SSRF-looking payload", Category: "exploit", Severity: SeverityHigh, Weight: 45, Source: "payload_rules"},
	{ID: "payload.path_traversal", Name: "Path traversal payload", Category: "exploit", Severity: SeverityHigh, Weight: 40, Source: "payload_rules"},
	{ID: "payload.sql_injection", Name: "SQL injection payload", Category: "exploit", Severity: SeverityHigh, Weight: 45, Source: "payload_rules"},
	{ID: "payload.xss", Name: "Cross-site scripting payload", Category: "exploit", Severity: SeverityHigh, Weight: 40, Source: "payload_rules"},
	{ID: "payload.template_injection", Name: "Template injection payload", Category: "exploit", Severity: SeverityMedium, Weight: 30, Source: "payload_rules"},
	{ID: "payload.deserialization", Name: "Deserialization probe", Category: "exploit", Severity: SeverityHigh, Weight: 45, Source: "payload_rules"},
	{ID: "payload.encoded", Name: "Encoded or packed payload", Category: "evasion", Severity: SeverityMedium, Weight: 25, Source: "payload_rules"},
	{ID: "payload.payment_card", Name: "Payment-card-like data", Category: "exfiltration", Severity: SeverityMedium, Weight: 25, Source: "payload_rules"},
	{ID: "download.executable", Name: "Executable download", Category: "malware", Severity: SeverityHigh, Weight: 45, Source: "download_rules"},
	{ID: "download.archive", Name: "Archive download", Category: "malware", Severity: SeverityMedium, Weight: 25, Source: "download_rules"},
	{ID: "download.macro_document", Name: "Macro-capable document download", Category: "malware", Severity: SeverityHigh, Weight: 40, Source: "download_rules"},
	{ID: "download.unknown_binary", Name: "Unknown binary download", Category: "malware", Severity: SeverityMedium, Weight: 30, Source: "download_rules"},
	{ID: "intel.malicious_domain", Name: "Threat intelligence malicious domain", Category: "threat_intel", Severity: SeverityCritical, Weight: 70, Source: "intel_rules"},
	{ID: "intel.malicious_hash", Name: "Threat intelligence malicious hash", Category: "threat_intel", Severity: SeverityCritical, Weight: 80, Source: "intel_rules"},
}

var categoryCaps = map[string]int{
	"url":                 45,
	"network":             50,
	"phishing":            90,
	"exfiltration":        85,
	"malware":             80,
	"command_and_control": 70,
	"exploit":             90,
	"evasion":             35,
	"threat_intel":        95,
}

func EvaluateHeuristics(input ScanInput, cfg cfgpkg.ThreatScannerConfig) HeuristicResult {
	features := ExtractFeatures(input, cfg)
	signals := evaluateRules(input, features)
	result := scoreSignals(signals)
	if features.TrustedDomainHit && result.Score < 85 {
		result.Suppressed = true
		result.SuppressionReason = "trusted or allowlisted domain suppressed low-confidence local heuristics"
		result.Score = min(result.Score, 20)
		result.RecommendedAction = ActionAllow
		result.RequiresAIConfirmation = false
	}
	return result
}

func evaluateRules(input ScanInput, f ExtractedFeatures) []DetectionSignal {
	var signals []DetectionSignal
	add := func(id string, evidence map[string]string) {
		def, ok := ruleByID(id)
		if !ok {
			return
		}
		signals = append(signals, DetectionSignal{
			ID:         def.ID,
			Name:       def.Name,
			Category:   def.Category,
			Severity:   def.Severity,
			Confidence: severityConfidence(def.Severity),
			Weight:     def.Weight,
			Evidence:   evidence,
			Source:     def.Source,
		})
	}

	if f.URL.IsIPAddress {
		add("url.ip_host", map[string]string{"host": f.URL.Hostname})
	}
	if f.Network.PrivateNetworkTarget {
		add("url.private_target", map[string]string{"host": f.URL.Hostname})
	}
	if f.Network.LoopbackTarget {
		add("url.loopback_target", map[string]string{"host": f.URL.Hostname})
	}
	if f.URL.SuspiciousTLD {
		add("url.suspicious_tld", map[string]string{"host": f.URL.Hostname})
	}
	if f.URL.CredentialThemed {
		add("url.credential_theme", map[string]string{"path": f.URL.Path})
	}
	if len(f.URL.ExternalRedirectTargets) > 0 {
		add("url.external_redirect", map[string]string{"targets": strings.Join(f.URL.ExternalRedirectTargets, ",")})
	}
	if f.URL.Entropy >= 4.2 && len(f.URL.Hostname) > 16 {
		add("url.high_entropy", map[string]string{"entropy": fmt.Sprintf("%.2f", f.URL.Entropy)})
	}
	if f.URL.Punycode || f.URL.HomoglyphLike {
		add("url.punycode_or_homoglyph", map[string]string{"host": f.URL.Hostname})
	}
	if f.HTML.HasCredentialCollection {
		add("html.credential_form", map[string]string{"password_fields": fmt.Sprintf("%d", f.HTML.PasswordFields)})
	}
	if len(f.HTML.ExternalFormActions) > 0 {
		add("html.external_credential_form", map[string]string{"actions": strings.Join(f.HTML.ExternalFormActions, ",")})
	}
	if f.HTML.HasBrandImpersonation {
		add("html.brand_impersonation", map[string]string{"brands": strings.Join(f.HTML.BrandTerms, ",")})
	}
	if f.HTML.HasTestPhishingMarker {
		add("html.test_phishing_marker", nil)
	}
	if f.HTML.HasCookieExfiltration || f.JavaScript.ReadsCookies && len(f.JavaScript.NetworkSinks) > 0 {
		add("js.cookie_exfiltration", map[string]string{"sinks": strings.Join(f.JavaScript.NetworkSinks, ",")})
	}
	if f.HTML.HasStorageExfiltration || f.JavaScript.ReadsStorage && len(f.JavaScript.NetworkSinks) > 0 {
		add("js.storage_exfiltration", map[string]string{"sinks": strings.Join(f.JavaScript.NetworkSinks, ",")})
	}
	if f.HTML.HasObfuscatedJavaScript || len(f.JavaScript.ObfuscationMarkers) > 0 {
		add("js.obfuscation", map[string]string{"markers": strings.Join(f.JavaScript.ObfuscationMarkers, ",")})
	}
	if f.JavaScript.UsesDynamicScript || f.JavaScript.UsesDocumentWrite || f.JavaScript.UsesEval {
		add("js.dynamic_script", nil)
	}
	if len(f.JavaScript.BeaconLikeEndpoints) > 0 || f.Network.C2BeaconLike {
		add("js.beacon_like", map[string]string{"endpoints": strings.Join(f.JavaScript.BeaconLikeEndpoints, ",")})
	}
	if f.Payload.CommandInjection {
		add("payload.command_injection", nil)
	}
	if f.Payload.SSRF {
		add("payload.ssrf", nil)
	}
	if f.Payload.PathTraversal {
		add("payload.path_traversal", nil)
	}
	if f.Payload.SQLInjection {
		add("payload.sql_injection", nil)
	}
	if f.Payload.XSS {
		add("payload.xss", nil)
	}
	if f.Payload.TemplateInjection {
		add("payload.template_injection", nil)
	}
	if f.Payload.DeserializationProbe {
		add("payload.deserialization", nil)
	}
	if f.Payload.EncodedPayload {
		add("payload.encoded", nil)
	}
	if cardLikeRE.Match(input.BodySample) {
		add("payload.payment_card", nil)
	}
	if f.Download.SuspiciousExecutable {
		add("download.executable", map[string]string{"file": f.Download.FileName})
	}
	if f.Download.SuspiciousArchive {
		add("download.archive", map[string]string{"file": f.Download.FileName})
	}
	if f.Download.SuspiciousDocument {
		add("download.macro_document", map[string]string{"file": f.Download.FileName})
	}
	if f.Download.UnknownBinaryDownload {
		add("download.unknown_binary", map[string]string{"content_type": input.ContentType})
	}
	for _, hit := range f.ThreatIntelHits {
		if strings.HasPrefix(hit, "malicious-domain:") {
			add("intel.malicious_domain", map[string]string{"hit": hit})
		}
		if strings.HasPrefix(hit, "malicious-hash:") {
			add("intel.malicious_hash", map[string]string{"hit": hit})
		}
	}
	return signals
}

func scoreSignals(signals []DetectionSignal) HeuristicResult {
	categoryScores := map[string]int{}
	for _, signal := range signals {
		categoryScores[signal.Category] += signal.Weight
	}
	total := 0
	for category, score := range categoryScores {
		if capValue, ok := categoryCaps[category]; ok && score > capValue {
			score = capValue
		}
		categoryScores[category] = score
		total += score
	}
	if total > 100 {
		total = 100
	}
	action := ActionAllow
	if total >= 70 {
		action = ActionBlock
	} else if total >= 45 {
		action = ActionWarn
	}
	return HeuristicResult{
		Score:                  total,
		Signals:                signals,
		RecommendedAction:      action,
		RequiresAIConfirmation: action == ActionBlock || action == ActionQuarantine,
		CategoryScores:         categoryScores,
	}
}

func ResultToVerdict(result HeuristicResult) ThreatVerdict {
	signals := make([]string, 0, len(result.Signals))
	categoryCounts := map[string]int{}
	for _, signal := range result.Signals {
		signals = append(signals, signal.ID)
		categoryCounts[signal.Category]++
	}
	category := "none"
	topCount := 0
	for candidate, count := range categoryCounts {
		if count > topCount {
			category = candidate
			topCount = count
		}
	}
	if result.RecommendedAction == ActionAllow {
		return allowVerdict("Local rules did not detect suspicious content.", signals...)
	}
	return ThreatVerdict{
		Threat:     true,
		Confidence: float64(result.Score) / 100,
		Category:   category,
		Reason:     localReason(result),
		Action:     result.RecommendedAction,
		Signals:    signals,
	}
}

func localReason(result HeuristicResult) string {
	if result.Suppressed {
		return result.SuppressionReason
	}
	if len(result.Signals) == 0 {
		return "Local rules did not detect suspicious content."
	}
	return fmt.Sprintf("Local rules found %d suspicious signal(s), led by %s.", len(result.Signals), result.Signals[0].Name)
}

func ruleByID(id string) (RuleDefinition, bool) {
	for _, rule := range ruleDefinitions {
		if rule.ID == id {
			return rule, true
		}
	}
	return RuleDefinition{}, false
}

func severityConfidence(severity Severity) float64 {
	switch severity {
	case SeverityCritical:
		return 0.95
	case SeverityHigh:
		return 0.85
	case SeverityMedium:
		return 0.65
	case SeverityLow:
		return 0.4
	default:
		return 0.2
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type RuleStats struct {
	mu    sync.Mutex
	stats map[string]*RuleRuntime
}

func NewRuleStats() *RuleStats {
	stats := make(map[string]*RuleRuntime)
	for _, def := range ruleDefinitions {
		copyDef := def
		stats[def.ID] = &RuleRuntime{Definition: copyDef}
	}
	return &RuleStats{stats: stats}
}

func (s *RuleStats) Record(signals []DetectionSignal) {
	if s == nil {
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	for _, signal := range signals {
		if seen[signal.ID] {
			continue
		}
		seen[signal.ID] = true
		stat := s.stats[signal.ID]
		if stat == nil {
			def := RuleDefinition{ID: signal.ID, Name: signal.Name, Category: signal.Category, Severity: signal.Severity, Weight: signal.Weight, Source: signal.Source}
			stat = &RuleRuntime{Definition: def}
			s.stats[signal.ID] = stat
		}
		stat.Hits++
		stat.LastTriggered = now
	}
}

func (s *RuleStats) RecordFalsePositive(signalIDs []string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range signalIDs {
		if stat := s.stats[id]; stat != nil {
			stat.FalsePositiveOverrides++
		}
	}
}

func (s *RuleStats) Top(limit int) []RuleMetric {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var metrics []RuleMetric
	for _, stat := range s.stats {
		if stat.Hits == 0 {
			continue
		}
		last := ""
		if !stat.LastTriggered.IsZero() {
			last = stat.LastTriggered.Format(time.RFC3339)
		}
		metrics = append(metrics, RuleMetric{
			ID:                     stat.Definition.ID,
			Name:                   stat.Definition.Name,
			Hits:                   stat.Hits,
			FalsePositiveOverrides: stat.FalsePositiveOverrides,
			LastTriggered:          last,
		})
	}
	sortRuleMetrics(metrics)
	if limit > 0 && len(metrics) > limit {
		metrics = metrics[:limit]
	}
	return metrics
}

func RuleCatalog() []RuleDefinition {
	return append([]RuleDefinition(nil), ruleDefinitions...)
}

func sortRuleMetrics(metrics []RuleMetric) {
	for i := 0; i < len(metrics); i++ {
		for j := i + 1; j < len(metrics); j++ {
			if metrics[j].Hits > metrics[i].Hits {
				metrics[i], metrics[j] = metrics[j], metrics[i]
			}
		}
	}
}
