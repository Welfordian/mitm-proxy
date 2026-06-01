package threats

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cfgpkg "mitm-proxy/internal/config"
)

type ConfigProvider func() *cfgpkg.Config

type Manager struct {
	config ConfigProvider
	ai     AIClient
	cache  *VerdictCache
	rules  *RuleStats

	mu          sync.RWMutex
	events      []Event
	subscribers []chan Event
	logMu       sync.Mutex

	scannedRequests  atomic.Uint64
	scannedResponses atomic.Uint64
	allowed          atomic.Uint64
	warnings         atomic.Uint64
	blockedThreats   atomic.Uint64
	quarantined      atomic.Uint64
	aiCalls          atomic.Uint64
	timeouts         atomic.Uint64
	falsePositives   atomic.Uint64
	totalLatencyMS   atomic.Uint64
}

func NewManager(config ConfigProvider) *Manager {
	return &Manager{
		config: config,
		ai:     NewOpenAIClient(),
		cache:  NewVerdictCache(),
		rules:  NewRuleStats(),
	}
}

func (m *Manager) ScanRequest(ctx context.Context, input ScanInput) (ThreatVerdict, error) {
	input.Target = ScanRequest
	cfg := m.threatConfig()
	if !cfg.Enabled || cfg.Mode == "off" || !cfg.ScanRequests {
		return allowVerdict("request scanning disabled", "scanner-disabled"), nil
	}
	m.scannedRequests.Add(1)
	return m.scan(ctx, cfg, input)
}

func (m *Manager) ScanResponse(ctx context.Context, input ScanInput) (ThreatVerdict, error) {
	input.Target = ScanResponse
	cfg := m.threatConfig()
	if !cfg.Enabled || cfg.Mode == "off" || !cfg.ScanResponses {
		return allowVerdict("response scanning disabled", "scanner-disabled"), nil
	}
	m.scannedResponses.Add(1)
	return m.scan(ctx, cfg, input)
}

func (m *Manager) scan(ctx context.Context, cfg cfgpkg.ThreatScannerConfig, input ScanInput) (ThreatVerdict, error) {
	start := time.Now()
	ensureBodyHash(&input)

	localResult := EvaluateHeuristics(input, cfg)
	localVerdict := ResultToVerdict(localResult)
	evidence := BuildEvidence(input, cfg, localResult)
	promptHash := EvidenceHash(evidence)
	if evidence.Quarantine != nil && evidence.Quarantine.Recommended {
		evidence.Quarantine.ID = randomID()
		evidence.Quarantine.CreatedAt = time.Now().UTC()
	}
	m.rules.Record(localResult.Signals)

	cacheKey := CacheKey(input)
	if verdict, ok := m.cache.Get(cacheKey); ok {
		record := scanRecord{
			input:       input,
			verdict:     verdict,
			localResult: localResult,
			evidence:    evidence,
			promptHash:  promptHash,
			cacheHit:    true,
			latency:     time.Since(start),
		}
		m.record(record)
		m.writeDebugLog(cfg, record)
		return verdict, nil
	}

	aiUsed := false
	model := ""
	var aiVerdict *ThreatVerdict
	var err error
	verdict := localVerdict

	if shouldUseAI(cfg, localResult.Score, input) {
		aiUsed = true
		m.aiCalls.Add(1)
		aiResult, aiModel, aiErr := m.ai.Classify(ctx, cfg, input, evidence)
		model = aiModel
		err = aiErr
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "timeout") {
				m.timeouts.Add(1)
			}
			if cfg.RequireAIConfirm && cfg.BlockCriticalOnAIFailure && hasCriticalLocalBlockEvidence(localResult) {
				verdict = criticalLocalAIFailureVerdict(err, localVerdict, localResult)
			} else if cfg.RequireAIConfirm {
				verdict = aiConfirmationUnavailableVerdict(err, localVerdict, cfg)
			} else if verdict.Action == ActionAllow {
				verdict = failureVerdict(err, cfg)
			} else {
				verdict.Signals = append(verdict.Signals, "ai-error-fail-open-preserved-local-verdict")
			}
		} else {
			aiVerdict = &aiResult
			verdict = applyAIVerdictPolicy(localVerdict, aiResult, cfg)
		}
		mergeSignals(&verdict, signalIDs(localResult.Signals))
	} else if cfg.RequireAIConfirm && isBlockingAction(verdict.Action) {
		verdict = localNeedsAIVerdict(verdict, cfg)
	}

	normalizeVerdict(&verdict, cfg)
	m.cache.Set(cacheKey, verdict, model, input.BodyHash)
	record := scanRecord{
		input:       input,
		verdict:     verdict,
		localResult: localResult,
		aiVerdict:   aiVerdict,
		evidence:    evidence,
		promptHash:  promptHash,
		model:       model,
		aiUsed:      aiUsed,
		latency:     time.Since(start),
		err:         err,
	}
	m.record(record)
	m.writeDebugLog(cfg, record)
	return verdict, err
}

func (m *Manager) threatConfig() cfgpkg.ThreatScannerConfig {
	if m == nil || m.config == nil {
		return cfgpkg.ThreatScannerConfig{}
	}
	return m.config().ThreatScanner
}

func shouldUseAI(cfg cfgpkg.ThreatScannerConfig, score int, input ScanInput) bool {
	if cfg.Provider != "openai" {
		return false
	}
	switch cfg.Mode {
	case "metadata_only":
		return false
	case "all_text", "paranoid":
		return isTextLike(cfg, input.ContentType)
	default:
		return score >= 25 || len(input.BodySample) > 0 && score >= 15
	}
}

func allowVerdict(reason string, signals ...string) ThreatVerdict {
	return ThreatVerdict{Threat: false, Confidence: 0.1, Category: "none", Reason: reason, Action: ActionAllow, Signals: signals}
}

func failureVerdict(err error, cfg cfgpkg.ThreatScannerConfig) ThreatVerdict {
	if cfg.FailOpen {
		return ThreatVerdict{Threat: false, Confidence: 0, Category: "scanner_error", Reason: "Threat scanner failed open: " + err.Error(), Action: ActionAllow, Signals: []string{"scanner-error"}}
	}
	return ThreatVerdict{Threat: true, Confidence: 1, Category: "scanner_error", Reason: "Threat scanner failed closed: " + err.Error(), Action: ActionBlock, Signals: []string{"scanner-error"}}
}

func aiConfirmationUnavailableVerdict(err error, local ThreatVerdict, cfg cfgpkg.ThreatScannerConfig) ThreatVerdict {
	if !cfg.FailOpen {
		return ThreatVerdict{Threat: true, Confidence: 1, Category: "scanner_error", Reason: "Threat scanner failed closed before AI confirmation: " + err.Error(), Action: ActionBlock, Signals: append(local.Signals, "ai-confirmation-error")}
	}
	return ThreatVerdict{
		Threat:     local.Threat,
		Confidence: local.Confidence,
		Category:   local.Category,
		Reason:     "Local heuristics found suspicious content, but AI confirmation was unavailable: " + err.Error(),
		Action:     ActionWarn,
		Signals:    append(local.Signals, "ai-confirmation-unavailable"),
	}
}

func criticalLocalAIFailureVerdict(err error, local ThreatVerdict, result HeuristicResult) ThreatVerdict {
	local.Action = ActionBlock
	local.Threat = true
	local.Confidence = maxFloat(local.Confidence, 0.95)
	if local.Category == "" || local.Category == "none" {
		local.Category = "critical_local_detection"
	}
	local.Reason = "Critical local threat evidence was detected and AI confirmation was unavailable: " + err.Error()
	local.Signals = appendUniqueStrings(local.Signals, signalIDs(result.Signals)...)
	local.Signals = appendUniqueStrings(local.Signals, "critical-local-ai-failure-block")
	return local
}

func localNeedsAIVerdict(local ThreatVerdict, cfg cfgpkg.ThreatScannerConfig) ThreatVerdict {
	if !cfg.FailOpen {
		local.Signals = append(local.Signals, "ai-confirmation-required")
		return local
	}
	local.Action = ActionWarn
	local.Reason = "Local heuristics found suspicious content; blocking requires AI confirmation."
	local.Signals = append(local.Signals, "ai-confirmation-required")
	return local
}

func normalizeVerdict(verdict *ThreatVerdict, cfg cfgpkg.ThreatScannerConfig) {
	if verdict.Action == "" {
		verdict.Action = ActionAllow
	}
	if verdict.Category == "" {
		verdict.Category = "unknown"
	}
	if verdict.Confidence < 0 {
		verdict.Confidence = 0
	}
	if verdict.Confidence > 1 {
		verdict.Confidence = 1
	}
	if verdict.Action == ActionAllow && !cfg.RequireAIConfirm {
		if verdict.Confidence >= cfg.BlockThreshold && verdict.Threat {
			verdict.Action = ActionBlock
		} else if verdict.Confidence >= cfg.WarnThreshold && verdict.Threat {
			verdict.Action = ActionWarn
		}
	}
	verdict.Threat = verdict.Action == ActionWarn || verdict.Action == ActionBlock || verdict.Action == ActionQuarantine || verdict.Threat
}

func shouldPreferAIVerdict(local, ai ThreatVerdict) bool {
	if local.Action == ActionAllow {
		return true
	}
	if ai.Action == ActionBlock || ai.Action == ActionQuarantine {
		return true
	}
	if local.Action == ActionWarn && ai.Action == ActionWarn && ai.Confidence >= local.Confidence {
		return true
	}
	return false
}

func applyAIVerdictPolicy(local, ai ThreatVerdict, cfg cfgpkg.ThreatScannerConfig) ThreatVerdict {
	normalizeVerdict(&ai, cfg)
	mergeSignals(&ai, local.Signals)
	if !cfg.RequireAIConfirm {
		if shouldPreferAIVerdict(local, ai) {
			return ai
		}
		return local
	}
	if isBlockingAction(ai.Action) {
		return ai
	}
	if isBlockingAction(local.Action) && ai.Action == ActionAllow {
		ai.Signals = append(ai.Signals, "ai-overrode-local-block")
		return ai
	}
	if isBlockingAction(local.Action) && ai.Action == ActionWarn {
		ai.Signals = append(ai.Signals, "ai-downgraded-local-block")
		return ai
	}
	if local.Action == ActionWarn && ai.Action == ActionAllow {
		ai.Signals = append(ai.Signals, "ai-overrode-local-warning")
		return ai
	}
	if local.Action == ActionAllow {
		return ai
	}
	return local
}

func isBlockingAction(action string) bool {
	return action == ActionBlock || action == ActionQuarantine
}

func hasCriticalLocalBlockEvidence(result HeuristicResult) bool {
	if result.Score < 95 {
		return false
	}
	ids := map[string]bool{}
	critical := 0
	highOrCriticalCategories := map[string]bool{}
	for _, signal := range result.Signals {
		ids[signal.ID] = true
		if signal.Severity == SeverityCritical {
			critical++
		}
		if signal.Severity == SeverityCritical || signal.Severity == SeverityHigh {
			highOrCriticalCategories[signal.Category] = true
		}
	}
	if ids["intel.malicious_domain"] || ids["intel.malicious_hash"] || ids["html.test_phishing_marker"] {
		return true
	}
	if ids["html.external_credential_form"] && ids["js.cookie_exfiltration"] && ids["html.brand_impersonation"] {
		return true
	}
	return critical >= 2 && len(highOrCriticalCategories) >= 2
}

func ShouldBlock(verdict ThreatVerdict, err error, cfg cfgpkg.ThreatScannerConfig) bool {
	if err != nil && !cfg.FailOpen {
		return true
	}
	return verdict.Action == ActionBlock || verdict.Action == ActionQuarantine
}

func isTextLike(cfg cfgpkg.ThreatScannerConfig, contentType string) bool {
	contentType = strings.ToLower(contentType)
	if contentType == "" {
		return true
	}
	for _, skip := range cfg.SkipContentTypes {
		if strings.HasPrefix(contentType, strings.ToLower(skip)) {
			return false
		}
	}
	for _, allowed := range cfg.ScanContentTypes {
		if strings.HasPrefix(contentType, strings.ToLower(allowed)) {
			return true
		}
	}
	return strings.HasPrefix(contentType, "text/")
}

func IsTextLikeForProxy(cfg cfgpkg.ThreatScannerConfig, contentType string) bool {
	return isTextLike(cfg, contentType)
}

func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func ensureBodyHash(input *ScanInput) {
	if input.BodyHash == "" && len(input.BodySample) > 0 {
		input.BodyHash = BodyHash(input.BodySample)
	}
}

func mergeSignals(verdict *ThreatVerdict, signals []string) {
	seen := make(map[string]bool)
	for _, signal := range verdict.Signals {
		seen[signal] = true
	}
	for _, signal := range signals {
		if !seen[signal] {
			verdict.Signals = append(verdict.Signals, signal)
		}
	}
}

func appendUniqueStrings(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if value == "" || seen[value] {
			continue
		}
		values = append(values, value)
		seen[value] = true
	}
	return values
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

type scanRecord struct {
	input       ScanInput
	verdict     ThreatVerdict
	localResult HeuristicResult
	aiVerdict   *ThreatVerdict
	evidence    EvidenceBundle
	promptHash  string
	model       string
	aiUsed      bool
	cacheHit    bool
	latency     time.Duration
	err         error
}

func (m *Manager) record(record scanRecord) {
	if m == nil {
		return
	}
	latencyMS := uint64(record.latency.Milliseconds())
	m.totalLatencyMS.Add(latencyMS)
	switch record.verdict.Action {
	case ActionAllow:
		m.allowed.Add(1)
	case ActionWarn:
		m.warnings.Add(1)
	case ActionBlock:
		m.blockedThreats.Add(1)
	case ActionQuarantine:
		m.blockedThreats.Add(1)
		m.quarantined.Add(1)
	}

	event := Event{
		ID:            randomID(),
		Timestamp:     time.Now().UTC(),
		Target:        record.input.Target,
		Method:        record.input.Method,
		URL:           record.input.URL,
		Host:          record.input.Host,
		RemoteIP:      record.input.RemoteIP,
		StatusCode:    record.input.StatusCode,
		ContentType:   record.input.ContentType,
		BodyHash:      record.input.BodyHash,
		Verdict:       record.verdict,
		LocalResult:   record.localResult,
		AIVerdict:     record.aiVerdict,
		Evidence:      eventEvidence(record.evidence),
		PromptHash:    record.promptHash,
		Model:         record.model,
		ScanLatencyMS: int64(latencyMS),
		AIUsed:        record.aiUsed,
		Blocked:       record.verdict.Action == ActionBlock || record.verdict.Action == ActionQuarantine,
		Quarantined:   record.verdict.Action == ActionQuarantine,
	}
	if record.err != nil {
		event.Verdict.Signals = append(event.Verdict.Signals, "scan-error")
	}

	m.mu.Lock()
	m.events = append(m.events, event)
	if len(m.events) > 1000 {
		m.events = m.events[len(m.events)-1000:]
	}
	subscribers := append([]chan Event(nil), m.subscribers...)
	m.mu.Unlock()

	for _, ch := range subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

func (m *Manager) Metrics() Metrics {
	requests := m.scannedRequests.Load()
	responses := m.scannedResponses.Load()
	total := requests + responses
	avg := 0.0
	if total > 0 {
		avg = float64(m.totalLatencyMS.Load()) / float64(total)
	}
	return Metrics{
		ScannedRequests:       requests,
		ScannedResponses:      responses,
		Allowed:               m.allowed.Load(),
		Warnings:              m.warnings.Load(),
		BlockedThreats:        m.blockedThreats.Load(),
		Quarantined:           m.quarantined.Load(),
		AICalls:               m.aiCalls.Load(),
		Timeouts:              m.timeouts.Load(),
		FalsePositiveOverride: m.falsePositives.Load(),
		AverageLatencyMS:      avg,
		TopRules:              m.rules.Top(10),
		ActionCounts: map[string]uint64{
			ActionAllow:      m.allowed.Load(),
			ActionWarn:       m.warnings.Load(),
			ActionBlock:      m.blockedThreats.Load(),
			ActionQuarantine: m.quarantined.Load(),
		},
	}
}

func (m *Manager) ListEvents(limit int) []Event {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	start := len(m.events) - limit
	if start < 0 {
		start = 0
	}
	out := append([]Event(nil), m.events[start:]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (m *Manager) GetEvent(id string) (Event, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, event := range m.events {
		if event.ID == id {
			return event, true
		}
	}
	return Event{}, false
}

func (m *Manager) OverrideEvent(id, action string) (Event, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.events {
		if m.events[i].ID == id {
			oldAction := m.events[i].Verdict.Action
			m.events[i].Verdict.Action = action
			m.events[i].Blocked = action == ActionBlock || action == ActionQuarantine
			now := time.Now().UTC()
			m.events[i].OverrideAction = action
			m.events[i].OverrideAt = &now
			if action == ActionAllow && (oldAction == ActionWarn || oldAction == ActionBlock || oldAction == ActionQuarantine) {
				m.falsePositives.Add(1)
				m.rules.RecordFalsePositive(m.events[i].Verdict.Signals)
			}
			return m.events[i], true
		}
	}
	return Event{}, false
}

func (m *Manager) Subscribe() <-chan Event {
	ch := make(chan Event, 32)
	m.mu.Lock()
	m.subscribers = append(m.subscribers, ch)
	m.mu.Unlock()
	return ch
}

func (m *Manager) Test(ctx context.Context, input ScanInput) (ThreatVerdict, error) {
	cfg := m.threatConfig()
	if input.Target == ScanResponse {
		return m.ScanResponse(ctx, input)
	}
	if !cfg.Enabled {
		cfg.Enabled = true
	}
	return m.scan(ctx, cfg, input)
}

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
	}
	return hex.EncodeToString(b[:])
}

func EventJSON(event Event) []byte {
	data, _ := json.Marshal(event)
	return data
}

func EvidenceHash(evidence EvidenceBundle) string {
	copy := evidence
	copy.BodySample = ""
	data, _ := json.Marshal(copy)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func signalIDs(signals []DetectionSignal) []string {
	out := make([]string, 0, len(signals))
	for _, signal := range signals {
		out = append(out, signal.ID)
	}
	return out
}

func eventEvidence(evidence EvidenceBundle) EvidenceBundle {
	evidence.BodySample = ""
	return evidence
}

func (m *Manager) RuleCatalog() []RuleDefinition {
	return RuleCatalog()
}

func (m *Manager) QuarantineItems() []QuarantineMetadata {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var items []QuarantineMetadata
	for _, event := range m.events {
		if event.Evidence.Quarantine != nil && event.Evidence.Quarantine.Recommended {
			items = append(items, *event.Evidence.Quarantine)
		}
	}
	return items
}

func (m *Manager) InvalidateCache() {
	m.cache = NewVerdictCache()
}

func ScanSummary(result HeuristicResult) string {
	return fmt.Sprintf("score=%d action=%s signals=%d", result.Score, result.RecommendedAction, len(result.Signals))
}

type debugLogEntry struct {
	Timestamp         time.Time           `json:"timestamp"`
	Target            ScanTarget          `json:"target"`
	Method            string              `json:"method,omitempty"`
	URL               string              `json:"url,omitempty"`
	Host              string              `json:"host,omitempty"`
	StatusCode        int                 `json:"status_code,omitempty"`
	ContentType       string              `json:"content_type,omitempty"`
	BodyHash          string              `json:"body_hash,omitempty"`
	CacheHit          bool                `json:"cache_hit"`
	LocalScore        int                 `json:"local_score"`
	LocalAction       string              `json:"local_action"`
	LocalSuppressed   bool                `json:"local_suppressed"`
	SuppressionReason string              `json:"suppression_reason,omitempty"`
	LocalSignals      []DetectionSignal   `json:"local_signals,omitempty"`
	CategoryScores    map[string]int      `json:"category_scores,omitempty"`
	AIUsed            bool                `json:"ai_used"`
	AIModel           string              `json:"ai_model,omitempty"`
	AIError           string              `json:"ai_error,omitempty"`
	AIVerdict         *ThreatVerdict      `json:"ai_verdict,omitempty"`
	FinalVerdict      ThreatVerdict       `json:"final_verdict"`
	ShouldBlock       bool                `json:"should_block"`
	PromptHash        string              `json:"prompt_hash,omitempty"`
	Redaction         RedactionReport     `json:"redaction"`
	Extracted         ExtractedFeatures   `json:"extracted_features"`
	Quarantine        *QuarantineMetadata `json:"quarantine,omitempty"`
	LatencyMS         int64               `json:"latency_ms"`
}

func (m *Manager) writeDebugLog(cfg cfgpkg.ThreatScannerConfig, record scanRecord) {
	path := strings.TrimSpace(cfg.DebugLogPath)
	if path == "" {
		path = "threats.log"
	}
	entry := debugLogEntry{
		Timestamp:         time.Now().UTC(),
		Target:            record.input.Target,
		Method:            record.input.Method,
		URL:               record.input.URL,
		Host:              record.input.Host,
		StatusCode:        record.input.StatusCode,
		ContentType:       record.input.ContentType,
		BodyHash:          record.input.BodyHash,
		CacheHit:          record.cacheHit,
		LocalScore:        record.localResult.Score,
		LocalAction:       record.localResult.RecommendedAction,
		LocalSuppressed:   record.localResult.Suppressed,
		SuppressionReason: record.localResult.SuppressionReason,
		LocalSignals:      record.localResult.Signals,
		CategoryScores:    record.localResult.CategoryScores,
		AIUsed:            record.aiUsed,
		AIModel:           record.model,
		AIVerdict:         record.aiVerdict,
		FinalVerdict:      record.verdict,
		ShouldBlock:       record.verdict.Action == ActionBlock || record.verdict.Action == ActionQuarantine,
		PromptHash:        record.promptHash,
		Redaction:         record.evidence.Redaction,
		Extracted:         record.evidence.Extracted,
		Quarantine:        record.evidence.Quarantine,
		LatencyMS:         record.latency.Milliseconds(),
	}
	if record.err != nil {
		entry.AIError = record.err.Error()
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	m.logMu.Lock()
	defer m.logMu.Unlock()
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.Write(append(data, '\n'))
}

func HeaderMap(headers http.Header) map[string][]string {
	if headers == nil {
		return nil
	}
	return map[string][]string(headers.Clone())
}
