package threats

import (
	"context"
	"time"
)

type ScanTarget string

const (
	ScanRequest  ScanTarget = "request"
	ScanResponse ScanTarget = "response"
)

const (
	ActionAllow      = "allow"
	ActionWarn       = "warn"
	ActionBlock      = "block"
	ActionQuarantine = "quarantine"
)

type ThreatVerdict struct {
	Threat           bool     `json:"threat"`
	Confidence       float64  `json:"confidence"`
	Category         string   `json:"category"`
	Reason           string   `json:"reason"`
	Action           string   `json:"action"`
	Signals          []string `json:"signals"`
	ConfirmedSignals []string `json:"confirmed_signals,omitempty"`
	DisputedSignals  []string `json:"disputed_signals,omitempty"`
}

type ScanInput struct {
	Target      ScanTarget          `json:"target"`
	Method      string              `json:"method,omitempty"`
	URL         string              `json:"url,omitempty"`
	Host        string              `json:"host,omitempty"`
	StatusCode  int                 `json:"status_code,omitempty"`
	Headers     map[string][]string `json:"headers,omitempty"`
	ContentType string              `json:"content_type,omitempty"`
	BodySample  []byte              `json:"-"`
	BodyHash    string              `json:"body_hash,omitempty"`
	RemoteIP    string              `json:"remote_ip,omitempty"`
}

type Event struct {
	ID               string            `json:"id"`
	Timestamp        time.Time         `json:"timestamp"`
	Target           ScanTarget        `json:"target"`
	Method           string            `json:"method,omitempty"`
	URL              string            `json:"url,omitempty"`
	Host             string            `json:"host,omitempty"`
	RemoteIP         string            `json:"remote_ip,omitempty"`
	StatusCode       int               `json:"status_code,omitempty"`
	ContentType      string            `json:"content_type,omitempty"`
	BodyHash         string            `json:"body_hash,omitempty"`
	Verdict          ThreatVerdict     `json:"verdict"`
	LocalResult      HeuristicResult   `json:"local_result"`
	AIVerdict        *ThreatVerdict    `json:"ai_verdict,omitempty"`
	Evidence         EvidenceBundle    `json:"evidence"`
	PromptHash       string            `json:"ai_prompt_hash,omitempty"`
	Model            string            `json:"model,omitempty"`
	ScanLatencyMS    int64             `json:"scan_latency_ms"`
	AIUsed           bool              `json:"ai_used"`
	Blocked          bool              `json:"blocked"`
	Quarantined      bool              `json:"quarantined"`
	OverrideAction   string            `json:"override_action,omitempty"`
	OverrideAt       *time.Time        `json:"override_at,omitempty"`
	OverrideMetadata map[string]string `json:"override_metadata,omitempty"`
}

type Metrics struct {
	ScannedRequests       uint64            `json:"scanned_requests"`
	ScannedResponses      uint64            `json:"scanned_responses"`
	Allowed               uint64            `json:"allowed"`
	Warnings              uint64            `json:"warnings"`
	BlockedThreats        uint64            `json:"blocked_threats"`
	Quarantined           uint64            `json:"quarantined"`
	AICalls               uint64            `json:"ai_calls"`
	Timeouts              uint64            `json:"timeouts"`
	FalsePositiveOverride uint64            `json:"false_positive_overrides"`
	AverageLatencyMS      float64           `json:"average_scan_latency_ms"`
	TopRules              []RuleMetric      `json:"top_rules"`
	ActionCounts          map[string]uint64 `json:"action_counts"`
}

type Scanner interface {
	ScanRequest(ctx context.Context, input ScanInput) (ThreatVerdict, error)
	ScanResponse(ctx context.Context, input ScanInput) (ThreatVerdict, error)
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type DetectionSignal struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Category   string            `json:"category"`
	Severity   Severity          `json:"severity"`
	Confidence float64           `json:"confidence"`
	Weight     int               `json:"weight"`
	Evidence   map[string]string `json:"evidence,omitempty"`
	Source     string            `json:"source"`
}

type HeuristicResult struct {
	Score                  int               `json:"score"`
	Signals                []DetectionSignal `json:"signals"`
	RecommendedAction      string            `json:"recommended_action"`
	RequiresAIConfirmation bool              `json:"requires_ai_confirmation"`
	CategoryScores         map[string]int    `json:"category_scores,omitempty"`
	Suppressed             bool              `json:"suppressed"`
	SuppressionReason      string            `json:"suppression_reason,omitempty"`
}

type EvidenceBundle struct {
	RequestMetadata  map[string]any      `json:"request_metadata,omitempty"`
	ResponseMetadata map[string]any      `json:"response_metadata,omitempty"`
	BodySample       string              `json:"body_sample,omitempty"`
	Extracted        ExtractedFeatures   `json:"extracted_features"`
	LocalSignals     []DetectionSignal   `json:"local_signals"`
	Redaction        RedactionReport     `json:"redaction_report"`
	Quarantine       *QuarantineMetadata `json:"quarantine,omitempty"`
}

type ExtractedFeatures struct {
	URL              URLFeatures      `json:"url"`
	HTML             HTMLFeatures     `json:"html"`
	JavaScript       JSFeatures       `json:"javascript"`
	Payload          PayloadFeatures  `json:"payload"`
	Download         DownloadFeatures `json:"download"`
	Network          NetworkFeatures  `json:"network"`
	ThreatIntelHits  []string         `json:"threat_intel_hits,omitempty"`
	TrustedDomainHit bool             `json:"trusted_domain_hit"`
}

type URLFeatures struct {
	Host                    string   `json:"host,omitempty"`
	Hostname                string   `json:"hostname,omitempty"`
	Scheme                  string   `json:"scheme,omitempty"`
	Path                    string   `json:"path,omitempty"`
	Query                   string   `json:"query,omitempty"`
	Extension               string   `json:"extension,omitempty"`
	IsIPAddress             bool     `json:"is_ip_address"`
	IsPrivateAddress        bool     `json:"is_private_address"`
	IsLoopback              bool     `json:"is_loopback"`
	SuspiciousTLD           bool     `json:"suspicious_tld"`
	CredentialThemed        bool     `json:"credential_themed"`
	Entropy                 float64  `json:"entropy"`
	Punycode                bool     `json:"punycode"`
	HomoglyphLike           bool     `json:"homoglyph_like"`
	SuspiciousQueryKeys     []string `json:"suspicious_query_keys,omitempty"`
	RedirectTargets         []string `json:"redirect_targets,omitempty"`
	ExternalRedirectTargets []string `json:"external_redirect_targets,omitempty"`
}

type HTMLFeatures struct {
	Forms                   []FormFeature `json:"forms,omitempty"`
	PasswordFields          int           `json:"password_fields"`
	HiddenFields            int           `json:"hidden_fields"`
	ExternalFormActions     []string      `json:"external_form_actions,omitempty"`
	IFrames                 []string      `json:"iframes,omitempty"`
	ExternalScripts         []string      `json:"external_scripts,omitempty"`
	MetaRefreshTargets      []string      `json:"meta_refresh_targets,omitempty"`
	SuspiciousLinks         []string      `json:"suspicious_links,omitempty"`
	BrandTerms              []string      `json:"brand_terms,omitempty"`
	HasCredentialCollection bool          `json:"has_credential_collection"`
	HasBrandImpersonation   bool          `json:"has_brand_impersonation"`
	HasTestPhishingMarker   bool          `json:"has_test_phishing_marker"`
	HasClientSideRedirect   bool          `json:"has_client_side_redirect"`
	HasCookieExfiltration   bool          `json:"has_cookie_exfiltration"`
	HasStorageExfiltration  bool          `json:"has_storage_exfiltration"`
	HasObfuscatedJavaScript bool          `json:"has_obfuscated_javascript"`
	HasSuspiciousScriptSink bool          `json:"has_suspicious_script_sink"`
}

type FormFeature struct {
	Action          string   `json:"action,omitempty"`
	Method          string   `json:"method,omitempty"`
	External        bool     `json:"external"`
	PasswordFields  int      `json:"password_fields"`
	HiddenFields    int      `json:"hidden_fields"`
	SensitiveFields []string `json:"sensitive_fields,omitempty"`
}

type JSFeatures struct {
	ReadsCookies        bool     `json:"reads_cookies"`
	ReadsStorage        bool     `json:"reads_storage"`
	NetworkSinks        []string `json:"network_sinks,omitempty"`
	UsesEval            bool     `json:"uses_eval"`
	UsesDynamicScript   bool     `json:"uses_dynamic_script"`
	UsesDocumentWrite   bool     `json:"uses_document_write"`
	ObfuscationMarkers  []string `json:"obfuscation_markers,omitempty"`
	ExternalEndpoints   []string `json:"external_endpoints,omitempty"`
	BeaconLikeEndpoints []string `json:"beacon_like_endpoints,omitempty"`
}

type PayloadFeatures struct {
	CommandInjection     bool     `json:"command_injection"`
	SSRF                 bool     `json:"ssrf"`
	PathTraversal        bool     `json:"path_traversal"`
	SQLInjection         bool     `json:"sql_injection"`
	XSS                  bool     `json:"xss"`
	TemplateInjection    bool     `json:"template_injection"`
	DeserializationProbe bool     `json:"deserialization_probe"`
	EncodedPayload       bool     `json:"encoded_payload"`
	MatchedPatterns      []string `json:"matched_patterns,omitempty"`
}

type DownloadFeatures struct {
	FileName              string `json:"file_name,omitempty"`
	Extension             string `json:"extension,omitempty"`
	ContentDisposition    string `json:"content_disposition,omitempty"`
	SuspiciousExecutable  bool   `json:"suspicious_executable"`
	SuspiciousArchive     bool   `json:"suspicious_archive"`
	SuspiciousDocument    bool   `json:"suspicious_document"`
	UnknownBinaryDownload bool   `json:"unknown_binary_download"`
	QuarantineRecommended bool   `json:"quarantine_recommended"`
}

type NetworkFeatures struct {
	PrivateNetworkTarget bool `json:"private_network_target"`
	LoopbackTarget       bool `json:"loopback_target"`
	IPAddressHost        bool `json:"ip_address_host"`
	NonStandardPort      bool `json:"non_standard_port"`
	C2BeaconLike         bool `json:"c2_beacon_like"`
}

type RedactionReport struct {
	Enabled            bool     `json:"enabled"`
	HeadersRedacted    []string `json:"headers_redacted,omitempty"`
	BodyRedactions     []string `json:"body_redactions,omitempty"`
	OriginalBodyBytes  int      `json:"original_body_bytes"`
	RedactedBodyBytes  int      `json:"redacted_body_bytes"`
	BodyTruncated      bool     `json:"body_truncated"`
	BodySampleLimit    int64    `json:"body_sample_limit"`
	RedactionVersion   string   `json:"redaction_version"`
	PromptMetadataHash string   `json:"prompt_metadata_hash,omitempty"`
}

type QuarantineMetadata struct {
	Recommended bool      `json:"recommended"`
	ID          string    `json:"id,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	FileName    string    `json:"file_name,omitempty"`
	BodyHash    string    `json:"body_hash,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
}

type RuleMetric struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	Hits                   uint64 `json:"hits"`
	FalsePositiveOverrides uint64 `json:"false_positive_overrides"`
	LastTriggered          string `json:"last_triggered,omitempty"`
}
