package config

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

// Config holds runtime configuration for the proxy.
type Config struct {
	// Server settings
	ListenAddr string `json:"listen_addr"`

	// CA certificate paths
	CACertPath string `json:"ca_cert_path"`
	CAKeyPath  string `json:"ca_key_path"`

	// Output paths for generated certificates
	CACertOutputPath string `json:"ca_cert_output_path"`
	CAKeyOutputPath  string `json:"ca_key_output_path"`

	// MITM settings
	EnableMITM bool `json:"enable_mitm"`

	// Domain exclusions (supports wildcards)
	ExcludedDomains []string `json:"excluded_domains"`

	// Logging
	VerboseLogging bool `json:"verbose_logging"`
	LogRequests    bool `json:"log_requests"`

	// Connection settings
	MaxIdleConns        int `json:"max_idle_conns"`
	IdleConnTimeout     int `json:"idle_conn_timeout_seconds"`
	TLSHandshakeTimeout int `json:"tls_handshake_timeout_seconds"`

	// TLS settings
	MinTLSVersion string   `json:"min_tls_version"`
	TLSNextProtos []string `json:"tls_next_protos"`

	// Proxy identity
	ProxyName string `json:"proxy_name"`

	// Admin dashboard
	AdminEnabled   bool   `json:"admin_enabled"`
	AdminAddr      string `json:"admin_addr"`
	AdminToken     string `json:"admin_token"`
	AdminReadToken string `json:"admin_read_token"`
	AdminUI        bool   `json:"admin_ui"`
	AdminStore     string `json:"admin_store"`

	// Caching (nested)
	Cache CacheConfig `json:"cache"`

	// Blocking policy
	BlockedPorts        []int    `json:"blocked_ports"`
	BlockedDomains      []string `json:"blocked_domains"`
	BlockedIPs          []string `json:"blocked_ips"`
	BlockAction         string   `json:"block_action"`
	BlockResponseStatus int      `json:"block_response_status"`

	// Threat scanning
	ThreatScanner ThreatScannerConfig `json:"threat_scanner"`

	// AI copilot powers optional research assistance in the admin dashboard.
	AICopilot AICopilotConfig `json:"ai_copilot"`

	// Traffic capture controls body persistence for dashboard inspection.
	TrafficCapture TrafficCaptureConfig `json:"traffic_capture"`

	// Deprecated legacy flat caching fields (supported for backward compatibility)
	CacheEnabledLegacy      bool     `json:"cache_enabled"`
	CacheDirLegacy          string   `json:"cache_dir"`
	IncludeDomainsLegacy    []string `json:"include_domains"`
	ExcludeDomainsLegacy    []string `json:"exclude_domains"`
	IncludeExtensionsLegacy []string `json:"include_extensions"`
	ExcludeExtensionsLegacy []string `json:"exclude_extensions"`
	CacheTTLLegacy          int      `json:"cache_ttl"`
}

// CacheConfig holds cache-related configuration
type CacheConfig struct {
	Enabled           bool     `json:"enabled"`
	Directory         string   `json:"directory"`
	IncludeDomains    []string `json:"include_domains"`
	ExcludeDomains    []string `json:"exclude_domains"`
	IncludeExtensions []string `json:"include_extensions"`
	ExcludeExtensions []string `json:"exclude_extensions"`
	TTL               int      `json:"ttl"`
}

// ThreatScannerConfig holds threat-scanning and AI classifier settings.
type ThreatScannerConfig struct {
	Enabled                  bool     `json:"enabled"`
	Mode                     string   `json:"mode"`
	Provider                 string   `json:"provider"`
	Model                    string   `json:"model"`
	SecondOpinionModel       string   `json:"second_opinion_model"`
	ScanRequests             bool     `json:"scan_requests"`
	ScanResponses            bool     `json:"scan_responses"`
	MaxBodyBytes             int64    `json:"max_body_bytes"`
	MaxAIBodyBytes           int64    `json:"max_ai_body_bytes"`
	AITimeoutMS              int      `json:"ai_timeout_ms"`
	BlockThreshold           float64  `json:"block_threshold"`
	WarnThreshold            float64  `json:"warn_threshold"`
	RequireAIConfirm         bool     `json:"require_ai_confirmation_for_block"`
	BlockCriticalOnAIFailure bool     `json:"block_critical_local_on_ai_failure"`
	FailOpen                 bool     `json:"fail_open"`
	ScanContentTypes         []string `json:"scan_content_types"`
	SkipContentTypes         []string `json:"skip_content_types"`
	TrustedDomains           []string `json:"trusted_domains"`
	AllowlistDomains         []string `json:"allowlist_domains"`
	MaliciousDomains         []string `json:"malicious_domains"`
	MaliciousFileHashes      []string `json:"malicious_file_hashes"`
	ThreatIntelUpdated       string   `json:"threat_intel_updated"`
	QuarantineDir            string   `json:"quarantine_dir"`
	DebugLogPath             string   `json:"debug_log_path"`
	RedactBeforeAI           bool     `json:"redact_before_ai"`
	StoreBodies              bool     `json:"store_bodies"`
	OpenAIAPIKeyEnv          string   `json:"openai_api_key_env"`
}

type AICopilotConfig struct {
	Enabled         bool   `json:"enabled"`
	Provider        string `json:"provider"`
	Model           string `json:"model"`
	TimeoutMS       int    `json:"timeout_ms"`
	MaxBodyBytes    int64  `json:"max_body_bytes"`
	RedactBeforeAI  bool   `json:"redact_before_ai"`
	OpenAIAPIKeyEnv string `json:"openai_api_key_env"`
}

type TrafficCaptureConfig struct {
	StoreBodies  bool  `json:"store_bodies"`
	MaxBodyBytes int64 `json:"max_body_bytes"`
	RedactBodies bool  `json:"redact_bodies"`
}

// defaultConfig returns a Config with sensible defaults.
func defaultConfig() *Config {
	return &Config{
		ListenAddr:          ":8080",
		CACertPath:          "",
		CAKeyPath:           "",
		CACertOutputPath:    "ca-cert.pem",
		CAKeyOutputPath:     "ca-key.pem",
		EnableMITM:          true,
		ExcludedDomains:     nil,
		VerboseLogging:      false,
		LogRequests:         true,
		MaxIdleConns:        200,
		IdleConnTimeout:     90,
		TLSHandshakeTimeout: 10,
		MinTLSVersion:       "1.2",
		TLSNextProtos:       []string{"h2", "http/1.1"},
		ProxyName:           "MITM-Proxy",
		AdminEnabled:        true,
		AdminAddr:           "127.0.0.1:9090",
		AdminUI:             true,
		AdminStore:          "dashboard.db",
		BlockAction:         "deny",
		BlockResponseStatus: 403,
		// Caching defaults
		Cache: CacheConfig{
			Enabled:   false,
			Directory: "cache",
			TTL:       3600,
		},
		ThreatScanner: defaultThreatScannerConfig(),
		AICopilot:     defaultAICopilotConfig(),
		TrafficCapture: TrafficCaptureConfig{
			StoreBodies:  false,
			MaxBodyBytes: 32768,
			RedactBodies: true,
		},
	}
}

func defaultAICopilotConfig() AICopilotConfig {
	return AICopilotConfig{
		Enabled:         false,
		Provider:        "openai",
		Model:           "gpt-5.4-nano",
		TimeoutMS:       30000,
		MaxBodyBytes:    32768,
		RedactBeforeAI:  true,
		OpenAIAPIKeyEnv: "OPENAI_API_KEY",
	}
}

func defaultThreatScannerConfig() ThreatScannerConfig {
	return ThreatScannerConfig{
		Enabled:                  false,
		Mode:                     "suspicious_only",
		Provider:                 "openai",
		Model:                    "gpt-5.4-nano",
		SecondOpinionModel:       "gpt-5.4-mini",
		ScanRequests:             true,
		ScanResponses:            true,
		MaxBodyBytes:             131072,
		MaxAIBodyBytes:           32768,
		AITimeoutMS:              5000,
		BlockThreshold:           0.85,
		WarnThreshold:            0.65,
		RequireAIConfirm:         true,
		BlockCriticalOnAIFailure: true,
		FailOpen:                 true,
		ScanContentTypes: []string{
			"text/html",
			"text/plain",
			"application/json",
			"application/javascript",
			"text/javascript",
			"application/xml",
		},
		SkipContentTypes: []string{
			"image/",
			"video/",
			"audio/",
			"font/",
			"application/octet-stream",
		},
		TrustedDomains: []string{
			"localhost",
			"127.0.0.1",
			"::1",
			"accounts.google.com",
			"login.microsoftonline.com",
			"github.com",
		},
		QuarantineDir:   "quarantine",
		DebugLogPath:    "threats.log",
		RedactBeforeAI:  true,
		StoreBodies:     false,
		OpenAIAPIKeyEnv: "OPENAI_API_KEY",
	}
}

// Load reads configuration from path or config.json, falling back to defaults.
func Load(path string) (*Config, error) {
	cfg := defaultConfig()

	if path == "" {
		if _, err := os.Stat("config.json"); err == nil {
			path = "config.json"
		} else {
			log.Println("No config file specified or found, using defaults")

			return cfg, nil
		}
	}

	data, err := os.ReadFile(path)

	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	// If nested cache object is not populated but legacy fields are present, migrate them
	if isZeroCache(cfg.Cache) && hasAnyLegacyCache(*cfg) {
		migrateLegacyToCache(cfg)
	}

	// Fill defaults for cache if missing
	if cfg.Cache.Directory == "" {
		cfg.Cache.Directory = "cache"
	}

	if cfg.Cache.TTL == 0 {
		cfg.Cache.TTL = 3600
	}

	applyThreatScannerDefaults(&cfg.ThreatScanner)
	applyAICopilotDefaults(&cfg.AICopilot, cfg.ThreatScanner)
	applyTrafficCaptureDefaults(&cfg.TrafficCapture)

	if strings.TrimSpace(cfg.AdminAddr) == "" {
		cfg.AdminAddr = "127.0.0.1:9090"
	}

	if strings.TrimSpace(cfg.AdminStore) == "" {
		cfg.AdminStore = "dashboard.db"
	}

	if cfg.BlockAction == "" {
		cfg.BlockAction = "deny"
	}

	if cfg.BlockResponseStatus == 0 {
		cfg.BlockResponseStatus = 403
	}

	// Default proxy name if missing
	if strings.TrimSpace(cfg.ProxyName) == "" {
		cfg.ProxyName = "MITM-Proxy"
	}

	// Validate mutual exclusivity for include/exclude settings (nested cache)
	if len(cfg.Cache.IncludeDomains) > 0 && len(cfg.Cache.ExcludeDomains) > 0 {
		return nil, fmt.Errorf("invalid config: cache.include_domains and cache.exclude_domains cannot both be set")
	}

	if len(cfg.Cache.IncludeExtensions) > 0 && len(cfg.Cache.ExcludeExtensions) > 0 {
		return nil, fmt.Errorf("invalid config: cache.include_extensions and cache.exclude_extensions cannot both be set")
	}

	log.Printf("Loaded configuration from %s", path)

	return cfg, nil
}

func applyAICopilotDefaults(c *AICopilotConfig, scanner ThreatScannerConfig) {
	defaults := defaultAICopilotConfig()
	if c.Provider == "" {
		c.Provider = defaults.Provider
	}
	if c.Model == "" {
		if scanner.Model != "" {
			c.Model = scanner.Model
		} else {
			c.Model = defaults.Model
		}
	}
	if c.TimeoutMS == 0 {
		c.TimeoutMS = defaults.TimeoutMS
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = defaults.MaxBodyBytes
	}
	if c.OpenAIAPIKeyEnv == "" {
		c.OpenAIAPIKeyEnv = defaults.OpenAIAPIKeyEnv
	}
}

func applyTrafficCaptureDefaults(c *TrafficCaptureConfig) {
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 32768
	}
	if !c.StoreBodies {
		c.RedactBodies = true
	}
}

func applyThreatScannerDefaults(c *ThreatScannerConfig) {
	defaults := defaultThreatScannerConfig()
	if c.Mode == "" {
		c.Mode = defaults.Mode
	}
	if c.Provider == "" {
		c.Provider = defaults.Provider
	}
	if c.Model == "" {
		c.Model = defaults.Model
	}
	if c.SecondOpinionModel == "" {
		c.SecondOpinionModel = defaults.SecondOpinionModel
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = defaults.MaxBodyBytes
	}
	if c.MaxAIBodyBytes == 0 {
		c.MaxAIBodyBytes = defaults.MaxAIBodyBytes
	}
	if c.AITimeoutMS == 0 {
		c.AITimeoutMS = defaults.AITimeoutMS
	}
	if c.BlockThreshold == 0 {
		c.BlockThreshold = defaults.BlockThreshold
	}
	if c.WarnThreshold == 0 {
		c.WarnThreshold = defaults.WarnThreshold
	}
	if len(c.ScanContentTypes) == 0 {
		c.ScanContentTypes = defaults.ScanContentTypes
	}
	if len(c.SkipContentTypes) == 0 {
		c.SkipContentTypes = defaults.SkipContentTypes
	}
	if len(c.TrustedDomains) == 0 {
		c.TrustedDomains = defaults.TrustedDomains
	}
	if c.QuarantineDir == "" {
		c.QuarantineDir = defaults.QuarantineDir
	}
	if c.DebugLogPath == "" {
		c.DebugLogPath = defaults.DebugLogPath
	}
	if c.OpenAIAPIKeyEnv == "" {
		c.OpenAIAPIKeyEnv = defaults.OpenAIAPIKeyEnv
	}
}

// isZeroCache reports whether all fields of CacheConfig are zero-values
func isZeroCache(c CacheConfig) bool {
	return !c.Enabled && c.Directory == "" && c.TTL == 0 && len(c.IncludeDomains) == 0 && len(c.ExcludeDomains) == 0 && len(c.IncludeExtensions) == 0 && len(c.ExcludeExtensions) == 0
}

// hasAnyLegacyCache reports whether any legacy cache field was provided
func hasAnyLegacyCache(c Config) bool {
	return c.CacheEnabledLegacy || c.CacheDirLegacy != "" || c.CacheTTLLegacy != 0 || len(c.IncludeDomainsLegacy) > 0 || len(c.ExcludeDomainsLegacy) > 0 || len(c.IncludeExtensionsLegacy) > 0 || len(c.ExcludeExtensionsLegacy) > 0
}

// migrateLegacyToCache copies legacy flat fields into the nested Cache object
func migrateLegacyToCache(cfg *Config) {
	cfg.Cache.Enabled = cfg.CacheEnabledLegacy

	if cfg.CacheDirLegacy != "" {
		cfg.Cache.Directory = cfg.CacheDirLegacy
	}

	if cfg.CacheTTLLegacy != 0 {
		cfg.Cache.TTL = cfg.CacheTTLLegacy
	}

	if len(cfg.IncludeDomainsLegacy) > 0 {
		cfg.Cache.IncludeDomains = cfg.IncludeDomainsLegacy
	}

	if len(cfg.ExcludeDomainsLegacy) > 0 {
		cfg.Cache.ExcludeDomains = cfg.ExcludeDomainsLegacy
	}

	if len(cfg.IncludeExtensionsLegacy) > 0 {
		cfg.Cache.IncludeExtensions = cfg.IncludeExtensionsLegacy
	}

	if len(cfg.ExcludeExtensionsLegacy) > 0 {
		cfg.Cache.ExcludeExtensions = cfg.ExcludeExtensionsLegacy
	}
}

// GetTLSVersion converts MinTLSVersion to tls package constant.
func (c *Config) GetTLSVersion() uint16 {
	switch c.MinTLSVersion {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// IsDomainExcluded checks a domain against the exclusion list (supports wildcard patterns like *.example.com).
func (c *Config) IsDomainExcluded(domain string) bool {
	if len(c.ExcludedDomains) == 0 {
		return false
	}

	domain = strings.ToLower(domain)

	if strings.Contains(domain, ":") {
		if host, _, err := net.SplitHostPort(domain); err == nil {
			domain = host
		}
	}

	for _, pattern := range c.ExcludedDomains {
		pattern = strings.ToLower(pattern)

		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:]
			if strings.HasSuffix(domain, suffix) || domain == pattern[2:] {
				return true
			}
		} else if pattern == domain {
			return true
		}
	}

	return false
}
