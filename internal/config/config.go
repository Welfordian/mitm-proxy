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

	// Caching (nested)
	Cache CacheConfig `json:"cache"`

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
		// Caching defaults
		Cache: CacheConfig{
			Enabled:   false,
			Directory: "cache",
			TTL:       3600,
		},
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
