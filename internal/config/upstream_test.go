package config

import "testing"

func TestUpstreamProxyDefaultsAndValidation(t *testing.T) {
	cfg := defaultConfig()
	if cfg.UpstreamProxy.Enabled {
		t.Fatal("upstream proxy should default to disabled")
	}
	if !cfg.UpstreamProxy.ChainTunnels || !cfg.UpstreamProxy.ApplyToRepeater {
		t.Fatalf("expected tunnel and repeater chaining defaults enabled: %+v", cfg.UpstreamProxy)
	}
	if err := cfg.ValidateUpstreamProxy(); err != nil {
		t.Fatalf("default upstream config should validate: %v", err)
	}

	cfg.UpstreamProxy.Enabled = true
	cfg.UpstreamProxy.URL = "socks5://127.0.0.1:9050"
	if err := cfg.ValidateUpstreamProxy(); err == nil {
		t.Fatal("expected SOCKS upstream URL to be rejected")
	}

	cfg.UpstreamProxy.URL = "http://user:pass@127.0.0.1:8080"
	if err := cfg.ValidateUpstreamProxy(); err == nil {
		t.Fatal("expected URL credentials to be rejected")
	}

	cfg.UpstreamProxy.URL = "http://127.0.0.1:8080"
	cfg.UpstreamProxy.NoProxy = []string{"*.example.com", "localhost"}
	if err := cfg.ValidateUpstreamProxy(); err != nil {
		t.Fatalf("valid upstream config rejected: %v", err)
	}
	if !cfg.IsUpstreamProxyBypassed("api.example.com:443") || !cfg.IsUpstreamProxyBypassed("localhost") {
		t.Fatal("expected exact and wildcard upstream bypass matches")
	}
}
