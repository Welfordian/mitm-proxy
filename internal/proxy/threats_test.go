package proxy

import (
	"net/http"
	"testing"

	cfgpkg "mitm-proxy/internal/config"
)

func TestPrepareRequestForThreatResponseScanStripsConditionalHeaders(t *testing.T) {
	cfg := &cfgpkg.Config{}
	cfg.ThreatScanner.Enabled = true
	cfg.ThreatScanner.ScanResponses = true
	p := New(nil, cfg)

	req, err := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for _, header := range []string{"If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since", "If-Range", "Range"} {
		req.Header.Set(header, "validator")
	}

	p.prepareRequestForThreatResponseScan(req)

	for _, header := range []string{"If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since", "If-Range", "Range"} {
		if got := req.Header.Get(header); got != "" {
			t.Fatalf("expected %s to be stripped, got %q", header, got)
		}
	}
	if got := req.Header.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("expected Cache-Control no-cache, got %q", got)
	}
}
