package upstream

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cfgpkg "mitm-proxy/internal/config"
)

func TestHTTPTransportUsesUpstreamProxyAndAuth(t *testing.T) {
	t.Setenv("UPSTREAM_PROXY_PASSWORD", "secret")
	var sawProxyAuth atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") == "Basic cmVzZWFyY2hlcjpzZWNyZXQ=" {
			sawProxyAuth.Store(true)
		}
		if r.URL.Scheme != "http" || r.URL.Host != "target.test" {
			t.Fatalf("expected absolute-form proxy request, got %q", r.URL.String())
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer proxy.Close()

	cfg := testConfig(proxy.URL)
	cfg.UpstreamProxy.Username = "researcher"
	client := NewHTTPClient(cfg, 2*time.Second)
	req, _ := http.NewRequest(http.MethodGet, "http://target.test/path", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through upstream proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted || string(body) != "proxied" {
		t.Fatalf("unexpected response: status=%d body=%q", resp.StatusCode, string(body))
	}
	if !sawProxyAuth.Load() {
		t.Fatal("expected Proxy-Authorization header at upstream proxy")
	}
}

func TestHTTPTransportBypassesNoProxy(t *testing.T) {
	var proxyHits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		http.Error(w, "should not use proxy", http.StatusTeapot)
	}))
	defer proxy.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("direct"))
	}))
	defer target.Close()

	cfg := testConfig(proxy.URL)
	cfg.UpstreamProxy.NoProxy = []string{"127.0.0.1"}
	client := NewHTTPClient(cfg, 2*time.Second)
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("direct request with no_proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "direct" || proxyHits.Load() != 0 {
		t.Fatalf("expected direct response without proxy hits, body=%q hits=%d", string(body), proxyHits.Load())
	}
}

func TestDialContextUsesUpstreamConnect(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend"))
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != backendAddr {
			t.Fatalf("expected CONNECT %s, got %s %s", backendAddr, r.Method, r.Host)
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("proxy server does not support hijacking")
		}
		clientConn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		targetConn, err := net.Dial("tcp", backendAddr)
		if err != nil {
			t.Fatalf("dial backend: %v", err)
		}
		go func() {
			defer clientConn.Close()
			defer targetConn.Close()
			_, _ = io.Copy(targetConn, clientConn)
		}()
		go func() {
			defer clientConn.Close()
			defer targetConn.Close()
			_, _ = io.Copy(clientConn, targetConn)
		}()
	}))
	defer proxy.Close()

	conn, err := DialContext(context.Background(), testConfig(proxy.URL), backendAddr)
	if err != nil {
		t.Fatalf("dial through upstream CONNECT: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+backendAddr+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request through tunnel: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read tunneled response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend" {
		t.Fatalf("unexpected tunneled body %q", string(body))
	}
}

func testConfig(proxyURL string) *cfgpkg.Config {
	return &cfgpkg.Config{
		MaxIdleConns:        10,
		IdleConnTimeout:     30,
		TLSHandshakeTimeout: 5,
		UpstreamProxy: cfgpkg.UpstreamProxyConfig{
			Enabled:         true,
			URL:             proxyURL,
			PasswordEnv:     "UPSTREAM_PROXY_PASSWORD",
			NoProxy:         []string{},
			ChainTunnels:    true,
			ApplyToRepeater: true,
		},
	}
}
