package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	cfgpkg "mitm-proxy/internal/config"

	"golang.org/x/net/http2"
)

func NewHTTPClient(cfg *cfgpkg.Config, timeout time.Duration) *http.Client {
	client := &http.Client{Transport: NewTransport(cfg)}
	if timeout > 0 {
		client.Timeout = timeout
	}
	return client
}

func NewTransport(cfg *cfgpkg.Config) *http.Transport {
	transport := &http.Transport{
		Proxy:               proxyFunc(cfg),
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        cfg.MaxIdleConns,
		IdleConnTimeout:     time.Duration(cfg.IdleConnTimeout) * time.Second,
		TLSHandshakeTimeout: time.Duration(cfg.TLSHandshakeTimeout) * time.Second,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}
	_ = http2.ConfigureTransport(transport)
	return transport
}

func proxyFunc(cfg *cfgpkg.Config) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		upstreamCfg := cfg.UpstreamProxy
		if !upstreamCfg.Enabled {
			return nil, nil
		}
		if cfg.IsUpstreamProxyBypassed(req.URL.Hostname()) {
			return nil, nil
		}
		return proxyURLWithAuth(upstreamCfg)
	}
}

func DialContext(ctx context.Context, cfg *cfgpkg.Config, target string) (net.Conn, error) {
	upstreamCfg := cfg.UpstreamProxy
	if !upstreamCfg.Enabled || !upstreamCfg.ChainTunnels || cfg.IsUpstreamProxyBypassed(target) {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		return dialer.DialContext(ctx, "tcp", target)
	}
	return connectTunnel(ctx, upstreamCfg, target)
}

func connectTunnel(ctx context.Context, upstreamCfg cfgpkg.UpstreamProxyConfig, target string) (net.Conn, error) {
	proxyURL, err := proxyURLWithAuth(upstreamCfg)
	if err != nil {
		return nil, err
	}
	proxyAddr := proxyURL.Host
	if !strings.Contains(proxyAddr, ":") {
		switch proxyURL.Scheme {
		case "https":
			proxyAddr = net.JoinHostPort(proxyAddr, "443")
		default:
			proxyAddr = net.JoinHostPort(proxyAddr, "80")
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial upstream proxy: %w", err)
	}
	if proxyURL.Scheme == "https" {
		serverName := proxyURL.Hostname()
		tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("upstream proxy TLS handshake: %w", err)
		}
		conn = tlsConn
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if auth := basicProxyAuthorization(upstreamCfg); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write upstream CONNECT: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read upstream CONNECT response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		conn.Close()
		return nil, fmt.Errorf("upstream CONNECT failed: %s", resp.Status)
	}
	return conn, nil
}

func proxyURLWithAuth(upstreamCfg cfgpkg.UpstreamProxyConfig) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(upstreamCfg.URL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid upstream proxy URL")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("upstream proxy URL must not include credentials")
	}
	if username := strings.TrimSpace(upstreamCfg.Username); username != "" {
		password, ok := os.LookupEnv(strings.TrimSpace(upstreamCfg.PasswordEnv))
		if !ok {
			return nil, fmt.Errorf("upstream proxy password env var %q is not set", upstreamCfg.PasswordEnv)
		}
		clone := *parsed
		clone.User = url.UserPassword(username, password)
		return &clone, nil
	}
	return parsed, nil
}

func basicProxyAuthorization(upstreamCfg cfgpkg.UpstreamProxyConfig) string {
	username := strings.TrimSpace(upstreamCfg.Username)
	if username == "" {
		return ""
	}
	password, ok := os.LookupEnv(strings.TrimSpace(upstreamCfg.PasswordEnv))
	if !ok {
		return ""
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}
