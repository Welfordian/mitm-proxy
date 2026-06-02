package proxy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mitm-proxy/internal/access"
	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/store"
)

func TestPlainHTTPProxyAuthAndHeaderStripping(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/dashboard.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	hash, err := access.HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := st.CreateProxyUser(context.Background(), store.ProxyUser{Username: "alice", PasswordHash: hash, Enabled: true}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := st.CreateProxyACLRule(context.Background(), store.ProxyACLRule{Priority: 1, Enabled: true, Action: "allow", Name: "allow all", Users: []string{"alice"}}); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	var upstreamProxyAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamProxyAuth = r.Header.Get("Proxy-Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	bus := events.NewBus(16)
	ch := bus.Subscribe("*")
	go func() {
		for event := range ch {
			_ = st.RecordEvent(context.Background(), event)
		}
	}()
	p := NewWithEvents(nil, &cfgpkg.Config{
		ProxyName: "MITM-Proxy",
		ProxyAuth: cfgpkg.ProxyAuthConfig{Enabled: true, Realm: "Test", RequireAuthForLoopback: true, DefaultAction: "deny"},
	}, bus)
	p.SetAccessStore(st)

	missingReq := httptest.NewRequest(http.MethodGet, target.URL, nil)
	missingRR := httptest.NewRecorder()
	p.ServeHTTP(missingRR, missingReq)
	if missingRR.Code != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407 for missing credentials, got %d", missingRR.Code)
	}

	req := httptest.NewRequest(http.MethodGet, target.URL, nil)
	req.Header.Set("Proxy-Authorization", basicProxy("alice", "secret"))
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected authenticated request success, got %d: %s", rr.Code, rr.Body.String())
	}
	if upstreamProxyAuth != "" {
		t.Fatalf("Proxy-Authorization reached upstream target: %q", upstreamProxyAuth)
	}

	time.Sleep(50 * time.Millisecond)
	flows, err := st.ListTraffic(context.Background(), 10)
	if err != nil {
		t.Fatalf("list traffic: %v", err)
	}
	if len(flows) == 0 || flows[0].ProxyUser != "alice" {
		t.Fatalf("expected captured flow attributed to alice, got %+v", flows)
	}
	headers, err := st.ListTrafficHeaders(context.Background(), flows[0].ID)
	if err != nil {
		t.Fatalf("list headers: %v", err)
	}
	for _, header := range headers {
		if header.Direction == "request" && http.CanonicalHeaderKey(header.Name) == "Proxy-Authorization" {
			t.Fatalf("captured Proxy-Authorization header: %+v", header)
		}
	}
}

func basicProxy(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}
