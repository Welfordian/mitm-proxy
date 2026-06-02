package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/store"
)

func TestProxyAccessAdminRoutes(t *testing.T) {
	st := openAdminTestStore(t)
	cfg := &cfgpkg.Config{ProxyAuth: cfgpkg.ProxyAuthConfig{Enabled: true, Realm: "Test", RequireAuthForLoopback: true, DefaultAction: "deny"}}
	s := New(Options{
		Token:     "admin-token",
		ReadToken: "read-token",
		Store:     st,
		Config:    func() *cfgpkg.Config { return cfg },
	})

	userData := postJSONForTest(t, s, "/api/proxy-auth/users", map[string]any{"username": "alice", "password": "secret", "enabled": true})
	if strings.Contains(string(userData), "secret") || strings.Contains(string(userData), "password_hash") {
		t.Fatalf("proxy user response leaked secret material: %s", string(userData))
	}
	var user store.ProxyUser
	if err := json.Unmarshal(userData, &user); err != nil {
		t.Fatalf("decode user: %v", err)
	}
	if user.Username != "alice" || !user.Enabled {
		t.Fatalf("unexpected user: %+v", user)
	}

	ruleData := postJSONForTest(t, s, "/api/proxy-acl/rules", map[string]any{
		"priority":      1,
		"enabled":       true,
		"action":        "allow",
		"name":          "allow alice",
		"users":         []string{"alice"},
		"host_patterns": []string{"example.com"},
	})
	var rule store.ProxyACLRule
	if err := json.Unmarshal(ruleData, &rule); err != nil {
		t.Fatalf("decode rule: %v", err)
	}
	if rule.Action != "allow" {
		t.Fatalf("unexpected rule: %+v", rule)
	}

	testData := postJSONForTest(t, s, "/api/proxy-acl/test", map[string]any{"username": "alice", "remote_ip": "192.0.2.1", "method": "GET", "url": "http://example.com/"})
	var result map[string]any
	if err := json.Unmarshal(testData, &result); err != nil {
		t.Fatalf("decode test result: %v", err)
	}
	if result["allowed"] != true || result["rule_id"] != rule.ID {
		t.Fatalf("unexpected ACL test result: %+v", result)
	}

	readReq := httptest.NewRequest(http.MethodPost, "/api/proxy-auth/users", strings.NewReader(`{"username":"bob","password":"secret"}`))
	readReq.Header.Set("Authorization", "Bearer read-token")
	readReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, readReq)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("read token should not create proxy user, got %d", rr.Code)
	}

	readTest := httptest.NewRequest(http.MethodPost, "/api/proxy-acl/test", strings.NewReader(`{"username":"alice","url":"http://example.com/"}`))
	readTest.Header.Set("Authorization", "Bearer read-token")
	readTest.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, readTest)
	if rr.Code != http.StatusOK {
		t.Fatalf("read token should run ACL test, got %d: %s", rr.Code, rr.Body.String())
	}
}
