package access

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/store"
)

type fakeStore struct {
	users map[string]store.ProxyUser
	rules []store.ProxyACLRule
}

func (f *fakeStore) GetProxyUserByUsername(_ context.Context, username string) (store.ProxyUser, bool, error) {
	user, ok := f.users[username]
	return user, ok, nil
}

func (f *fakeStore) TouchProxyUserLastUsed(context.Context, string) error { return nil }

func (f *fakeStore) ListProxyACLRules(context.Context) ([]store.ProxyACLRule, error) {
	return f.rules, nil
}

func (f *fakeStore) MatchResearchScope(context.Context, string, string, string) (string, error) {
	return "", nil
}

func TestBasicAuthAndACLDecisions(t *testing.T) {
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	cfg := &cfgpkg.Config{ProxyAuth: cfgpkg.ProxyAuthConfig{Enabled: true, Realm: "Test", RequireAuthForLoopback: true, DefaultAction: "deny"}}
	fs := &fakeStore{
		users: map[string]store.ProxyUser{
			"alice": {ID: "u1", Username: "alice", PasswordHash: hash, Enabled: true},
			"bob":   {ID: "u2", Username: "bob", PasswordHash: hash, Enabled: false},
		},
		rules: []store.ProxyACLRule{
			{ID: "deny-post", Priority: 1, Enabled: true, Action: "deny", Name: "deny posts", MethodPatterns: []string{"POST"}},
			{ID: "allow-alice", Priority: 2, Enabled: true, Action: "allow", Name: "allow alice", Users: []string{"alice"}, HostPatterns: []string{"example.com"}},
		},
	}
	controller := NewController(func() *cfgpkg.Config { return cfg }, fs)

	missing := controller.Authorize(context.Background(), "", "192.0.2.1:4444", http.MethodGet, "http://example.com/")
	if missing.Allowed || !missing.AuthNeeded || missing.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected missing credentials to require auth: %+v", missing)
	}

	disabled := controller.Authorize(context.Background(), basic("bob", "secret"), "192.0.2.1:4444", http.MethodGet, "http://example.com/")
	if disabled.Allowed || !disabled.AuthNeeded {
		t.Fatalf("expected disabled user to be rejected: %+v", disabled)
	}

	allowed := controller.Authorize(context.Background(), basic("alice", "secret"), "192.0.2.1:4444", http.MethodGet, "http://example.com/")
	if !allowed.Allowed || allowed.RuleID != "allow-alice" || allowed.Username != "alice" {
		t.Fatalf("expected allow rule for alice: %+v", allowed)
	}

	denied := controller.Authorize(context.Background(), basic("alice", "secret"), "192.0.2.1:4444", http.MethodPost, "http://example.com/")
	if denied.Allowed || denied.RuleID != "deny-post" || denied.StatusCode != http.StatusForbidden {
		t.Fatalf("expected first matching deny rule: %+v", denied)
	}
}

func basic(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}
