package store

import (
	"context"
	"testing"
)

func TestProxyAccessMigrationAndCRUD(t *testing.T) {
	st, err := Open(t.TempDir() + "/dashboard.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	for _, table := range []string{"proxy_users", "proxy_acl_rules"} {
		var name string
		if err := st.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name); err != nil {
			t.Fatalf("expected table %s: %v", table, err)
		}
	}
	var proxyUserColumn string
	if err := st.db.QueryRowContext(ctx, `SELECT name FROM pragma_table_info('traffic_flows') WHERE name='proxy_user'`).Scan(&proxyUserColumn); err != nil {
		t.Fatalf("expected traffic proxy_user column: %v", err)
	}

	user, err := st.CreateProxyUser(ctx, ProxyUser{Username: "alice", PasswordHash: "hash", Enabled: true})
	if err != nil {
		t.Fatalf("create proxy user: %v", err)
	}
	user.Enabled = false
	updatedUser, err := st.UpdateProxyUser(ctx, user)
	if err != nil {
		t.Fatalf("update proxy user: %v", err)
	}
	if updatedUser.Enabled {
		t.Fatalf("expected disabled user: %+v", updatedUser)
	}
	resetUser, err := st.ResetProxyUserPassword(ctx, user.ID, "new-hash")
	if err != nil {
		t.Fatalf("reset proxy user password: %v", err)
	}
	if resetUser.PasswordHash != "new-hash" {
		t.Fatalf("expected new password hash, got %+v", resetUser)
	}

	rule, err := st.CreateProxyACLRule(ctx, ProxyACLRule{
		Priority:       10,
		Enabled:        true,
		Action:         "allow",
		Name:           "allow alice",
		Users:          []string{"alice"},
		HostPatterns:   []string{"example.com"},
		PortPatterns:   []string{"443"},
		MethodPatterns: []string{"get"},
	})
	if err != nil {
		t.Fatalf("create proxy acl rule: %v", err)
	}
	if rule.MethodPatterns[0] != "GET" {
		t.Fatalf("expected normalized method, got %+v", rule)
	}
	rule.Priority = 5
	updatedRule, err := st.UpdateProxyACLRule(ctx, rule)
	if err != nil {
		t.Fatalf("update proxy acl rule: %v", err)
	}
	if updatedRule.Priority != 5 {
		t.Fatalf("expected updated priority, got %+v", updatedRule)
	}
	if err := st.DeleteProxyACLRule(ctx, rule.ID); err != nil {
		t.Fatalf("delete proxy acl rule: %v", err)
	}
	if err := st.DeleteProxyUser(ctx, user.ID); err != nil {
		t.Fatalf("delete proxy user: %v", err)
	}
}
