package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryTokenOnlyAuthenticatesReadRequests(t *testing.T) {
	handler := Middleware{Token: "admin-token", ReadToken: "read-token"}.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/traffic/export?token=admin-token", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected query token to authenticate GET, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/settings?token=admin-token", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected query token to be rejected for POST, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/settings", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected bearer token to authenticate POST, got %d", rr.Code)
	}
}

func TestReadTokenProxyACLTestRequiresBearerHeader(t *testing.T) {
	handler := Middleware{Token: "admin-token", ReadToken: "read-token"}.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/proxy-acl/test?token=read-token", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected read query token to be rejected for POST, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/proxy-acl/test", nil)
	req.Header.Set("Authorization", "Bearer read-token")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected read bearer token to authenticate ACL test, got %d", rr.Code)
	}
}
