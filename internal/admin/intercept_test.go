package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInterceptReadOnlyTokenCannotMutate(t *testing.T) {
	st := openAdminTestStore(t)
	s := newTestServer(st)
	req := httptest.NewRequest(http.MethodPost, "/api/intercept/rules", strings.NewReader(`{"name":"rule"}`))
	req.Header.Set("Authorization", "Bearer read-token")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("read token should not create intercept rules, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/intercept/pending/missing/drop", nil)
	req.Header.Set("Authorization", "Bearer read-token")
	rr = httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("read token should not drop pending intercepts, got %d", rr.Code)
	}
}
