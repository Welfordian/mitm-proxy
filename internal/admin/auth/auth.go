package auth

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
)

type Middleware struct {
	Token     string
	ReadToken string
}

func (m Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.Token == "" && isLoopback(r.RemoteAddr) {
			next.ServeHTTP(w, r)
			return
		}

		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		if m.Token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(m.Token)) == 1 {
			r.Header.Set("X-Admin-Role", "admin")
			next.ServeHTTP(w, r)
			return
		}

		if m.ReadToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(m.ReadToken)) == 1 && isReadOnly(r) {
			r.Header.Set("X-Admin-Role", "read")
			next.ServeHTTP(w, r)
			return
		}

		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func isReadOnly(r *http.Request) bool {
	if r.Method == http.MethodPost && r.URL.Path == "/api/proxy-acl/test" {
		return true
	}
	return r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
