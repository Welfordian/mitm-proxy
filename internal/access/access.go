package access

import (
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/store"

	"golang.org/x/crypto/bcrypt"
)

type ConfigProvider func() *cfgpkg.Config

type Store interface {
	GetProxyUserByUsername(context.Context, string) (store.ProxyUser, bool, error)
	TouchProxyUserLastUsed(context.Context, string) error
	ListProxyACLRules(context.Context) ([]store.ProxyACLRule, error)
	MatchResearchScope(context.Context, string, string, string) (string, error)
}

type Controller struct {
	cfg   ConfigProvider
	store Store
}

type RequestInfo struct {
	Method     string `json:"method"`
	URL        string `json:"url"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	RemoteIP   string `json:"remote_ip"`
	Username   string `json:"username,omitempty"`
	ScopeID    string `json:"scope_id,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	RuleName   string `json:"rule_name,omitempty"`
	Action     string `json:"action"`
	Reason     string `json:"reason"`
	AuthNeeded bool   `json:"auth_needed,omitempty"`
}

type Decision struct {
	Allowed    bool
	AuthNeeded bool
	Username   string
	UserID     string
	RuleID     string
	RuleName   string
	Reason     string
	StatusCode int
	Info       RequestInfo
}

type contextKey struct{}

func NewController(cfg ConfigProvider, store Store) *Controller {
	return &Controller{cfg: cfg, store: store}
}

func HashPassword(password string) (string, error) {
	password = strings.TrimSpace(password)
	if password == "" {
		return "", fmt.Errorf("password is required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func WithUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, contextKey{}, strings.TrimSpace(username))
}

func Username(ctx context.Context) string {
	if username, ok := ctx.Value(contextKey{}).(string); ok {
		return username
	}
	return ""
}

func (c *Controller) AuthorizeRequest(r *http.Request, target string) Decision {
	return c.Authorize(r.Context(), r.Header.Get("Proxy-Authorization"), r.RemoteAddr, r.Method, target)
}

func (c *Controller) AuthorizeKnownUser(ctx context.Context, username, remoteAddr, method, target string) Decision {
	return c.authorize(ctx, username, "", remoteAddr, method, target, false)
}

func (c *Controller) Authorize(ctx context.Context, proxyAuthorization, remoteAddr, method, target string) Decision {
	username, password, ok := parseBasicProxyAuth(proxyAuthorization)
	return c.authorize(ctx, username, password, remoteAddr, method, target, ok)
}

func (c *Controller) Test(ctx context.Context, username, remoteAddr, method, target, scopeID string) Decision {
	cfg := c.config()
	info := requestInfo(method, target, remoteAddr)
	info.Username = strings.TrimSpace(username)
	info.ScopeID = strings.TrimSpace(scopeID)
	if info.ScopeID == "" && c.store != nil {
		info.ScopeID, _ = c.store.MatchResearchScope(ctx, info.Method, info.URL, info.Host)
	}
	rule, matched, err := c.matchRule(ctx, info.Username, info)
	if err != nil {
		info.Action = "deny"
		info.Reason = err.Error()
		return Decision{Allowed: false, Username: info.Username, StatusCode: http.StatusForbidden, RuleID: "acl:error", Reason: info.Reason, Info: info}
	}
	action := strings.ToLower(strings.TrimSpace(cfg.ProxyAuth.DefaultAction))
	if action == "" {
		action = "deny"
	}
	if matched {
		action = rule.Action
		info.RuleID = rule.ID
		info.RuleName = rule.Name
	}
	info.Action = action
	info.Reason = "matched proxy ACL test"
	if !matched {
		info.Reason = "matched default proxy auth action"
	}
	return Decision{Allowed: action == "allow", Username: info.Username, RuleID: info.RuleID, RuleName: info.RuleName, Reason: info.Reason, Info: info}
}

func (c *Controller) authorize(ctx context.Context, username, password, remoteAddr, method, target string, hasCredentials bool) Decision {
	cfg := c.config()
	info := requestInfo(method, target, remoteAddr)
	if !cfg.ProxyAuth.Enabled || (!cfg.ProxyAuth.RequireAuthForLoopback && isLoopback(remoteAddr)) {
		info.Action = "allow"
		info.Reason = "proxy auth disabled or loopback exempt"
		info.Username = username
		return Decision{Allowed: true, Username: username, Info: info}
	}
	if c.store == nil {
		info.Action = "deny"
		info.Reason = "proxy auth store unavailable"
		return Decision{Allowed: false, StatusCode: http.StatusProxyAuthRequired, AuthNeeded: true, Reason: info.Reason, Info: info}
	}
	if !hasCredentials {
		info.Action = "deny"
		info.Reason = "proxy authentication required"
		info.AuthNeeded = true
		return Decision{Allowed: false, StatusCode: http.StatusProxyAuthRequired, AuthNeeded: true, Reason: info.Reason, Info: info}
	}
	user, ok, err := c.store.GetProxyUserByUsername(ctx, username)
	if err != nil || !ok || !user.Enabled || !CheckPassword(user.PasswordHash, password) {
		info.Action = "deny"
		info.Reason = "invalid proxy credentials"
		info.AuthNeeded = true
		return Decision{Allowed: false, StatusCode: http.StatusProxyAuthRequired, AuthNeeded: true, Reason: info.Reason, Info: info}
	}
	info.Username = user.Username
	scopeID, _ := c.store.MatchResearchScope(ctx, method, info.URL, info.Host)
	info.ScopeID = scopeID
	rule, matched, err := c.matchRule(ctx, user.Username, info)
	if err != nil {
		info.Action = "deny"
		info.Reason = err.Error()
		return Decision{Allowed: false, Username: user.Username, UserID: user.ID, StatusCode: http.StatusForbidden, RuleID: "acl:error", Reason: info.Reason, Info: info}
	}
	action := strings.ToLower(strings.TrimSpace(cfg.ProxyAuth.DefaultAction))
	if action == "" {
		action = "deny"
	}
	if matched {
		action = rule.Action
		info.RuleID = rule.ID
		info.RuleName = rule.Name
	}
	info.Action = action
	if action == "allow" {
		_ = c.store.TouchProxyUserLastUsed(ctx, user.ID)
		info.Reason = "allowed by proxy ACL"
		if !matched {
			info.Reason = "allowed by default proxy auth action"
		}
		return Decision{Allowed: true, Username: user.Username, UserID: user.ID, RuleID: info.RuleID, RuleName: info.RuleName, Reason: info.Reason, Info: info}
	}
	info.Reason = "denied by proxy ACL"
	if !matched {
		info.Reason = "denied by default proxy auth action"
	}
	return Decision{Allowed: false, Username: user.Username, UserID: user.ID, StatusCode: http.StatusForbidden, RuleID: defaultString(info.RuleID, "proxy_acl:default"), RuleName: info.RuleName, Reason: info.Reason, Info: info}
}

func (c *Controller) matchRule(ctx context.Context, username string, info RequestInfo) (store.ProxyACLRule, bool, error) {
	rules, err := c.store.ListProxyACLRules(ctx)
	if err != nil {
		return store.ProxyACLRule{}, false, err
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if ruleMatches(rule, username, info) {
			return rule, true, nil
		}
	}
	return store.ProxyACLRule{}, false, nil
}

func ruleMatches(rule store.ProxyACLRule, username string, info RequestInfo) bool {
	return stringListMatches(rule.Users, username, false) &&
		ipListMatches(rule.SourceIPs, info.RemoteIP) &&
		hostListMatches(rule.HostPatterns, info.Host) &&
		portListMatches(rule.PortPatterns, info.Port) &&
		stringListMatches(rule.MethodPatterns, info.Method, true) &&
		scopeListMatches(rule.ScopeIDs, info.ScopeID)
}

func requestInfo(method, target, remoteAddr string) RequestInfo {
	host := target
	rawURL := target
	port := 0
	if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
		host = parsed.Hostname()
		rawURL = parsed.String()
		if parsed.Port() != "" {
			port, _ = strconv.Atoi(parsed.Port())
		} else if parsed.Scheme == "https" {
			port = 443
		} else if parsed.Scheme == "http" {
			port = 80
		}
	} else {
		if strings.Contains(target, ":") {
			if h, p, err := net.SplitHostPort(target); err == nil {
				host = h
				port, _ = strconv.Atoi(p)
			}
		}
	}
	return RequestInfo{
		Method:   strings.ToUpper(strings.TrimSpace(method)),
		URL:      rawURL,
		Host:     strings.ToLower(strings.Trim(host, "[]")),
		Port:     port,
		RemoteIP: remoteIP(remoteAddr),
	}
}

func (c *Controller) config() *cfgpkg.Config {
	if c != nil && c.cfg != nil {
		if cfg := c.cfg(); cfg != nil {
			return cfg
		}
	}
	return &cfgpkg.Config{}
}

func parseBasicProxyAuth(header string) (string, string, bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(header, prefix)))
	if err != nil {
		return "", "", false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok || strings.TrimSpace(username) == "" {
		return "", "", false
	}
	return username, password, true
}

func WriteDenied(w http.ResponseWriter, cfg *cfgpkg.Config, decision Decision) {
	status, body := DeniedPageHTML(cfg, decision)
	if decision.AuthNeeded || decision.StatusCode == http.StatusProxyAuthRequired {
		realm := "MITM Proxy"
		if cfg != nil && strings.TrimSpace(cfg.ProxyAuth.Realm) != "" {
			realm = cfg.ProxyAuth.Realm
		}
		w.Header().Set("Proxy-Authenticate", `Basic realm="`+realm+`"`)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func DeniedPageHTML(cfg *cfgpkg.Config, decision Decision) (int, string) {
	status := decision.StatusCode
	if decision.AuthNeeded || status == http.StatusProxyAuthRequired {
		status = http.StatusProxyAuthRequired
	} else if status == 0 {
		status = http.StatusForbidden
	}
	title := "Request blocked"
	eyebrow := "Proxy access control"
	summary := "This request was stopped by the proxy before it reached the destination."
	if status == http.StatusProxyAuthRequired {
		title = "Proxy authentication required"
		eyebrow = "Authentication required"
		summary = "Sign in with a proxy username and password to continue through this proxy."
	}
	realm := "MITM Proxy"
	if cfg != nil && strings.TrimSpace(cfg.ProxyAuth.Realm) != "" {
		realm = cfg.ProxyAuth.Realm
	}
	reason := displayString(decision.Reason, "No matching access rule allowed this request.")
	rule := displayString(decision.RuleName, decision.RuleID)
	if strings.TrimSpace(rule) == "" {
		rule = "default policy"
	}
	user := displayString(decision.Username, "not authenticated")
	host := displayString(decision.Info.Host, "unknown host")
	method := displayString(decision.Info.Method, "unknown")
	remoteIP := displayString(decision.Info.RemoteIP, "unknown client")

	return status, fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>%s</title>
  <style>
    :root {
      color-scheme: light;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f5f7fb;
      color: #111827;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 32px 18px;
      background:
        linear-gradient(135deg, rgba(255,255,255,.92), rgba(245,247,251,.9)),
        radial-gradient(circle at 18%% 10%%, rgba(14, 165, 233, .16), transparent 28rem),
        radial-gradient(circle at 82%% 14%%, rgba(239, 68, 68, .12), transparent 24rem);
    }
    main {
      width: min(860px, 100%%);
      overflow: hidden;
      border: 1px solid #dbe3ef;
      border-radius: 14px;
      background: rgba(255,255,255,.96);
      box-shadow: 0 26px 90px rgba(15, 23, 42, .14);
    }
    .hero {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 18px;
      align-items: center;
      padding: 30px 32px 26px;
      border-bottom: 1px solid #e5ebf3;
      background: linear-gradient(180deg, #ffffff, #f8fbff);
    }
    .mark {
      width: 52px;
      height: 52px;
      display: grid;
      place-items: center;
      border-radius: 14px;
      background: #0f172a;
      color: #ffffff;
      font-size: 28px;
      font-weight: 800;
      box-shadow: inset 0 -10px 18px rgba(255,255,255,.08);
    }
    .eyebrow {
      margin: 0 0 8px;
      color: #0f766e;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: .08em;
      text-transform: uppercase;
    }
    h1 {
      margin: 0;
      font-size: clamp(28px, 5vw, 42px);
      line-height: 1.05;
      letter-spacing: 0;
    }
    .summary {
      margin: 10px 0 0;
      color: #536173;
      font-size: 16px;
      line-height: 1.55;
    }
    .content {
      padding: 28px 32px 32px;
    }
    .reason {
      border: 1px solid #fecaca;
      border-left: 5px solid #dc2626;
      border-radius: 12px;
      padding: 17px 18px;
      background: #fff7f7;
    }
    .reason strong {
      display: block;
      margin-bottom: 6px;
      color: #991b1b;
      font-size: 14px;
    }
    .reason p {
      margin: 0;
      color: #334155;
      line-height: 1.55;
      overflow-wrap: anywhere;
    }
    .facts {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-top: 18px;
    }
    .fact {
      min-width: 0;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 14px 15px;
      background: #fbfdff;
    }
    .label {
      display: block;
      margin-bottom: 6px;
      color: #64748b;
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }
    .value {
      display: block;
      color: #0f172a;
      font-size: 15px;
      font-weight: 700;
      overflow-wrap: anywhere;
    }
    .footer {
      margin: 20px 0 0;
      color: #64748b;
      font-size: 13px;
      line-height: 1.5;
    }
    @media (max-width: 680px) {
      body { padding: 0; place-items: stretch; }
      main { min-height: 100vh; border-radius: 0; border-left: 0; border-right: 0; }
      .hero { grid-template-columns: 1fr; }
      .hero, .content { padding-left: 22px; padding-right: 22px; }
      .facts { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="mark">!</div>
      <div>
        <p class="eyebrow">%s</p>
        <h1>%s</h1>
        <p class="summary">%s</p>
      </div>
    </section>
    <section class="content">
      <div class="reason">
        <strong>Decision</strong>
        <p>%s</p>
      </div>
      <div class="facts">
        <div class="fact"><span class="label">HTTP status</span><span class="value">%d</span></div>
        <div class="fact"><span class="label">Realm</span><span class="value">%s</span></div>
        <div class="fact"><span class="label">Rule</span><span class="value">%s</span></div>
        <div class="fact"><span class="label">User</span><span class="value">%s</span></div>
        <div class="fact"><span class="label">Target</span><span class="value">%s %s</span></div>
        <div class="fact"><span class="label">Client</span><span class="value">%s</span></div>
      </div>
      <p class="footer">Review the Access Control page in the admin dashboard to inspect users, ACL rules, and blocked traffic records.</p>
    </section>
  </main>
</body>
</html>`,
		html.EscapeString(title),
		html.EscapeString(eyebrow),
		html.EscapeString(title),
		html.EscapeString(summary),
		html.EscapeString(reason),
		status,
		html.EscapeString(realm),
		html.EscapeString(rule),
		html.EscapeString(user),
		html.EscapeString(method),
		html.EscapeString(host),
		html.EscapeString(remoteIP),
	)
}

func displayString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return strings.TrimSpace(fallback)
	}
	return value
}

func stringListMatches(values []string, candidate string, upper bool) bool {
	if len(values) == 0 {
		return true
	}
	candidate = strings.TrimSpace(candidate)
	if upper {
		candidate = strings.ToUpper(candidate)
	}
	for _, value := range values {
		if upper {
			value = strings.ToUpper(strings.TrimSpace(value))
		}
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return true
		}
	}
	return false
}

func scopeListMatches(values []string, scopeID string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "__out_of_scope__" && strings.TrimSpace(scopeID) == "" {
			return true
		}
		if value == scopeID {
			return true
		}
	}
	return false
}

func hostListMatches(patterns []string, host string) bool {
	if len(patterns) == 0 {
		return true
	}
	host = strings.ToLower(strings.Trim(host, ".[]"))
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if strings.HasPrefix(pattern, "*.") {
			base := strings.TrimPrefix(pattern, "*.")
			if host == base || strings.HasSuffix(host, "."+base) {
				return true
			}
			continue
		}
		if host == strings.Trim(pattern, ".[]") {
			return true
		}
	}
	return false
}

func ipListMatches(patterns []string, remoteIP string) bool {
	if len(patterns) == 0 {
		return true
	}
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return false
	}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if _, cidr, err := net.ParseCIDR(pattern); err == nil && cidr.Contains(ip) {
			return true
		}
		if parsed := net.ParseIP(pattern); parsed != nil && parsed.Equal(ip) {
			return true
		}
	}
	return false
}

func portListMatches(patterns []string, port int) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if strings.Contains(pattern, "-") {
			startText, endText, ok := strings.Cut(pattern, "-")
			if !ok {
				continue
			}
			start, startErr := strconv.Atoi(strings.TrimSpace(startText))
			end, endErr := strconv.Atoi(strings.TrimSpace(endText))
			if startErr == nil && endErr == nil && port >= start && port <= end {
				return true
			}
			continue
		}
		if parsed, err := strconv.Atoi(pattern); err == nil && parsed == port {
			return true
		}
	}
	return false
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return strings.Trim(host, "[]")
}

func isLoopback(remoteAddr string) bool {
	ip := net.ParseIP(remoteIP(remoteAddr))
	return ip != nil && ip.IsLoopback()
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func Now() time.Time {
	return time.Now().UTC()
}
