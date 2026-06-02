package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"mitm-proxy/internal/access"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/threats"
)

type trafficIDContextKey struct{}

func requestID(start time.Time) string {
	return fmt.Sprintf("%d", start.UnixNano())
}

func withTrafficID(req *http.Request, id string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), trafficIDContextKey{}, id))
}

func trafficID(ctx context.Context) string {
	if id, ok := ctx.Value(trafficIDContextKey{}).(string); ok {
		return id
	}
	return ""
}

func (p *Proxy) publishTrafficStarted(id string, req *http.Request, protocol string) {
	payload := map[string]any{
		"method":          req.Method,
		"url":             req.URL.String(),
		"host":            req.URL.Host,
		"protocol":        protocol,
		"remote_ip":       remoteIP(req.RemoteAddr),
		"request_headers": p.headerPayload(req.Header),
	}
	if username := access.Username(req.Context()); username != "" {
		payload["proxy_user"] = username
	}
	p.publish(events.TopicTrafficRequestStarted, payload, id)
}

func (p *Proxy) publishTrafficCompleted(id string, req *http.Request, statusCode int, bytes any, dur time.Duration, cacheHit bool, headers ...http.Header) {
	payload := map[string]any{
		"method":      req.Method,
		"url":         req.URL.String(),
		"host":        req.URL.Host,
		"status":      statusCode,
		"bytes":       bytes,
		"duration_ms": dur.Milliseconds(),
		"cache_hit":   cacheHit,
	}
	if len(headers) > 0 {
		payload["response_headers"] = p.headerPayload(headers[0])
		payload["mime_type"] = headers[0].Get("Content-Type")
	}
	if username := access.Username(req.Context()); username != "" {
		payload["proxy_user"] = username
	}
	p.publish(events.TopicTrafficResponseCompleted, payload, id)
}

func (p *Proxy) publishTunnelOpened(hostPort, protocol, remoteAddr string, usernames ...string) {
	payload := map[string]any{
		"target":    hostPort,
		"protocol":  protocol,
		"remote_ip": remoteIP(remoteAddr),
	}
	if len(usernames) > 0 && usernames[0] != "" {
		payload["proxy_user"] = usernames[0]
	}
	p.publish(events.TopicTrafficTunnelOpened, payload, "")
}

func (p *Proxy) publishBlocked(id string, req *http.Request, ruleID, reason string) {
	payload := map[string]any{
		"method":    req.Method,
		"url":       req.URL.String(),
		"host":      req.URL.Host,
		"rule_id":   ruleID,
		"reason":    reason,
		"remote_ip": remoteIP(req.RemoteAddr),
	}
	if username := access.Username(req.Context()); username != "" {
		payload["proxy_user"] = username
	}
	p.publish(events.TopicTrafficBlocked, payload, id)
}

func (p *Proxy) publishAccessDenied(req *http.Request, decision access.Decision) {
	targetURL := decision.Info.URL
	if targetURL == "" && req != nil && req.URL != nil {
		targetURL = req.URL.String()
	}
	host := decision.Info.Host
	if host == "" && req != nil && req.URL != nil {
		host = req.URL.Host
	}
	method := decision.Info.Method
	if method == "" && req != nil {
		method = req.Method
	}
	remote := decision.Info.RemoteIP
	if remote == "" && req != nil {
		remote = remoteIP(req.RemoteAddr)
	}
	p.publish(events.TopicTrafficBlocked, map[string]any{
		"method":     method,
		"url":        targetURL,
		"host":       host,
		"rule_id":    defaultString(decision.RuleID, "proxy_auth"),
		"reason":     decision.Reason,
		"remote_ip":  remote,
		"proxy_user": decision.Username,
		"status":     decision.StatusCode,
	}, "")
}

func (p *Proxy) headerPayload(headers http.Header) map[string]any {
	cfg := p.cfg().TrafficCapture
	if !cfg.StoreHeaders {
		return nil
	}
	out := make(map[string]any, len(headers))
	for name, values := range headers {
		if isCookieHeader(name) && !cfg.StoreCookies {
			continue
		}
		captured := append([]string(nil), values...)
		if stringListContainsFold(cfg.RedactedHeaders, name) {
			captured = redactedValues(captured)
		} else if isCookieHeader(name) && len(cfg.RedactedCookies) > 0 {
			captured = redactCookieHeaderValues(name, captured, cfg.RedactedCookies)
		}
		out[name] = captured
	}
	return out
}

func isCookieHeader(name string) bool {
	return strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Set-Cookie")
}

func redactedValues(values []string) []string {
	if len(values) == 0 {
		return []string{"[redacted]"}
	}
	out := make([]string, len(values))
	for i := range out {
		out[i] = "[redacted]"
	}
	return out
}

func redactCookieHeaderValues(headerName string, values []string, redactedCookies []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.EqualFold(headerName, "Set-Cookie") {
			out = append(out, redactSetCookieValue(value, redactedCookies))
			continue
		}
		out = append(out, redactCookieValue(value, redactedCookies))
	}
	return out
}

func redactCookieValue(value string, redactedCookies []string) string {
	parts := strings.Split(value, ";")
	for i, part := range parts {
		name, rest, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		if stringListContainsFold(redactedCookies, name) {
			prefix := ""
			if leading := leadingWhitespace(part); leading != "" {
				prefix = leading
			}
			parts[i] = prefix + name + "=[redacted]" + cookieSuffix(rest)
		}
	}
	return strings.Join(parts, ";")
}

func redactSetCookieValue(value string, redactedCookies []string) string {
	name, rest, ok := strings.Cut(strings.TrimSpace(value), "=")
	if !ok || !stringListContainsFold(redactedCookies, name) {
		return value
	}
	if semi := strings.Index(rest, ";"); semi >= 0 {
		return name + "=[redacted]" + rest[semi:]
	}
	return name + "=[redacted]"
}

func cookieSuffix(value string) string {
	if semi := strings.Index(value, ";"); semi >= 0 {
		return value[semi:]
	}
	return ""
}

func leadingWhitespace(value string) string {
	i := 0
	for i < len(value) && (value[i] == ' ' || value[i] == '\t') {
		i++
	}
	return value[:i]
}

func stringListContainsFold(values []string, candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "*" || strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func (p *Proxy) captureTrafficBody(ctx context.Context, direction string, body []byte) {
	cfg := p.cfg().TrafficCapture
	if !cfg.StoreBodies || len(body) == 0 {
		return
	}
	id := trafficID(ctx)
	if id == "" {
		return
	}

	captured := append([]byte(nil), body...)
	if cfg.MaxBodyBytes > 0 && int64(len(captured)) > cfg.MaxBodyBytes {
		captured = captured[:cfg.MaxBodyBytes]
	}
	if cfg.RedactBodies {
		captured = threats.RedactBody(captured)
	}

	p.publish(events.TopicTrafficBodyCaptured, map[string]any{
		"direction": direction,
		"body":      string(captured),
	}, id)
}
