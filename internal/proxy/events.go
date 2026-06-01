package proxy

import (
	"context"
	"fmt"
	"net/http"
	"time"

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
	p.publish(events.TopicTrafficRequestStarted, map[string]any{
		"method":          req.Method,
		"url":             req.URL.String(),
		"host":            req.URL.Host,
		"protocol":        protocol,
		"remote_ip":       remoteIP(req.RemoteAddr),
		"request_headers": headerPayload(req.Header),
	}, id)
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
		payload["response_headers"] = headerPayload(headers[0])
		payload["mime_type"] = headers[0].Get("Content-Type")
	}
	p.publish(events.TopicTrafficResponseCompleted, payload, id)
}

func (p *Proxy) publishTunnelOpened(hostPort, protocol, remoteAddr string) {
	p.publish(events.TopicTrafficTunnelOpened, map[string]any{
		"target":    hostPort,
		"protocol":  protocol,
		"remote_ip": remoteIP(remoteAddr),
	}, "")
}

func (p *Proxy) publishBlocked(id string, req *http.Request, ruleID, reason string) {
	p.publish(events.TopicTrafficBlocked, map[string]any{
		"method":  req.Method,
		"url":     req.URL.String(),
		"host":    req.URL.Host,
		"rule_id": ruleID,
		"reason":  reason,
	}, id)
}

func headerPayload(headers http.Header) map[string]any {
	out := make(map[string]any, len(headers))
	for name, values := range headers {
		out[name] = append([]string(nil), values...)
	}
	return out
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
