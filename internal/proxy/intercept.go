package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"mitm-proxy/internal/store"
	"mitm-proxy/internal/threats"
)

func (p *Proxy) interceptRequest(ctx context.Context, req *http.Request, requestID string) (bool, error) {
	if p.intercept == nil || !p.intercept.Enabled() {
		return false, nil
	}
	rule, ok, err := p.intercept.Check(ctx, store.BreakpointMatch{
		Direction:   "request",
		Method:      req.Method,
		URL:         req.URL.String(),
		Host:        req.URL.Host,
		ContentType: req.Header.Get("Content-Type"),
	})
	if err != nil || !ok {
		return false, err
	}
	body, err := sampleRequestBody(req, p.cfg().TrafficCapture.MaxBodyBytes)
	if err != nil {
		return false, err
	}
	if p.cfg().TrafficCapture.RedactBodies {
		body = redactBodyForCapture(body)
	}
	msg := store.InterceptMessage{
		Method:    req.Method,
		URL:       req.URL.String(),
		Host:      req.URL.Host,
		Status:    0,
		Headers:   cloneHeaderMap(req.Header),
		Body:      string(body),
		Protocol:  req.Proto,
		MIMEType:  req.Header.Get("Content-Type"),
		RemoteIP:  remoteIP(req.RemoteAddr),
		RuleID:    rule.ID,
		Direction: "request",
		RequestID: requestID,
		CreatedAt: time.Now().UTC(),
	}
	result, err := p.intercept.Submit(ctx, store.PendingIntercept{
		RequestID: requestID,
		RuleID:    rule.ID,
		Direction: "request",
		Original:  msg,
		Edited:    msg,
	})
	if err != nil {
		return false, err
	}
	if result.Action == "drop" {
		return true, nil
	}
	applyRequestMessage(req, result.Message)
	return false, nil
}

func (p *Proxy) interceptBufferedResponse(ctx context.Context, req *http.Request, resp *http.Response, body []byte, requestID string) ([]byte, bool, error) {
	if p.intercept == nil || !p.intercept.Enabled() || resp == nil {
		return body, false, nil
	}
	contentType := resp.Header.Get("Content-Type")
	rule, ok, err := p.intercept.Check(ctx, store.BreakpointMatch{
		Direction:   "response",
		Method:      req.Method,
		URL:         req.URL.String(),
		Host:        req.URL.Host,
		Status:      resp.StatusCode,
		ContentType: contentType,
	})
	if err != nil || !ok {
		return body, false, err
	}
	captured := body
	if max := p.cfg().TrafficCapture.MaxBodyBytes; max > 0 && int64(len(captured)) > max {
		return body, false, nil
	}
	if p.cfg().TrafficCapture.RedactBodies {
		captured = redactBodyForCapture(captured)
	}
	msg := store.InterceptMessage{
		Method:    req.Method,
		URL:       req.URL.String(),
		Host:      req.URL.Host,
		Status:    resp.StatusCode,
		Headers:   cloneHeaderMap(resp.Header),
		Body:      string(captured),
		Protocol:  resp.Proto,
		MIMEType:  contentType,
		RemoteIP:  remoteIP(req.RemoteAddr),
		RuleID:    rule.ID,
		Direction: "response",
		RequestID: requestID,
		CreatedAt: time.Now().UTC(),
	}
	result, err := p.intercept.Submit(ctx, store.PendingIntercept{
		RequestID: requestID,
		RuleID:    rule.ID,
		Direction: "response",
		Original:  msg,
		Edited:    msg,
	})
	if err != nil {
		return body, false, err
	}
	if result.Action == "drop" {
		return body, true, nil
	}
	applyResponseMessage(resp, result.Message)
	return []byte(result.Message.Body), false, nil
}

func (p *Proxy) interceptStreamingResponse(ctx context.Context, req *http.Request, resp *http.Response, requestID string) (bool, error) {
	if p.intercept == nil || !p.intercept.Enabled() || resp == nil || resp.Body == nil {
		return false, nil
	}
	limit := p.cfg().TrafficCapture.MaxBodyBytes
	if limit <= 0 {
		limit = 32768
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return false, err
	}
	if int64(len(buf)) > limit {
		resp.Body = struct {
			io.Reader
			io.Closer
		}{Reader: io.MultiReader(bytes.NewReader(buf), resp.Body), Closer: resp.Body}
		return false, nil
	}
	_ = resp.Body.Close()
	next, dropped, err := p.interceptBufferedResponse(ctx, req, resp, buf, requestID)
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(buf))
		return false, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(next))
	resp.ContentLength = int64(len(next))
	resp.Header.Set("Content-Length", strconv.Itoa(len(next)))
	return dropped, nil
}

func cloneHeaderMap(h http.Header) map[string][]string {
	out := map[string][]string{}
	for key, values := range h {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func applyRequestMessage(req *http.Request, msg store.InterceptMessage) {
	if msg.Method != "" {
		req.Method = strings.ToUpper(msg.Method)
	}
	if msg.Headers != nil {
		req.Header = http.Header(msg.Headers)
	}
	if msg.Body != "" {
		req.Body = io.NopCloser(strings.NewReader(msg.Body))
		req.ContentLength = int64(len(msg.Body))
	}
}

func applyResponseMessage(resp *http.Response, msg store.InterceptMessage) {
	if msg.Status != 0 {
		resp.StatusCode = msg.Status
		resp.Status = strconv.Itoa(msg.Status) + " " + http.StatusText(msg.Status)
	}
	if msg.Headers != nil {
		resp.Header = http.Header(msg.Headers)
	}
}

func redactBodyForCapture(body []byte) []byte {
	// The threat redactor is already used by traffic capture; keep intercept snapshots consistent.
	return threats.RedactBody(body)
}

func threatsFromPolicyString(reason string) threats.ThreatVerdict {
	return threats.ThreatVerdict{
		Threat:     true,
		Confidence: 1,
		Category:   "intercept",
		Reason:     reason,
		Action:     threats.ActionBlock,
		Signals:    []string{"intercept-drop"},
	}
}
