package proxy

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"mitm-proxy/internal/access"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/upstream"
)

// isWebSocketRequest reports whether the request is a WS upgrade.
func isWebSocketRequest(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}

	conn := r.Header.Get("Connection")

	for _, part := range strings.Split(conn, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "upgrade") {
			return true
		}
	}

	return false
}

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func stripHopByHopHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, part := range strings.Split(c, ",") {
			if name := strings.TrimSpace(part); name != "" {
				h.Del(name)
			}
		}
	}

	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
}

// handleHTTP proxies plain HTTP and upgrades ws://
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.URL.String()
	if target == "" || r.URL.Host == "" {
		clone := *r.URL
		if clone.Scheme == "" {
			clone.Scheme = "http"
		}
		if clone.Host == "" {
			clone.Host = r.Host
		}
		target = clone.String()
	}
	decision := p.accessController().AuthorizeRequest(r, target)
	if !decision.Allowed {
		p.publishAccessDenied(r, decision)
		access.WriteDenied(w, p.cfg(), decision)
		return
	}
	if decision.Username != "" {
		r = r.WithContext(access.WithUsername(r.Context(), decision.Username))
	}

	if isWebSocketRequest(r) {
		p.handleWebSocketHTTP(w, r)

		return
	}

	start := time.Now()
	requestID := requestID(start)

	req := r.Clone(r.Context())
	req = withTrafficID(req, requestID)
	req.RequestURI = ""

	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}

	if req.URL.Host == "" {
		req.URL.Host = r.Host
	}

	stripHopByHopHeaders(req.Header)
	p.publishTrafficStarted(requestID, req, "http/1.1")
	effectiveCfg := p.effectiveConfigForRequest(req)

	if result := p.applyRequestFault(req.Context(), req, requestID); result.Handled {
		for k, vals := range result.Headers {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		if result.Status == 0 {
			result.Status = http.StatusServiceUnavailable
		}
		w.WriteHeader(result.Status)
		n, _ := w.Write(result.Body)
		if result.Rule.Action == "drop" {
			p.publishBlocked(requestID, req, result.Rule.ID, "dropped by fault injection")
		}
		p.publishTrafficCompleted(requestID, req, result.Status, n, time.Since(start), false, result.Headers)
		return
	}

	if decision := p.checkPolicyWithConfig(effectiveCfg, req.URL.Host); decision.Blocked {
		p.publishBlocked(requestID, req, decision.RuleID, decision.Reason)
		writeThreatBlockedResponse(w, effectiveCfg.BlockResponseStatus, threatsFromPolicy(decision))
		return
	}
	dropped, err := p.interceptRequest(req.Context(), req, requestID)
	if err != nil {
		http.Error(w, "intercept error", http.StatusBadGateway)
		return
	}
	if dropped {
		http.Error(w, "dropped by intercept", http.StatusForbidden)
		return
	}

	verdict, scanErr := p.scanRequest(req.Context(), req)
	if p.shouldBlock(verdict, scanErr) {
		writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
		return
	}
	p.prepareRequestForThreatResponseScan(req)

	// Try cache for GET
	if p.cache != nil && p.cache.ShouldConsider(req) {
		if cr, hashHex, err := p.cache.LoadContext(req.Context(), req.URL); err == nil && cr != nil {
			p.publish(events.TopicCacheHit, map[string]any{"url": req.URL.String(), "cache_key": hashHex}, requestID)
			cachedResp := &http.Response{StatusCode: cr.Status, Header: cr.Header.Clone(), Body: io.NopCloser(strings.NewReader(""))}
			cr.Body = p.applyBufferedResponseFault(req.Context(), req, cachedResp, cr.Body, requestID)
			verdict, scanErr := p.scanBufferedResponse(req.Context(), req, cachedResp, cr.Body)
			if p.shouldBlock(verdict, scanErr) {
				writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
				return
			}
			body := cr.Body
			body, dropped, err = p.interceptBufferedResponse(req.Context(), req, cachedResp, body, requestID)
			if err != nil {
				http.Error(w, "intercept error", http.StatusBadGateway)
				return
			}
			if dropped {
				http.Error(w, "dropped by intercept", http.StatusForbidden)
				return
			}

			for k, vals := range cachedResp.Header {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}

			// Indicate response served via local cache
			w.Header().Set("Via", p.cfg().ProxyName)

			// Add UID header derived from proxy name containing the cache file hash
			uidHeader := p.makeCustomHeader("uid")

			w.Header().Set(uidHeader, hashHex)
			w.WriteHeader(cachedResp.StatusCode)
			n, _ := w.Write(body)
			dur := time.Since(start)

			p.logRequest("CACHE HIT HTTP %s %s -> status=%d, bytes=%d, dur=%s", r.Method, req.URL.String(), cr.Status, n, dur)
			p.publishTrafficCompleted(requestID, req, cachedResp.StatusCode, n, dur, true, cachedResp.Header)

			return
		}
		p.publish(events.TopicCacheMiss, map[string]any{"url": req.URL.String()}, requestID)
	}

	resp, err := p.httpClientForConfig(effectiveCfg).Do(req)

	if err != nil {
		log.Printf("HTTP proxy error: %v", err)
		http.Error(w, "proxy error", http.StatusBadGateway)

		return
	}

	defer resp.Body.Close()

	stripHopByHopHeaders(resp.Header)

	var bodyBuf []byte

	if p.cache != nil && p.cache.ShouldConsider(req) {
		// read fully to cache
		bodyBuf, _ = io.ReadAll(resp.Body)
		bodyBuf = p.applyBufferedResponseFault(req.Context(), req, resp, bodyBuf, requestID)
		verdict, scanErr := p.scanBufferedResponse(req.Context(), req, resp, bodyBuf)
		if p.shouldBlock(verdict, scanErr) {
			writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
			return
		}
		bodyBuf, dropped, err = p.interceptBufferedResponse(req.Context(), req, resp, bodyBuf, requestID)
		if err != nil {
			http.Error(w, "intercept error", http.StatusBadGateway)
			return
		}
		if dropped {
			http.Error(w, "dropped by intercept", http.StatusForbidden)
			return
		}

		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}

		w.WriteHeader(resp.StatusCode)
		n, _ := w.Write(bodyBuf)
		p.cache.SaveContext(req.Context(), req.URL, resp, bodyBuf)
		dur := time.Since(start)

		p.logRequest("HTTP %s %s -> status=%d, bytes=%d, dur=%s (cached)", r.Method, req.URL.String(), resp.StatusCode, n, dur)
		p.publishTrafficCompleted(requestID, req, resp.StatusCode, n, dur, false, resp.Header)

		return
	}

	// stream if not caching
	verdict, scanErr = p.prepareResponseForScan(req.Context(), req, resp)
	if p.shouldBlock(verdict, scanErr) {
		writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
		return
	}
	p.wrapStreamingResponseFault(req.Context(), req, resp, requestID)
	dropped, err = p.interceptStreamingResponse(req.Context(), req, resp, requestID)
	if err != nil {
		http.Error(w, "intercept error", http.StatusBadGateway)
		return
	}
	if dropped {
		http.Error(w, "dropped by intercept", http.StatusForbidden)
		return
	}

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)

	dur := time.Since(start)

	p.logRequest("HTTP %s %s -> status=%d, bytes=%d, dur=%s", r.Method, req.URL.String(), resp.StatusCode, n, dur)
	p.publishTrafficCompleted(requestID, req, resp.StatusCode, n, dur, false, resp.Header)
}

// handleWebSocketHTTP establishes a transparent ws:// tunnel.
func (p *Proxy) handleWebSocketHTTP(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)

	if !ok {
		http.Error(w, "websocket proxy: hijacking not supported", http.StatusInternalServerError)

		return
	}

	clientConn, _, err := hj.Hijack()

	if err != nil {
		log.Printf("websocket hijack error: %v", err)

		return
	}

	targetHost := r.URL.Host

	if targetHost == "" {
		targetHost = r.Host
	}

	if !strings.Contains(targetHost, ":") {
		targetHost = net.JoinHostPort(targetHost, "80")
	}
	r.Header.Del("Proxy-Authorization")
	stripWebSocketCompression(r.Header)

	upstreamConn, err := upstream.DialContext(r.Context(), p.cfg(), targetHost)

	if err != nil {
		log.Printf("websocket upstream dial error: %v", err)

		clientConn.Close()

		return
	}

	if err := r.Write(upstreamConn); err != nil {
		log.Printf("websocket write request to upstream error: %v", err)

		clientConn.Close()
		upstreamConn.Close()

		return
	}

	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, r)

	if err != nil {
		log.Printf("websocket read response from upstream error: %v", err)

		clientConn.Close()
		upstreamConn.Close()

		return
	}

	// Ensure response body (usually empty for 101) is closed to avoid leaks
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		log.Printf("websocket upgrade failed: status=%d", resp.StatusCode)

		_ = resp.Write(clientConn)
		clientConn.Close()
		upstreamConn.Close()

		return
	}

	if err := resp.Write(clientConn); err != nil {
		log.Printf("websocket write response to client error: %v", err)

		clientConn.Close()
		upstreamConn.Close()

		return
	}

	p.logVerbose("ws tunnel established %s <-> %s", clientConn.RemoteAddr(), targetHost)
	rawURL := r.URL.String()
	if rawURL == "" {
		rawURL = "ws://" + targetHost + r.URL.RequestURI()
	}
	p.startWebSocketInspection(r.Context(), requestID(time.Now()), rawURL, targetHost, "ws", r.RemoteAddr, access.Username(r.Context()), clientConn, upstreamConn, upstreamReader)
}
