package proxy

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"mitm-proxy/internal/events"
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
	p.publishTrafficStarted(requestID, req, "http/1.1")

	stripHopByHopHeaders(req.Header)

	if decision := p.checkPolicy(req.URL.Host); decision.Blocked {
		p.publishBlocked(requestID, req, decision.RuleID, decision.Reason)
		writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, threatsFromPolicy(decision))
		return
	}

	verdict, scanErr := p.scanRequest(r.Context(), req)
	if p.shouldBlock(verdict, scanErr) {
		writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
		return
	}
	p.prepareRequestForThreatResponseScan(req)

	// Try cache for GET
	if p.cache != nil && p.cache.ShouldConsider(req) {
		if cr, hashHex, err := p.cache.Load(req.URL); err == nil && cr != nil {
			p.publish(events.TopicCacheHit, map[string]any{"url": req.URL.String(), "cache_key": hashHex}, requestID)
			cachedResp := &http.Response{StatusCode: cr.Status, Header: cr.Header.Clone(), Body: io.NopCloser(strings.NewReader(""))}
			verdict, scanErr := p.scanBufferedResponse(r.Context(), req, cachedResp, cr.Body)
			if p.shouldBlock(verdict, scanErr) {
				writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
				return
			}

			for k, vals := range cr.Header {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}

			// Indicate response served via local cache
			w.Header().Set("Via", p.cfg().ProxyName)

			// Add UID header derived from proxy name containing the cache file hash
			uidHeader := p.makeCustomHeader("uid")

			w.Header().Set(uidHeader, hashHex)
			w.WriteHeader(cr.Status)
			n, _ := w.Write(cr.Body)
			dur := time.Since(start)

			p.logRequest("CACHE HIT HTTP %s %s -> status=%d, bytes=%d, dur=%s", r.Method, req.URL.String(), cr.Status, n, dur)
			p.publishTrafficCompleted(requestID, req, cr.Status, n, dur, true, cr.Header)

			return
		}
		p.publish(events.TopicCacheMiss, map[string]any{"url": req.URL.String()}, requestID)
	}

	resp, err := p.client.Do(req)

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
		verdict, scanErr := p.scanBufferedResponse(r.Context(), req, resp, bodyBuf)
		if p.shouldBlock(verdict, scanErr) {
			writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
			return
		}

		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}

		w.WriteHeader(resp.StatusCode)
		n, _ := w.Write(bodyBuf)
		p.cache.Save(req.URL, resp, bodyBuf)
		dur := time.Since(start)

		p.logRequest("HTTP %s %s -> status=%d, bytes=%d, dur=%s (cached)", r.Method, req.URL.String(), resp.StatusCode, n, dur)
		p.publishTrafficCompleted(requestID, req, resp.StatusCode, n, dur, false, resp.Header)

		return
	}

	// stream if not caching
	verdict, scanErr = p.prepareResponseForScan(r.Context(), req, resp)
	if p.shouldBlock(verdict, scanErr) {
		writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
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

	upstreamConn, err := net.DialTimeout("tcp", targetHost, 10*time.Second)

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

	go func() {
		defer clientConn.Close()
		defer upstreamConn.Close()

		io.Copy(upstreamConn, clientConn)
	}()

	go func() {
		defer clientConn.Close()
		defer upstreamConn.Close()

		io.Copy(clientConn, upstreamConn)
	}()
}
