package proxy

import (
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"

	"mitm-proxy/internal/events"
)

// mitmHTTPS2 handles HTTPS traffic where ALPN negotiated HTTP/2.
func (p *Proxy) mitmHTTPS2(clientTLS net.Conn, host string) {
	defer clientTLS.Close()

	h2s := &http2.Server{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := requestID(start)

		req := r.Clone(r.Context())
		req = withTrafficID(req, requestID)
		req.RequestURI = ""

		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}

		if req.URL.Host == "" {
			if req.Host != "" {
				req.URL.Host = req.Host
			} else {
				req.URL.Host = host
			}
		}

		stripHopByHopHeaders(req.Header)
		p.publishTrafficStarted(requestID, req, "https/2")

		if decision := p.checkPolicy(req.URL.Host); decision.Blocked {
			p.publishBlocked(requestID, req, decision.RuleID, decision.Reason)
			writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, threatsFromPolicy(decision))
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
				cachedResp := &http.Response{StatusCode: cr.Status, Header: cr.Header.Clone()}
				verdict, scanErr := p.scanBufferedResponse(req.Context(), req, cachedResp, cr.Body)
				if p.shouldBlock(verdict, scanErr) {
					writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
					return
				}

				for k, vv := range cr.Header {
					for _, v := range vv {
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

				p.logRequest("CACHE HIT HTTPS/2 %s %s -> status=%d, bytes=%d, dur=%s", req.Method, req.URL.String(), cr.Status, n, time.Since(start))
				p.publishTrafficCompleted(requestID, req, cr.Status, n, time.Since(start), true, cr.Header)

				return
			}
			p.publish(events.TopicCacheMiss, map[string]any{"url": req.URL.String()}, requestID)
		}

		resp, err := p.httpClient().Do(req)

		if err != nil {
			p.logVerbose("upstream HTTPS/2 error: %v", err)

			http.Error(w, "upstream error", http.StatusBadGateway)

			return
		}

		defer resp.Body.Close()

		stripHopByHopHeaders(resp.Header)

		if p.cache != nil && p.cache.ShouldConsider(req) {
			body, _ := io.ReadAll(resp.Body)
			verdict, scanErr := p.scanBufferedResponse(req.Context(), req, resp, body)
			if p.shouldBlock(verdict, scanErr) {
				writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
				return
			}

			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}

			w.WriteHeader(resp.StatusCode)
			n, _ := w.Write(body)
			p.cache.SaveContext(req.Context(), req.URL, resp, body)

			p.logRequest("HTTPS/2 %s %s -> status=%d, bytes=%d, dur=%s (cached)", req.Method, req.URL.String(), resp.StatusCode, n, time.Since(start))
			p.publishTrafficCompleted(requestID, req, resp.StatusCode, n, time.Since(start), false, resp.Header)

			return
		}

		verdict, scanErr = p.prepareResponseForScan(req.Context(), req, resp)
		if p.shouldBlock(verdict, scanErr) {
			writeThreatBlockedResponse(w, p.cfg().BlockResponseStatus, verdict)
			return
		}

		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		w.WriteHeader(resp.StatusCode)
		n, _ := io.Copy(w, resp.Body)

		dur := time.Since(start)

		p.logRequest("HTTPS/2 %s %s -> status=%d, bytes=%d, dur=%s", req.Method, req.URL.String(), resp.StatusCode, n, dur)
		p.publishTrafficCompleted(requestID, req, resp.StatusCode, int(n), dur, false, resp.Header)
	})

	h2s.ServeConn(clientTLS, &http2.ServeConnOpts{Handler: handler})
}
