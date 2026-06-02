package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
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

// mitmHTTPS11 handles HTTPS traffic where ALPN negotiated HTTP/1.1.
func (p *Proxy) mitmHTTPS11(clientTLS net.Conn, host, proxyUser, remoteAddr string) {
	reader := bufio.NewReader(clientTLS)

	for {
		req, err := http.ReadRequest(reader)

		if err != nil {
			if err != io.EOF {
				log.Printf("ReadRequest error for host %s: %v", host, err)
			}
			clientTLS.Close()

			return
		}

		if req.Method == "PRI" && req.URL.Path == "*" && req.ProtoMajor == 2 {
			p.logVerbose("Got HTTP/2 PRI preface on HTTP/1.1 path for %s; ignoring", host)

			continue
		}

		if isWebSocketRequest(req) {
			p.logVerbose("Detected wss:// WebSocket upgrade to %s", host)
			p.handleWebSocketHTTPS11(clientTLS, req, host, proxyUser, remoteAddr)

			return
		}

		start := time.Now()
		requestID := requestID(start)
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
		req.RemoteAddr = remoteAddr
		if proxyUser != "" {
			req = req.WithContext(access.WithUsername(req.Context(), proxyUser))
		}
		accessDecision := p.accessController().AuthorizeKnownUser(req.Context(), proxyUser, remoteAddr, req.Method, req.URL.String())
		if !accessDecision.Allowed {
			p.publishAccessDenied(req, accessDecision)
			blocked := accessBlockedResponse(p.cfg(), accessDecision)
			_ = blocked.Write(clientTLS)
			continue
		}

		stripHopByHopHeaders(req.Header)
		p.publishTrafficStarted(requestID, req, "https/1.1")

		if decision := p.checkPolicy(req.URL.Host); decision.Blocked {
			p.publishBlocked(requestID, req, decision.RuleID, decision.Reason)
			blocked := threatBlockedResponse(threatsFromPolicy(decision))
			_ = blocked.Write(clientTLS)
			continue
		}

		verdict, scanErr := p.scanRequest(req.Context(), req)
		if p.shouldBlock(verdict, scanErr) {
			blocked := threatBlockedResponse(verdict)
			_ = blocked.Write(clientTLS)
			continue
		}
		p.prepareRequestForThreatResponseScan(req)

		// Try cache for GET
		if p.cache != nil && p.cache.ShouldConsider(req) {
			if cr, hashHex, err := p.cache.LoadContext(req.Context(), req.URL); err == nil && cr != nil {
				p.publish(events.TopicCacheHit, map[string]any{"url": req.URL.String(), "cache_key": hashHex}, requestID)
				cachedResp := &http.Response{StatusCode: cr.Status, Header: cr.Header.Clone()}
				verdict, scanErr := p.scanBufferedResponse(req.Context(), req, cachedResp, cr.Body)
				if p.shouldBlock(verdict, scanErr) {
					blocked := threatBlockedResponse(verdict)
					_ = blocked.Write(clientTLS)
					continue
				}

				// write cached response directly to TLS conn
				hdr := make(http.Header)

				for k, vv := range cr.Header {
					for _, v := range vv {
						hdr.Add(k, v)
					}
				}

				// Indicate response served via local cache
				hdr.Set("Via", p.cfg().ProxyName)

				// Add UID header derived from proxy name containing the cache file hash
				uidHeader := p.makeCustomHeader("uid")
				hdr.Set(uidHeader, hashHex)

				cached := &http.Response{StatusCode: cr.Status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: hdr, Body: io.NopCloser(bytes.NewReader(cr.Body))}
				_ = cached.Write(clientTLS)

				p.logRequest("CACHE HIT HTTPS/1.1 %s %s -> status=%d, dur=%s", req.Method, req.URL.String(), cr.Status, time.Since(start))
				p.publishTrafficCompleted(requestID, req, cr.Status, len(cr.Body), time.Since(start), true, cr.Header)

				continue
			}
			p.publish(events.TopicCacheMiss, map[string]any{"url": req.URL.String()}, requestID)
		}

		resp, err := p.httpClient().Do(req)

		if err != nil {
			log.Printf("upstream HTTPS/1.1 error: %v", err)
			clientTLS.Close()

			return
		}

		if p.cache != nil && p.cache.ShouldConsider(req) {
			// read body fully to cache and write back
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			stripHopByHopHeaders(resp.Header)

			verdict, scanErr := p.scanBufferedResponse(req.Context(), req, resp, body)
			if p.shouldBlock(verdict, scanErr) {
				blocked := threatBlockedResponse(verdict)
				_ = blocked.Write(clientTLS)
				continue
			}

			// Construct response to write
			out := &http.Response{StatusCode: resp.StatusCode, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: resp.Header.Clone(), Body: io.NopCloser(bytes.NewReader(body))}

			if err := out.Write(clientTLS); err != nil {
				log.Printf("write to client error: %v", err)
				clientTLS.Close()

				return
			}

			p.cache.SaveContext(req.Context(), req.URL, resp, body)

			p.logRequest("HTTPS/1.1 %s %s -> status=%d, dur=%s (cached)", req.Method, req.URL.String(), resp.StatusCode, time.Since(start))
			p.publishTrafficCompleted(requestID, req, resp.StatusCode, len(body), time.Since(start), false, resp.Header)
		} else {
			p.logRequest("HTTPS/1.1 %s %s -> status=%d, dur=%s", req.Method, req.URL.String(), resp.StatusCode, time.Since(start))

			stripHopByHopHeaders(resp.Header)
			verdict, scanErr = p.prepareResponseForScan(req.Context(), req, resp)
			if p.shouldBlock(verdict, scanErr) {
				resp.Body.Close()
				blocked := threatBlockedResponse(verdict)
				_ = blocked.Write(clientTLS)
				continue
			}
			err = resp.Write(clientTLS)
			resp.Body.Close()

			if err != nil {
				log.Printf("write to client error: %v", err)

				clientTLS.Close()

				return
			}
			p.publishTrafficCompleted(requestID, req, resp.StatusCode, -1, time.Since(start), false, resp.Header)
		}
	}
}

// handleWebSocketHTTPS11 proxies a wss:// WebSocket over the established TLS MITM.
func (p *Proxy) handleWebSocketHTTPS11(clientTLS net.Conn, req *http.Request, host, proxyUser, remoteAddr string) {
	targetHost := req.URL.Host

	if targetHost == "" {
		if req.Host != "" {
			targetHost = req.Host
		} else {
			targetHost = host
		}
	}

	if !strings.Contains(targetHost, ":") {
		targetHost = net.JoinHostPort(targetHost, "443")
	}
	req.RemoteAddr = remoteAddr
	if proxyUser != "" {
		req = req.WithContext(access.WithUsername(req.Context(), proxyUser))
	}
	accessDecision := p.accessController().AuthorizeKnownUser(req.Context(), proxyUser, remoteAddr, req.Method, "https://"+targetHost+req.URL.RequestURI())
	if !accessDecision.Allowed {
		p.publishAccessDenied(req, accessDecision)
		blocked := accessBlockedResponse(p.cfg(), accessDecision)
		_ = blocked.Write(clientTLS)
		clientTLS.Close()
		return
	}
	req.Header.Del("Proxy-Authorization")

	rawUpstream, err := upstream.DialContext(req.Context(), p.cfg(), targetHost)

	if err != nil {
		log.Printf("wss upstream dial error: %v", err)

		clientTLS.Close()

		return
	}

	serverName := targetHost

	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		serverName = h
	}

	upstreamTLS := tls.Client(rawUpstream, &tls.Config{ServerName: serverName})

	if err := upstreamTLS.Handshake(); err != nil {
		log.Printf("wss upstream TLS handshake error: %v", err)

		upstreamTLS.Close()
		clientTLS.Close()

		return
	}

	if err := req.Write(upstreamTLS); err != nil {
		log.Printf("wss write request to upstream error: %v", err)

		upstreamTLS.Close()
		clientTLS.Close()

		return
	}

	upstreamReader := bufio.NewReader(upstreamTLS)
	resp, err := http.ReadResponse(upstreamReader, req)

	if err != nil {
		log.Printf("wss read response from upstream error: %v", err)

		upstreamTLS.Close()
		clientTLS.Close()

		return
	}

	// Ensure response body (typically empty for 101) is closed
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		log.Printf("wss upgrade failed: status=%d", resp.StatusCode)

		_ = resp.Write(clientTLS)
		upstreamTLS.Close()
		clientTLS.Close()

		return
	}

	if err := resp.Write(clientTLS); err != nil {
		log.Printf("wss write response to client error: %v", err)

		upstreamTLS.Close()
		clientTLS.Close()

		return
	}

	p.logVerbose("wss tunnel established %s <-> %s", clientTLS.RemoteAddr(), targetHost)
	p.publishTunnelOpened(targetHost, "wss", clientTLS.RemoteAddr().String())

	go func() {
		defer clientTLS.Close()
		defer upstreamTLS.Close()

		io.Copy(upstreamTLS, clientTLS)
	}()

	go func() {
		defer clientTLS.Close()
		defer upstreamTLS.Close()

		io.Copy(clientTLS, upstreamTLS)
	}()
}
