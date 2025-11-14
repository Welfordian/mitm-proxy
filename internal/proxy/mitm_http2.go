package proxy

import (
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// mitmHTTPS2 handles HTTPS traffic where ALPN negotiated HTTP/2.
func (p *Proxy) mitmHTTPS2(clientTLS net.Conn, host string) {
	defer clientTLS.Close()

	h2s := &http2.Server{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		req := r.Clone(r.Context())
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

		// Try cache for GET
		if p.cache != nil && p.cache.ShouldConsider(req) {
			if cr, hashHex, err := p.cache.Load(req.URL); err == nil && cr != nil {
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

				return
			}
		}

		resp, err := p.client.Do(req)

		if err != nil {
			p.logVerbose("upstream HTTPS/2 error: %v", err)

			http.Error(w, "upstream error", http.StatusBadGateway)

			return
		}

		defer resp.Body.Close()

		stripHopByHopHeaders(resp.Header)

		if p.cache != nil && p.cache.ShouldConsider(req) {
			body, _ := io.ReadAll(resp.Body)

			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}

			w.WriteHeader(resp.StatusCode)
			n, _ := w.Write(body)
			p.cache.Save(req.URL, resp, body)

			p.logRequest("HTTPS/2 %s %s -> status=%d, bytes=%d, dur=%s (cached)", req.Method, req.URL.String(), resp.StatusCode, n, time.Since(start))

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
	})

	h2s.ServeConn(clientTLS, &http2.ServeConnOpts{Handler: handler})
}
