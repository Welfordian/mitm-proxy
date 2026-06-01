package proxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"mitm-proxy/internal/events"
)

// tunnelTCP relays raw bytes between client and target.
func tunnelTCP(clientConn net.Conn, target string, p *Proxy) {
	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)

	if err != nil {
		log.Printf("CONNECT tunnel dial error to %s: %v", target, err)

		clientConn.Close()

		return
	}

	p.logVerbose("CONNECT tunnel %s <-> %s", clientConn.RemoteAddr(), target)

	go func() {
		defer clientConn.Close()
		defer upstream.Close()

		io.Copy(upstream, clientConn)
	}()

	go func() {
		defer clientConn.Close()
		defer upstream.Close()

		io.Copy(clientConn, upstream)
	}()
}

// handleConnect processes CONNECT requests and decides between tunneling and MITM.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host

	if !strings.Contains(hostPort, ":") {
		hostPort = net.JoinHostPort(hostPort, "443")
	}

	host, port, err := net.SplitHostPort(hostPort)

	if err != nil {
		http.Error(w, "invalid CONNECT host", http.StatusBadRequest)

		return
	}

	if decision := p.checkPolicy(hostPort); decision.Blocked {
		p.publish(events.TopicTrafficBlocked, map[string]any{
			"method":  r.Method,
			"target":  hostPort,
			"rule_id": decision.RuleID,
			"reason":  decision.Reason,
		}, "")
		http.Error(w, decision.Reason, p.cfg().BlockResponseStatus)
		return
	}

	hj, ok := w.(http.Hijacker)

	if !ok {
		http.Error(w, "proxy does not support hijacking", http.StatusInternalServerError)

		return
	}

	clientConn, buf, err := hj.Hijack()

	if err != nil {
		log.Printf("hijack error: %v", err)

		return
	}
	_ = buf

	// Inform client that the tunnel is established
	if _, err = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("write 200 Connection Established failed: %v", err)

		clientConn.Close()

		return
	}

	if p.cfg().IsDomainExcluded(host) {
		p.logVerbose("Domain %s is excluded, using plain tunnel", host)
		p.publishTunnelOpened(hostPort, "connect", r.RemoteAddr)

		go tunnelTCP(clientConn, hostPort, p)

		return
	}

	if port != "443" {
		p.publishTunnelOpened(hostPort, "connect", r.RemoteAddr)
		go tunnelTCP(clientConn, hostPort, p)

		return
	}

	if !p.cfg().EnableMITM {
		p.logVerbose("MITM disabled, using plain tunnel for %s", hostPort)
		p.publishTunnelOpened(hostPort, "connect", r.RemoteAddr)

		go tunnelTCP(clientConn, hostPort, p)

		return
	}

	cert, err := p.getCertForHost(host)

	if err != nil {
		log.Printf("getCertForHost(%q) error: %v", host, err)

		clientConn.Close()

		return
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   p.cfg().GetTLSVersion(),
		NextProtos:   p.cfg().TLSNextProtos,
	})

	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake with client failed: %v", err)

		tlsConn.Close()

		return
	}

	state := tlsConn.ConnectionState()

	p.logVerbose("Established TLS MITM for %s:%s, ALPN=%q", host, port, state.NegotiatedProtocol)

	switch state.NegotiatedProtocol {
	case "h2":
		p.mitmHTTPS2(tlsConn, host)
	default:
		p.mitmHTTPS11(tlsConn, host)
	}
}
