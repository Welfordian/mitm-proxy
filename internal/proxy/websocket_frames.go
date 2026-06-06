package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"mitm-proxy/internal/events"
	"mitm-proxy/internal/store"
	"mitm-proxy/internal/threats"
)

type wsFrame struct {
	Fin     bool
	Opcode  int
	Payload []byte
}

func (p *Proxy) startWebSocketInspection(ctx context.Context, id, rawURL, host, protocol, remoteAddr, proxyUser string, client net.Conn, upstream net.Conn, upstreamReader *bufio.Reader) {
	if p.ws == nil {
		go proxyCopy(upstream, client)
		go proxyCopy(client, upstream)
		return
	}
	conn := p.ws.Create(ctx, store.WebSocketConnection{
		ID:        id,
		CreatedAt: time.Now().UTC(),
		URL:       rawURL,
		Host:      host,
		Protocol:  protocol,
		RemoteIP:  remoteIP(remoteAddr),
		ProxyUser: proxyUser,
	})
	p.publish(events.TopicWebSocketConnection, map[string]any{"id": conn.ID, "url": conn.URL, "host": conn.Host, "protocol": conn.Protocol}, "")
	var writeClientMu sync.Mutex
	var writeUpstreamMu sync.Mutex
	p.ws.Register(conn.ID, func(direction string, opcode int, payload []byte) error {
		switch direction {
		case "server_to_client":
			writeClientMu.Lock()
			defer writeClientMu.Unlock()
			return writeWSFrame(client, opcode, payload, false)
		default:
			writeUpstreamMu.Lock()
			defer writeUpstreamMu.Unlock()
			return writeWSFrame(upstream, opcode, payload, true)
		}
	})
	go func() {
		defer client.Close()
		defer upstream.Close()
		defer p.ws.Unregister(conn.ID)
		defer p.ws.Close(context.Background(), conn.ID)
		p.relayWSFrames(ctx, conn.ID, "client_to_server", bufio.NewReader(client), upstream, true, &writeUpstreamMu)
	}()
	go func() {
		defer client.Close()
		defer upstream.Close()
		reader := upstreamReader
		if reader == nil {
			reader = bufio.NewReader(upstream)
		}
		p.relayWSFrames(ctx, conn.ID, "server_to_client", reader, client, false, &writeClientMu)
	}()
}

func (p *Proxy) relayWSFrames(ctx context.Context, connectionID, direction string, reader *bufio.Reader, dst io.Writer, maskOut bool, writeMu *sync.Mutex) {
	for {
		frame, err := readWSFrame(reader)
		if err != nil {
			return
		}
		p.recordWSFrame(ctx, connectionID, direction, frame)
		writeMu.Lock()
		err = writeWSFrame(dst, frame.Opcode, frame.Payload, maskOut)
		writeMu.Unlock()
		if err != nil {
			return
		}
		if frame.Opcode == 8 {
			return
		}
	}
}

func (p *Proxy) recordWSFrame(ctx context.Context, connectionID, direction string, frame wsFrame) {
	if p.ws == nil {
		return
	}
	payload := frame.Payload
	truncated := false
	if max := p.cfg().TrafficCapture.MaxBodyBytes; max > 0 && int64(len(payload)) > max {
		payload = payload[:max]
		truncated = true
	}
	if p.cfg().TrafficCapture.RedactBodies {
		payload = threats.RedactBody(payload)
	}
	record := store.WebSocketFrame{
		ConnectionID: connectionID,
		CreatedAt:    time.Now().UTC(),
		Direction:    direction,
		Opcode:       frame.Opcode,
		OpcodeName:   wsOpcodeName(frame.Opcode),
		Payload:      string(payload),
		PayloadBytes: int64(len(frame.Payload)),
		Truncated:    truncated,
	}
	record = p.ws.Record(ctx, record)
	p.publish(events.TopicWebSocketFrame, websocketFramePayload(record), "")
}

func websocketFramePayload(frame store.WebSocketFrame) map[string]any {
	return map[string]any{
		"frame": map[string]any{
			"id":            frame.ID,
			"connection_id": frame.ConnectionID,
			"created_at":    frame.CreatedAt,
			"direction":     frame.Direction,
			"opcode":        frame.Opcode,
			"opcode_name":   frame.OpcodeName,
			"payload":       frame.Payload,
			"payload_bytes": frame.PayloadBytes,
			"truncated":     frame.Truncated,
			"injected":      frame.Injected,
		},
		"connection_id": frame.ConnectionID,
	}
}

func readWSFrame(r *bufio.Reader) (wsFrame, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return wsFrame{}, err
	}
	fin := header[0]&0x80 != 0
	opcode := int(header[0] & 0x0f)
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var buf [2]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return wsFrame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(buf[:]))
	case 127:
		var buf [8]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return wsFrame{}, err
		}
		length = binary.BigEndian.Uint64(buf[:])
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return wsFrame{}, err
		}
	}
	if length > 16*1024*1024 {
		return wsFrame{}, fmt.Errorf("websocket frame too large")
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(r, payload); err != nil {
		return wsFrame{}, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return wsFrame{Fin: fin, Opcode: opcode, Payload: payload}, nil
}

func writeWSFrame(w io.Writer, opcode int, payload []byte, masked bool) error {
	first := byte(0x80 | (opcode & 0x0f))
	header := []byte{first, 0}
	length := len(payload)
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch {
	case length < 126:
		header[1] = maskBit | byte(length)
	case length <= 65535:
		header[1] = maskBit | 126
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(length))
		header = append(header, ext[:]...)
	default:
		header[1] = maskBit | 127
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(length))
		header = append(header, ext[:]...)
	}
	out := payload
	if masked {
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		header = append(header, key[:]...)
		out = append([]byte(nil), payload...)
		for i := range out {
			out[i] ^= key[i%4]
		}
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(out)
	return err
}

func proxyCopy(dst io.Writer, src io.Reader) {
	_, _ = io.Copy(dst, src)
}

func wsOpcodeName(opcode int) string {
	switch opcode {
	case 1:
		return "text"
	case 2:
		return "binary"
	case 8:
		return "close"
	case 9:
		return "ping"
	case 10:
		return "pong"
	default:
		return "continuation"
	}
}

func stripWebSocketCompression(h http.Header) {
	for _, value := range h.Values("Sec-WebSocket-Extensions") {
		if strings.Contains(strings.ToLower(value), "permessage-deflate") {
			h.Del("Sec-WebSocket-Extensions")
			return
		}
	}
}
