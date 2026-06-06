package wsinspect

import (
	"context"
	"fmt"
	"sync"

	"mitm-proxy/internal/store"
)

type Sender func(direction string, opcode int, payload []byte) error

type Store interface {
	CreateWebSocketConnection(context.Context, store.WebSocketConnection) (store.WebSocketConnection, error)
	CloseWebSocketConnection(context.Context, string) error
	AddWebSocketFrame(context.Context, store.WebSocketFrame) (store.WebSocketFrame, error)
}

type Manager struct {
	store Store
	mu    sync.RWMutex
	conns map[string]Sender
}

func NewManager(st Store) *Manager {
	return &Manager{store: st, conns: map[string]Sender{}}
}

func (m *Manager) Register(id string, sender Sender) {
	if m == nil || id == "" || sender == nil {
		return
	}
	m.mu.Lock()
	m.conns[id] = sender
	m.mu.Unlock()
}

func (m *Manager) Create(ctx context.Context, c store.WebSocketConnection) store.WebSocketConnection {
	if m == nil || m.store == nil {
		return c
	}
	created, err := m.store.CreateWebSocketConnection(ctx, c)
	if err != nil {
		return c
	}
	return created
}

func (m *Manager) Unregister(id string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	delete(m.conns, id)
	m.mu.Unlock()
}

func (m *Manager) Close(ctx context.Context, id string) {
	if m == nil || m.store == nil {
		return
	}
	_ = m.store.CloseWebSocketConnection(ctx, id)
}

func (m *Manager) Send(ctx context.Context, connectionID, direction string, opcode int, payload []byte) (store.WebSocketFrame, error) {
	if m == nil {
		return store.WebSocketFrame{}, fmt.Errorf("websocket manager unavailable")
	}
	m.mu.RLock()
	sender := m.conns[connectionID]
	m.mu.RUnlock()
	if sender == nil {
		return store.WebSocketFrame{}, fmt.Errorf("websocket connection is not active")
	}
	if err := sender(direction, opcode, payload); err != nil {
		return store.WebSocketFrame{}, err
	}
	frame := store.WebSocketFrame{
		ConnectionID: connectionID,
		Direction:    direction,
		Opcode:       opcode,
		OpcodeName:   opcodeName(opcode),
		Payload:      string(payload),
		PayloadBytes: int64(len(payload)),
		Injected:     true,
	}
	if m.store == nil {
		return frame, nil
	}
	return m.store.AddWebSocketFrame(ctx, frame)
}

func (m *Manager) Record(ctx context.Context, frame store.WebSocketFrame) store.WebSocketFrame {
	if m == nil || m.store == nil {
		return frame
	}
	created, err := m.store.AddWebSocketFrame(ctx, frame)
	if err != nil {
		return frame
	}
	return created
}

func opcodeName(opcode int) string {
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
