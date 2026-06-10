package events

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	TopicTrafficRequestStarted    = "traffic.request.started"
	TopicTrafficResponseCompleted = "traffic.response.completed"
	TopicTrafficTunnelOpened      = "traffic.tunnel.opened"
	TopicTrafficBlocked           = "traffic.blocked"
	TopicTrafficBodyCaptured      = "traffic.body.captured"
	TopicInterceptPending         = "intercept.pending"
	TopicInterceptResolved        = "intercept.resolved"
	TopicWebSocketConnection      = "websocket.connection"
	TopicWebSocketFrame           = "websocket.frame"
	TopicCertGenerated            = "cert.generated"
	TopicConfigUpdated            = "config.updated"
	TopicDeploymentUpdated        = "deployment.updated"
	TopicCacheHit                 = "cache.hit"
	TopicCacheMiss                = "cache.miss"
	TopicFaultInjected            = "fault.injected"
	TopicTimelineEntry            = "timeline.entry"
	TopicHostProfileMatched       = "host_profile.matched"
)

type Event struct {
	ID        string         `json:"id"`
	Topic     string         `json:"topic"`
	Time      time.Time      `json:"time"`
	Payload   map[string]any `json:"payload,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
}

type EventBus interface {
	Publish(event Event)
}

type Bus struct {
	mu          sync.RWMutex
	subscribers map[string][]chan Event
	recent      []Event
	maxRecent   int
	buffer      int
	nextID      atomic.Uint64
}

func NewBus(buffer int) *Bus {
	if buffer <= 0 {
		buffer = 32
	}

	return &Bus{
		subscribers: make(map[string][]chan Event),
		maxRecent:   1000,
		buffer:      buffer,
	}
}

func (b *Bus) Publish(event Event) {
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	if event.ID == "" {
		event.ID = fmt.Sprintf("%d", b.nextID.Add(1))
	}

	b.mu.Lock()
	b.recent = append(b.recent, event)
	if len(b.recent) > b.maxRecent {
		copy(b.recent, b.recent[len(b.recent)-b.maxRecent:])
		b.recent = b.recent[:b.maxRecent]
	}
	targets := append([]chan Event(nil), b.subscribers[event.Topic]...)
	targets = append(targets, b.subscribers["*"]...)
	b.mu.Unlock()

	for _, ch := range targets {
		select {
		case ch <- event:
		default:
		}
	}
}

func (b *Bus) Subscribe(topic string) (<-chan Event, func()) {
	if topic == "" {
		topic = "*"
	}

	ch := make(chan Event, b.buffer)
	cancelled := false
	b.mu.Lock()
	b.subscribers[topic] = append(b.subscribers[topic], ch)
	b.mu.Unlock()

	cancel := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if cancelled {
			return
		}
		cancelled = true
		subscribers := b.subscribers[topic]
		for i, subscriber := range subscribers {
			if subscriber == ch {
				copy(subscribers[i:], subscribers[i+1:])
				subscribers = subscribers[:len(subscribers)-1]
				break
			}
		}
		if len(subscribers) == 0 {
			delete(b.subscribers, topic)
			return
		}
		b.subscribers[topic] = subscribers
	}

	return ch, cancel
}

func (b *Bus) Recent(topic string, limit int) []Event {
	if limit <= 0 || limit > b.maxRecent {
		limit = 100
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	events := make([]Event, 0, limit)
	for i := len(b.recent) - 1; i >= 0 && len(events) < limit; i-- {
		event := b.recent[i]
		if topic == "" || topic == "*" || event.Topic == topic {
			events = append(events, event)
		}
	}

	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	return events
}

func (b *Bus) Get(id string) (Event, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for i := len(b.recent) - 1; i >= 0; i-- {
		if b.recent[i].ID == id || b.recent[i].RequestID == id {
			return b.recent[i], true
		}
	}

	return Event{}, false
}
