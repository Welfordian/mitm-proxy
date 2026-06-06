package intercept

import (
	"context"
	"strings"
	"sync"
	"time"

	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/events"
	"mitm-proxy/internal/store"
)

type ConfigProvider func() *cfgpkg.Config

type Store interface {
	MatchInterceptRule(context.Context, store.BreakpointMatch) (store.InterceptRule, bool, error)
	CreatePendingIntercept(context.Context, store.PendingIntercept) (store.PendingIntercept, error)
	ResolvePendingIntercept(context.Context, string, string, string, store.InterceptMessage) (store.PendingIntercept, bool, error)
}

type Result struct {
	Action  string
	Message store.InterceptMessage
	Pending store.PendingIntercept
}

type Manager struct {
	config ConfigProvider
	store  Store
	events events.EventBus

	mu      sync.Mutex
	waiters map[string]chan Result
}

func NewManager(config ConfigProvider, st Store, bus events.EventBus) *Manager {
	return &Manager{config: config, store: st, events: bus, waiters: map[string]chan Result{}}
}

func (m *Manager) Enabled() bool {
	cfg := m.cfg()
	return cfg.Intercept.Enabled && m.store != nil
}

func (m *Manager) Check(ctx context.Context, in store.BreakpointMatch) (store.InterceptRule, bool, error) {
	if !m.Enabled() {
		return store.InterceptRule{}, false, nil
	}
	return m.store.MatchInterceptRule(ctx, in)
}

func (m *Manager) Submit(ctx context.Context, pending store.PendingIntercept) (Result, error) {
	cfg := m.cfg().Intercept
	if pending.TimeoutAction == "" {
		pending.TimeoutAction = cfg.TimeoutAction
	}
	if pending.TimeoutAction == "" {
		pending.TimeoutAction = "forward"
	}
	if pending.TimeoutAt.IsZero() {
		timeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		pending.TimeoutAt = time.Now().UTC().Add(timeout)
	}
	if pending.Edited.Headers == nil {
		pending.Edited = pending.Original
	}
	created, err := m.store.CreatePendingIntercept(ctx, pending)
	if err != nil {
		return Result{}, err
	}
	ch := make(chan Result, 1)
	m.mu.Lock()
	m.waiters[created.ID] = ch
	m.mu.Unlock()
	m.publish(events.TopicInterceptPending, created, created.RequestID)

	timer := time.NewTimer(time.Until(created.TimeoutAt))
	defer timer.Stop()
	select {
	case result := <-ch:
		return result, nil
	case <-timer.C:
		action := strings.ToLower(created.TimeoutAction)
		state := "timed_out"
		if action == "drop" {
			state = "dropped"
		}
		resolved, _, _ := m.store.ResolvePendingIntercept(context.Background(), created.ID, state, "timeout", store.InterceptMessage{})
		m.removeWaiter(created.ID)
		m.publish(events.TopicInterceptResolved, resolved, created.RequestID)
		return Result{Action: action, Message: created.Original, Pending: resolved}, nil
	case <-ctx.Done():
		m.removeWaiter(created.ID)
		return Result{Action: "drop", Message: created.Original, Pending: created}, ctx.Err()
	}
}

func (m *Manager) Forward(ctx context.Context, id string, edited store.InterceptMessage) (store.PendingIntercept, bool, error) {
	pending, ok, err := m.store.ResolvePendingIntercept(ctx, id, "forwarded", "admin.forward", edited)
	if err != nil || !ok {
		return pending, ok, err
	}
	m.resolve(id, Result{Action: "forward", Message: pending.Edited, Pending: pending})
	m.publish(events.TopicInterceptResolved, pending, pending.RequestID)
	return pending, true, nil
}

func (m *Manager) Drop(ctx context.Context, id string) (store.PendingIntercept, bool, error) {
	pending, ok, err := m.store.ResolvePendingIntercept(ctx, id, "dropped", "admin.drop", store.InterceptMessage{})
	if err != nil || !ok {
		return pending, ok, err
	}
	m.resolve(id, Result{Action: "drop", Message: pending.Edited, Pending: pending})
	m.publish(events.TopicInterceptResolved, pending, pending.RequestID)
	return pending, true, nil
}

func (m *Manager) resolve(id string, result Result) {
	m.mu.Lock()
	ch := m.waiters[id]
	delete(m.waiters, id)
	m.mu.Unlock()
	if ch != nil {
		select {
		case ch <- result:
		default:
		}
	}
}

func (m *Manager) removeWaiter(id string) {
	m.mu.Lock()
	delete(m.waiters, id)
	m.mu.Unlock()
}

func (m *Manager) cfg() *cfgpkg.Config {
	if m == nil || m.config == nil {
		return &cfgpkg.Config{}
	}
	return m.config()
}

func (m *Manager) publish(topic string, payload any, requestID string) {
	if m == nil || m.events == nil {
		return
	}
	m.events.Publish(events.Event{
		Topic:     topic,
		Time:      time.Now().UTC(),
		RequestID: requestID,
		Payload: map[string]any{
			"intercept": payload,
		},
	})
}
