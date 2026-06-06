package intercept

import (
	"context"
	"testing"
	"time"

	cfgpkg "mitm-proxy/internal/config"
	"mitm-proxy/internal/store"
)

func TestSubmitTimesOutForwardByDefault(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/dashboard.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	cfg := &cfgpkg.Config{Intercept: cfgpkg.InterceptConfig{Enabled: true, TimeoutMS: 10, TimeoutAction: "forward"}}
	manager := NewManager(func() *cfgpkg.Config { return cfg }, st, nil)
	result, err := manager.Submit(context.Background(), store.PendingIntercept{
		RequestID: "req-1",
		Direction: "request",
		Original:  store.InterceptMessage{Method: "GET", URL: "https://example.test/"},
		Edited:    store.InterceptMessage{Method: "GET", URL: "https://example.test/"},
		TimeoutAt: time.Now().UTC().Add(10 * time.Millisecond),
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if result.Action != "forward" || result.Pending.State != "timed_out" {
		t.Fatalf("unexpected timeout result: %+v", result)
	}
}

func TestSubmitTimesOutDropWhenConfigured(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/dashboard.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	cfg := &cfgpkg.Config{Intercept: cfgpkg.InterceptConfig{Enabled: true, TimeoutMS: 10, TimeoutAction: "drop"}}
	manager := NewManager(func() *cfgpkg.Config { return cfg }, st, nil)
	result, err := manager.Submit(context.Background(), store.PendingIntercept{
		RequestID: "req-2",
		Direction: "response",
		Original:  store.InterceptMessage{Status: 200},
		Edited:    store.InterceptMessage{Status: 200},
		TimeoutAt: time.Now().UTC().Add(10 * time.Millisecond),
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if result.Action != "drop" || result.Pending.State != "dropped" {
		t.Fatalf("unexpected timeout result: %+v", result)
	}
}
