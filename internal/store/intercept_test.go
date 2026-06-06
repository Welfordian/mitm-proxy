package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"mitm-proxy/internal/events"
)

func TestInterceptRuleMatching(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	rule, err := st.CreateInterceptRule(ctx, InterceptRule{
		Name:                "JSON posts",
		Enabled:             true,
		Priority:            10,
		Direction:           "request",
		HostPatterns:        []string{"example.test"},
		MethodPatterns:      []string{"post"},
		ContentTypePatterns: []string{"application/json"},
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	got, ok, err := st.MatchInterceptRule(ctx, BreakpointMatch{
		Direction:   "request",
		Method:      "POST",
		Host:        "api.example.test",
		ContentType: "application/json; charset=utf-8",
	})
	if err != nil || !ok || got.ID != rule.ID {
		t.Fatalf("match ok=%v err=%v got=%+v", ok, err, got)
	}
	if _, ok, err := st.MatchInterceptRule(ctx, BreakpointMatch{Direction: "response", Method: "POST", Host: "api.example.test"}); err != nil || ok {
		t.Fatalf("response should not match request rule ok=%v err=%v", ok, err)
	}
}

func TestDeleteInterceptRuleRemovesRulePendingIntercepts(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	rule, err := st.CreateInterceptRule(ctx, InterceptRule{Name: "example", Enabled: true, Direction: "request"})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	otherRule, err := st.CreateInterceptRule(ctx, InterceptRule{Name: "other", Enabled: true, Direction: "request"})
	if err != nil {
		t.Fatalf("create other rule: %v", err)
	}
	for _, pending := range []PendingIntercept{
		{RequestID: "req-1", RuleID: rule.ID, Direction: "request", State: "timed_out", TimeoutAt: time.Now().Add(time.Second), TimeoutAction: "forward", Original: InterceptMessage{Method: "GET", Host: "example.com"}},
		{RequestID: "req-2", RuleID: rule.ID, Direction: "request", State: "forwarded", TimeoutAt: time.Now().Add(time.Second), TimeoutAction: "forward", Original: InterceptMessage{Method: "GET", Host: "example.com"}},
		{RequestID: "req-3", RuleID: otherRule.ID, Direction: "request", State: "pending", TimeoutAt: time.Now().Add(time.Second), TimeoutAction: "forward", Original: InterceptMessage{Method: "GET", Host: "other.test"}},
		{RequestID: "req-4", RuleID: "missing-rule", Direction: "request", State: "pending", TimeoutAt: time.Now().Add(time.Second), TimeoutAction: "forward", Original: InterceptMessage{Method: "GET", Host: "orphan.test"}},
	} {
		if _, err := st.CreatePendingIntercept(ctx, pending); err != nil {
			t.Fatalf("create pending intercept: %v", err)
		}
	}
	if err := st.DeleteInterceptRule(ctx, rule.ID); err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	items, err := st.ListPendingIntercepts(ctx, "", 100)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(items) != 1 || items[0].RuleID != otherRule.ID {
		t.Fatalf("expected only other rule pending intercept to remain, got %+v", items)
	}
}

func TestListWebSocketFramesNewestFirst(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	conn, err := st.CreateWebSocketConnection(ctx, WebSocketConnection{
		ID:       "conn-1",
		URL:      "wss://example.test/ws",
		Host:     "example.test:443",
		Protocol: "wss",
	})
	if err != nil {
		t.Fatalf("create websocket connection: %v", err)
	}
	base := time.Now().UTC()
	for _, frame := range []WebSocketFrame{
		{ID: "frame-old", ConnectionID: conn.ID, CreatedAt: base.Add(-2 * time.Second), Direction: "server_to_client", Opcode: 1, Payload: "old", PayloadBytes: 3},
		{ID: "frame-new", ConnectionID: conn.ID, CreatedAt: base, Direction: "server_to_client", Opcode: 1, Payload: "new", PayloadBytes: 3},
		{ID: "frame-mid", ConnectionID: conn.ID, CreatedAt: base.Add(-time.Second), Direction: "server_to_client", Opcode: 1, Payload: "mid", PayloadBytes: 3},
	} {
		if _, err := st.AddWebSocketFrame(ctx, frame); err != nil {
			t.Fatalf("add websocket frame: %v", err)
		}
	}
	frames, err := st.ListWebSocketFrames(ctx, conn.ID, 10, 0, "")
	if err != nil {
		t.Fatalf("list websocket frames: %v", err)
	}
	got := []string{}
	for _, frame := range frames {
		got = append(got, frame.ID)
	}
	want := []string{"frame-new", "frame-mid", "frame-old"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected newest-first order %v, got %v", want, got)
	}
}

func TestTrafficAdvancedSearchFields(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	if err := st.RecordEvent(ctx, testTrafficStarted("flow-1", "POST", "https://example.test/login", "example.test")); err != nil {
		t.Fatalf("record start: %v", err)
	}
	if err := st.RecordEvent(ctx, testTrafficBody("flow-1", "request", "token=abc")); err != nil {
		t.Fatalf("record body: %v", err)
	}
	if err := st.RecordEvent(ctx, testTrafficCompleted("flow-1", 401)); err != nil {
		t.Fatalf("record complete: %v", err)
	}
	flows, err := st.ListTrafficAdvanced(ctx, 10, 0, "", true, "host:example.test method:POST status:>=400 body:token")
	if err != nil {
		t.Fatalf("advanced search: %v", err)
	}
	if len(flows) != 1 || flows[0].ID != "flow-1" {
		t.Fatalf("unexpected flows: %+v", flows)
	}
	if _, err := st.ListTrafficAdvanced(ctx, 10, 0, "", true, "status:nope"); err == nil {
		t.Fatalf("expected invalid status query to fail")
	}
}

func testTrafficStarted(id, method, rawURL, host string) events.Event {
	return events.Event{
		Topic:     events.TopicTrafficRequestStarted,
		Time:      time.Now().UTC(),
		RequestID: id,
		Payload: map[string]any{
			"method": method,
			"url":    rawURL,
			"host":   host,
			"request_headers": map[string]any{
				"Authorization": []string{"Bearer token"},
			},
		},
	}
}

func testTrafficCompleted(id string, status int) events.Event {
	return events.Event{
		Topic:     events.TopicTrafficResponseCompleted,
		Time:      time.Now().UTC(),
		RequestID: id,
		Payload: map[string]any{
			"status": status,
			"response_headers": map[string]any{
				"Content-Type": []string{"application/json"},
			},
		},
	}
}

func testTrafficBody(id, direction, body string) events.Event {
	return events.Event{
		Topic:     events.TopicTrafficBodyCaptured,
		Time:      time.Now().UTC(),
		RequestID: id,
		Payload: map[string]any{
			"direction": direction,
			"body":      body,
		},
	}
}
