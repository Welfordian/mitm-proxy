package store

import (
	"context"
	"testing"
	"time"

	"mitm-proxy/internal/events"
)

func TestListTrafficDetailsScopedPageLoadsRelatedData(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := st.RecordEvent(ctx, events.Event{
		Topic:     events.TopicTrafficRequestStarted,
		RequestID: "flow-1",
		Time:      now,
		Payload: map[string]any{
			"method": "POST",
			"url":    "https://example.test/login?debug=true",
			"host":   "example.test",
			"request_headers": map[string]any{
				"Cookie": []string{"session=abc; theme=dark"},
				"X-Test": []string{"one"},
			},
		},
	}); err != nil {
		t.Fatalf("record flow 1 start: %v", err)
	}
	if err := st.RecordEvent(ctx, events.Event{
		Topic:     events.TopicTrafficBodyCaptured,
		RequestID: "flow-1",
		Time:      now,
		Payload:   map[string]any{"direction": "request", "body": "username=alice"},
	}); err != nil {
		t.Fatalf("record flow 1 body: %v", err)
	}
	if err := st.RecordEvent(ctx, events.Event{
		Topic:     events.TopicTrafficRequestStarted,
		RequestID: "flow-2",
		Time:      now.Add(time.Second),
		Payload: map[string]any{
			"method": "GET",
			"url":    "https://other.test/",
			"host":   "other.test",
		},
	}); err != nil {
		t.Fatalf("record flow 2 start: %v", err)
	}

	details, err := st.ListTrafficDetailsScopedPage(ctx, 10, 0, "", true, "")
	if err != nil {
		t.Fatalf("list details: %v", err)
	}
	if len(details) != 2 {
		t.Fatalf("expected two details, got %+v", details)
	}
	if details[0].ID != "flow-2" || details[1].ID != "flow-1" {
		t.Fatalf("expected traffic order to match flow page, got %s then %s", details[0].ID, details[1].ID)
	}
	flow := details[1]
	if got := flow.QueryParams["debug"]; len(got) != 1 || got[0] != "true" {
		t.Fatalf("query params were not populated: %+v", flow.QueryParams)
	}
	if flow.Cookies["session"] != "abc" || flow.Cookies["theme"] != "dark" {
		t.Fatalf("cookies were not populated: %+v", flow.Cookies)
	}
	if flow.RequestBody != "username=alice" {
		t.Fatalf("request body was not populated: %q", flow.RequestBody)
	}
	if len(flow.Headers) != 2 {
		t.Fatalf("headers were not populated: %+v", flow.Headers)
	}
}
