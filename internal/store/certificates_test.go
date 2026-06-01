package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"mitm-proxy/internal/events"
)

func TestListCertificatesPageSupportsSearchAndPagination(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	for i, host := range []string{"api.example.test", "cdn.example.test", "outside.test"} {
		if err := st.RecordEvent(ctx, events.Event{
			Topic: events.TopicCertGenerated,
			Time:  time.Now().UTC(),
			Payload: map[string]any{
				"host":        host,
				"subject":     fmt.Sprintf("CN=%s", host),
				"fingerprint": fmt.Sprintf("fingerprint-%d", i),
				"created_at":  time.Now().UTC().Format(time.RFC3339Nano),
				"expires_at":  time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
			},
		}); err != nil {
			t.Fatalf("record certificate: %v", err)
		}
	}

	page, err := st.ListCertificatesPage(ctx, 1, 1, "example")
	if err != nil {
		t.Fatalf("list certificates page: %v", err)
	}
	if page.Total != 2 || page.HasMore {
		t.Fatalf("unexpected certificate page metadata: %+v", page)
	}
	if len(page.Items) != 1 || page.Items[0].Host != "api.example.test" {
		t.Fatalf("unexpected certificate items: %+v", page.Items)
	}
}

func TestRecordCertificateUpsertsByHost(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	for _, fingerprint := range []string{"old-fingerprint", "new-fingerprint"} {
		if err := st.RecordEvent(ctx, events.Event{
			Topic: events.TopicCertGenerated,
			Time:  time.Now().UTC(),
			Payload: map[string]any{
				"host":        "github.com",
				"subject":     "CN=github.com",
				"fingerprint": fingerprint,
				"created_at":  time.Now().UTC().Format(time.RFC3339Nano),
				"expires_at":  time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
			},
		}); err != nil {
			t.Fatalf("record certificate: %v", err)
		}
	}

	page, err := st.ListCertificatesPage(ctx, 10, 0, "github.com")
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("expected one current certificate, got %+v", page)
	}
	if page.Items[0].Fingerprint != "new-fingerprint" {
		t.Fatalf("expected latest fingerprint, got %+v", page.Items[0])
	}
}
