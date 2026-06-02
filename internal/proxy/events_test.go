package proxy

import (
	"net/http"
	"testing"

	cfgpkg "mitm-proxy/internal/config"
)

func TestHeaderPayloadCaptureOptions(t *testing.T) {
	p := New(nil, &cfgpkg.Config{
		TrafficCapture: cfgpkg.TrafficCaptureConfig{
			StoreHeaders:    true,
			RedactedHeaders: []string{"Authorization", "X-Api-Key"},
			StoreCookies:    true,
			RedactedCookies: []string{"session", "refresh"},
		},
	})

	headers := http.Header{}
	headers.Set("Authorization", "Bearer secret")
	headers.Set("X-Api-Key", "key-secret")
	headers.Set("User-Agent", "research-browser")
	headers.Set("Cookie", "session=abc; theme=dark")
	headers.Add("Set-Cookie", "refresh=xyz; Path=/; HttpOnly")
	headers.Add("Set-Cookie", "theme=dark; Path=/")

	payload := p.headerPayload(headers)
	assertHeaderValues(t, payload, "Authorization", []string{"[redacted]"})
	assertHeaderValues(t, payload, "X-Api-Key", []string{"[redacted]"})
	assertHeaderValues(t, payload, "User-Agent", []string{"research-browser"})
	assertHeaderValues(t, payload, "Cookie", []string{"session=[redacted]; theme=dark"})
	assertHeaderValues(t, payload, "Set-Cookie", []string{"refresh=[redacted]; Path=/; HttpOnly", "theme=dark; Path=/"})
}

func TestHeaderPayloadCanSkipHeadersAndCookies(t *testing.T) {
	p := New(nil, &cfgpkg.Config{
		TrafficCapture: cfgpkg.TrafficCaptureConfig{
			StoreHeaders: true,
			StoreCookies: false,
		},
	})

	headers := http.Header{}
	headers.Set("User-Agent", "research-browser")
	headers.Set("Cookie", "session=abc")
	headers.Set("Set-Cookie", "session=abc; Path=/")

	payload := p.headerPayload(headers)
	assertHeaderValues(t, payload, "User-Agent", []string{"research-browser"})
	if _, ok := payload["Cookie"]; ok {
		t.Fatalf("Cookie header should not be captured when StoreCookies=false")
	}
	if _, ok := payload["Set-Cookie"]; ok {
		t.Fatalf("Set-Cookie header should not be captured when StoreCookies=false")
	}

	p.SetConfig(&cfgpkg.Config{TrafficCapture: cfgpkg.TrafficCaptureConfig{StoreHeaders: false, StoreCookies: true}})
	if got := p.headerPayload(headers); got != nil {
		t.Fatalf("headers should not be captured when StoreHeaders=false: %#v", got)
	}
}

func assertHeaderValues(t *testing.T, payload map[string]any, name string, want []string) {
	t.Helper()
	raw, ok := payload[name]
	if !ok {
		t.Fatalf("missing header %s in %#v", name, payload)
	}
	got, ok := raw.([]string)
	if !ok {
		t.Fatalf("header %s has type %T, want []string", name, raw)
	}
	if len(got) != len(want) {
		t.Fatalf("header %s values = %#v, want %#v", name, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("header %s values = %#v, want %#v", name, got, want)
		}
	}
}
