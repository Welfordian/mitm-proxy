package admin

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"testing"

	"mitm-proxy/internal/store"
)

func TestDecodeTrafficBodiesForDisplayGzip(t *testing.T) {
	flow := store.TrafficDetail{
		Headers: []store.HeaderRecord{
			{Direction: "request", Name: "Content-Encoding", Value: "gzip"},
			{Direction: "response", Name: "Content-Encoding", Value: "gzip"},
		},
		RequestBody:  gzipString(t, "request json"),
		ResponseBody: gzipString(t, "response html"),
	}

	decodeTrafficBodiesForDisplay(&flow)

	if flow.RequestBody != "request json" {
		t.Fatalf("request body was not decoded: %q", flow.RequestBody)
	}
	if flow.ResponseBody != "response html" {
		t.Fatalf("response body was not decoded: %q", flow.ResponseBody)
	}
}

func TestDecodeBodyForDisplayInvalidGzipFallsBack(t *testing.T) {
	headers := http.Header{"Content-Encoding": []string{"gzip"}}
	body := "not actually gzip"

	if got := decodeBodyForDisplay(body, headers); got != body {
		t.Fatalf("invalid gzip should be returned unchanged, got %q", got)
	}
}

func TestDecodeRepeaterRunForDisplayGzip(t *testing.T) {
	run := store.RepeaterRun{
		ResponseHeaders: map[string][]string{"Content-Encoding": {"gzip"}},
		ResponseBody:    gzipString(t, "readable repeater response"),
	}

	decodeRepeaterRunForDisplay(&run)

	if run.ResponseBody != "readable repeater response" {
		t.Fatalf("repeater response body was not decoded: %q", run.ResponseBody)
	}
}

func gzipString(t *testing.T, value string) string {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write([]byte(value)); err != nil {
		t.Fatalf("write gzip body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return string(buf.Bytes())
}
