package proxy

import (
	"bufio"
	"bytes"
	"testing"
)

func TestWebSocketFrameCodecMaskedAndUnmasked(t *testing.T) {
	var masked bytes.Buffer
	if err := writeWSFrame(&masked, 1, []byte("hello"), true); err != nil {
		t.Fatalf("write masked: %v", err)
	}
	frame, err := readWSFrame(bufio.NewReader(&masked))
	if err != nil {
		t.Fatalf("read masked: %v", err)
	}
	if frame.Opcode != 1 || string(frame.Payload) != "hello" {
		t.Fatalf("unexpected masked frame: %+v", frame)
	}

	var plain bytes.Buffer
	if err := writeWSFrame(&plain, 2, []byte{1, 2, 3}, false); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	frame, err = readWSFrame(bufio.NewReader(&plain))
	if err != nil {
		t.Fatalf("read plain: %v", err)
	}
	if frame.Opcode != 2 || !bytes.Equal(frame.Payload, []byte{1, 2, 3}) {
		t.Fatalf("unexpected plain frame: %+v", frame)
	}
}
