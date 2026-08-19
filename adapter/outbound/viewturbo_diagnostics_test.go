package outbound

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestViewTurboDiagnosticConnPreservesWireBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := wrapViewTurboDiagnosticConn(client)
	request := []byte("request-wire")
	response := []byte("response-wire")
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, len(request))
		if _, err := io.ReadFull(server, buffer); err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(buffer, request) {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		_, err := server.Write(response)
		serverDone <- err
	}()

	if n, err := wrapped.Write(request); err != nil || n != len(request) {
		t.Fatalf("diagnostic write changed result: n=%d err=%v", n, err)
	}
	buffer := make([]byte, len(response))
	if _, err := io.ReadFull(wrapped, buffer); err != nil {
		t.Fatalf("diagnostic read failed: %v", err)
	}
	if !bytes.Equal(buffer, response) {
		t.Fatalf("diagnostic read changed bytes: %q", buffer)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server exchange failed: %v", err)
	}
}

func TestViewTurboDiagnosticErrorClassIsBounded(t *testing.T) {
	if got := viewTurboErrorClass(nil); got != "none" {
		t.Fatalf("nil error class = %q", got)
	}
	if got := viewTurboErrorClass(io.ErrUnexpectedEOF); got != "io" {
		t.Fatalf("I/O error class = %q", got)
	}
}
