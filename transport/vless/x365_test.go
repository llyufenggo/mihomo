package vless

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
)

const x365FixtureUUID = "00112233-4455-6677-8899-aabbccddeeff"

func x365FixtureDestination() *DstAddr {
	return &DstAddr{
		AddrType: AtypDomainName,
		Addr:     []byte("example.com"),
		Port:     443,
	}
}

func TestX365RequestWireFormat(t *testing.T) {
	client, err := NewX365Client(x365FixtureUUID, nil)
	if err != nil {
		t.Fatalf("NewX365Client: %v", err)
	}
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	conn, err := client.StreamConn(clientSide, x365FixtureDestination())
	if err != nil {
		t.Fatalf("StreamConn: %v", err)
	}

	payload := []byte("fixture-payload")
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeDone <- err
	}()

	expectedLength := 5 + 1 + 16 + 2 + 1 + len("example.com") + len(payload)
	wire := make([]byte, expectedLength)
	if _, err := io.ReadFull(serverSide, wire); err != nil {
		t.Fatalf("read wire request: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write request: %v", err)
	}
	if !bytes.Equal(wire[:5], []byte{'X', '3', '6', '5', 0x01}) {
		t.Fatalf("unexpected X365 prefix: %x", wire[:5])
	}
	if wire[5] != CommandTCP {
		t.Fatalf("unexpected command: %d", wire[5])
	}
	if !bytes.Equal(wire[len(wire)-len(payload):], payload) {
		t.Fatalf("payload mismatch: %x", wire)
	}
}

func TestX365ResponseRejectsInvalidHeader(t *testing.T) {
	client, err := NewX365Client(x365FixtureUUID, nil)
	if err != nil {
		t.Fatalf("NewX365Client: %v", err)
	}
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	conn, err := client.StreamConn(clientSide, x365FixtureDestination())
	if err != nil {
		t.Fatalf("StreamConn: %v", err)
	}
	go func() {
		_, _ = serverSide.Write([]byte("WRONG"))
	}()
	buffer := make([]byte, 1)
	_, err = conn.Read(buffer)
	if err == nil || !strings.Contains(err.Error(), "invalid x365 response header") {
		t.Fatalf("unexpected response error: %v", err)
	}
}

func TestStandardVLESSRequestRemainsUnchanged(t *testing.T) {
	client, err := NewClient(x365FixtureUUID, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	conn, err := client.StreamConn(clientSide, x365FixtureDestination())
	if err != nil {
		t.Fatalf("StreamConn: %v", err)
	}
	go func() {
		_, _ = conn.Write([]byte("fixture"))
	}()
	first := make([]byte, 1)
	if _, err := io.ReadFull(serverSide, first); err != nil {
		t.Fatalf("read standard request: %v", err)
	}
	if first[0] != Version {
		t.Fatalf("standard VLESS prefix changed: got %d want %d", first[0], Version)
	}
}
