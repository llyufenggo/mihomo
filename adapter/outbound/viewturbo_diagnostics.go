package outbound

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
)

const (
	viewTurboMaxDiagnosticConnections = 32
	viewTurboMaxWriteEvents          = 6
	viewTurboMaxReadEvents           = 3
)

var viewTurboConnectionID atomic.Uint64

type viewTurboDiagnosticConn struct {
	net.Conn
	id         uint64
	startedAt  time.Time
	mu         sync.Mutex
	writeCount int
	readCount  int
}

func wrapViewTurboDiagnosticConn(conn net.Conn) net.Conn {
	id := viewTurboConnectionID.Add(1)
	if id > viewTurboMaxDiagnosticConnections {
		return conn
	}
	log.Infoln("[ViewTurbo] phase=tcp_connected connection=%d", id)
	return &viewTurboDiagnosticConn{
		Conn:      conn,
		id:        id,
		startedAt: time.Now(),
	}
}

func (c *viewTurboDiagnosticConn) Write(buffer []byte) (int, error) {
	startedAt := time.Now()
	n, err := c.Conn.Write(buffer)
	c.mu.Lock()
	c.writeCount++
	sequence := c.writeCount
	c.mu.Unlock()
	if sequence <= viewTurboMaxWriteEvents {
		log.Infoln(
			"[ViewTurbo] phase=wire_write connection=%d sequence=%d requested=%d written=%d duration_ms=%d error=%s",
			c.id,
			sequence,
			len(buffer),
			n,
			time.Since(startedAt).Milliseconds(),
			viewTurboErrorClass(err),
		)
	}
	return n, err
}

func (c *viewTurboDiagnosticConn) Read(buffer []byte) (int, error) {
	startedAt := time.Now()
	n, err := c.Conn.Read(buffer)
	c.mu.Lock()
	c.readCount++
	sequence := c.readCount
	c.mu.Unlock()
	if sequence <= viewTurboMaxReadEvents {
		log.Infoln(
			"[ViewTurbo] phase=wire_read connection=%d sequence=%d read=%d duration_ms=%d since_connect_ms=%d error=%s",
			c.id,
			sequence,
			n,
			time.Since(startedAt).Milliseconds(),
			time.Since(c.startedAt).Milliseconds(),
			viewTurboErrorClass(err),
		)
	}
	return n, err
}

func viewTurboErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return "timeout"
		}
		if netErr.Temporary() {
			return "temporary"
		}
	}
	return "io"
}
