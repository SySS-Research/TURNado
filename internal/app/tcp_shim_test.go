package app

import (
	"io"
	"net"
	"strings"
	"testing"

	"github.com/pion/transport/v4"
)

type halfCloseConn struct {
	net.Conn
	closedWrite bool
}

func (c *halfCloseConn) CloseWrite() error { c.closedWrite = true; return nil }

func TestTURNTCPConnShim(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if got := asTURNTCPConn(raw); got != raw.(transport.TCPConn) {
		t.Fatal("native TCP connection was wrapped")
	}

	a, b := net.Pipe()
	defer b.Close()
	inner := &halfCloseConn{Conn: a}
	shim := asTURNTCPConn(inner)
	if err := shim.CloseWrite(); err != nil || !inner.closedWrite {
		t.Fatalf("CloseWrite not delegated: %v", err)
	}
	if err := shim.SetNoDelay(true); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() { p, _ := io.ReadAll(b); done <- string(p) }()
	if _, err := shim.ReadFrom(strings.NewReader("payload")); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	if got := <-done; got != "payload" {
		t.Fatalf("ReadFrom wrote %q", got)
	}
}
