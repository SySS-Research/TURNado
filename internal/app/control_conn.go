package app

import (
	"errors"
	"net"
	"sync"
)

// Pion's listener stops when its control socket fails, but an allocated relay's
// ReadFrom can remain blocked. Expose that failure to the tunnel owner too.
type observedControlConn struct {
	net.PacketConn
	failed   chan struct{}
	failOnce sync.Once
	failure  error // Published by closing failed.
}

func observeControlConn(pc net.PacketConn) *observedControlConn {
	return &observedControlConn{PacketConn: pc, failed: make(chan struct{})}
}

func (c *observedControlConn) recordFailure(err error) {
	if err == nil {
		return
	}
	var ne net.Error
	if errors.As(err, &ne) && (ne.Timeout() || ne.Temporary()) {
		return
	}
	c.failOnce.Do(func() { c.failure = err; close(c.failed) })
}

func (c *observedControlConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	c.recordFailure(err)
	return n, addr, err
}

func (c *observedControlConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	c.recordFailure(err)
	return n, err
}

func (c *observedControlConn) Close() error {
	c.recordFailure(net.ErrClosed)
	return c.PacketConn.Close()
}
