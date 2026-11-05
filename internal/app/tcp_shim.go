package app

import (
	"io"
	"net"
	"time"

	"github.com/pion/transport/v4"
)

// Pion binds RFC 6062 data connections only if they implement the full
// transport.TCPConn interface. TLS and proxied connections do not, so the
// socket options become no-ops and half-closes fall back where possible.
type tcpConnShim struct{ net.Conn }

func asTURNTCPConn(c net.Conn) transport.TCPConn {
	if tc, ok := c.(transport.TCPConn); ok {
		return tc
	}
	return tcpConnShim{Conn: c}
}

func (c tcpConnShim) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (c tcpConnShim) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c tcpConnShim) ReadFrom(r io.Reader) (int64, error)  { return io.Copy(c.Conn, r) }
func (tcpConnShim) SetLinger(int) error                    { return nil }
func (tcpConnShim) SetKeepAlive(bool) error                { return nil }
func (tcpConnShim) SetKeepAlivePeriod(time.Duration) error { return nil }
func (tcpConnShim) SetNoDelay(bool) error                  { return nil }
func (tcpConnShim) SetWriteBuffer(int) error               { return nil }
func (tcpConnShim) SetReadBuffer(int) error                { return nil }
