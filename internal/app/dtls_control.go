package app

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pion/dtls/v3"
)

// DTLS application records preserve TURN message boundaries, so the TURN
// client can use them as a PacketConn without TCP's STUN framing.
type dtlsControlConn struct{ conn *dtls.Conn }

func (c *dtlsControlConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.conn.Read(p)
	return n, c.conn.RemoteAddr(), err
}
func (c *dtlsControlConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.conn.Write(p)
}
func (c *dtlsControlConn) Close() error                       { return c.conn.Close() }
func (c *dtlsControlConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *dtlsControlConn) SetDeadline(v time.Time) error      { return c.conn.SetDeadline(v) }
func (c *dtlsControlConn) SetReadDeadline(v time.Time) error  { return c.conn.SetReadDeadline(v) }
func (c *dtlsControlConn) SetWriteDeadline(v time.Time) error { return c.conn.SetWriteDeadline(v) }

func dialDTLSControl(cfg commonConfig) (net.PacketConn, error) {
	server, err := net.ResolveUDPAddr("udp", cfg.Turn)
	if err != nil {
		return nil, fmt.Errorf("resolve DTLS TURN server: %w", err)
	}
	network, listenAddr := "udp4", "0.0.0.0:0"
	if server.IP.To4() == nil {
		network, listenAddr = "udp6", "[::]:0"
	}
	underlying, err := net.ListenPacket(network, listenAddr)
	if err != nil {
		return nil, err
	}
	config := &dtls.Config{ServerName: hostOnly(cfg.Turn), InsecureSkipVerify: cfg.Insecure}
	conn, err := dtls.Client(underlying, server, config)
	if err != nil {
		_ = underlying.Close()
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		_ = underlying.Close()
		return nil, fmt.Errorf("DTLS handshake: %w", err)
	}
	return &dtlsControlConn{conn: conn}, nil
}
