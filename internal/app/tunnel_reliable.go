package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

const (
	msgTypeReliable = 9
	kcpMTU          = 1100 // Fits inside the 1172-byte encrypted tunnel payload.
)

var (
	// reliableOpenTimeout bounds the wait for the exit's answer to a new
	// stream. The exit's own dial timeout is 15 s; a missing answer after this
	// means the exit is unreachable, so the SOCKS client gets an error instead
	// of a hanging connection.
	reliableOpenTimeout = newTunableDuration(30 * time.Second)
	// halfCloseStall bounds how long the remaining direction of a half-closed
	// stream may block without progress. A peer stream that is gone grants no
	// flow-control window, so such a write would otherwise never return.
	halfCloseStall = newTunableDuration(time.Minute)

	errReliableSessionClosed = errors.New("reliable session with the peer closed")
)

// tunableDuration is a timeout that tests can shorten while goroutines of
// earlier tests may still read it.
type tunableDuration struct{ ns atomic.Int64 }

func newTunableDuration(d time.Duration) *tunableDuration {
	t := &tunableDuration{}
	t.ns.Store(int64(d))
	return t
}

func (t *tunableDuration) get() time.Duration { return time.Duration(t.ns.Load()) }

// set changes the duration and returns a function that restores it.
func (t *tunableDuration) set(d time.Duration) func() {
	old := t.ns.Swap(int64(d))
	return func() { t.ns.Store(old) }
}

// kcpPacketConn frames KCP packets as tunnel messages. peerTransport remains
// the sole reader of the TURN allocation and handles DTLS/SRTP and heartbeats.
type kcpPacketConn struct{ transport *peerTransport }

func (c *kcpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var buf [maxPacketSize]byte
	for {
		n, addr, err := c.transport.ReadFrom(buf[:])
		if err != nil {
			return 0, nil, err
		}
		h, payload, err := parseHeader(buf[:n])
		if err != nil || h.Type != msgTypeReliable {
			continue
		}
		if len(payload) > len(p) {
			return 0, nil, io.ErrShortBuffer
		}
		return copy(p, payload), addr, nil
	}
}

func (c *kcpPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > c.transport.maxPayload() {
		return 0, fmt.Errorf("KCP packet exceeds tunnel payload limit")
	}
	if _, err := c.transport.WriteTo(buildPacket(msgTypeReliable, 0, p), addr); err != nil {
		select {
		case <-c.transport.closed:
			return 0, err
		default:
		}
		// KCP treats any write error as fatal for the session. On a live
		// transport a failed send (e.g. no route during a network change) is
		// packet loss that KCP retransmits once the path is back.
	}
	return len(p), nil
}

func (c *kcpPacketConn) Close() error                       { return nil }
func (c *kcpPacketConn) LocalAddr() net.Addr                { return c.transport.LocalAddr() }
func (c *kcpPacketConn) SetDeadline(v time.Time) error      { return c.transport.SetDeadline(v) }
func (c *kcpPacketConn) SetReadDeadline(v time.Time) error  { return c.transport.SetReadDeadline(v) }
func (c *kcpPacketConn) SetWriteDeadline(v time.Time) error { return c.transport.SetWriteDeadline(v) }

func reliableMuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.MaxFrameSize = 16 * 1024
	// peerTransport heartbeats keep the TURN path alive and report inactivity.
	// smux's keepalive would close the session after 30 s without frames, so
	// a temporary outage would end the tunnel instead of resuming it.
	cfg.KeepAliveDisabled = true
	return cfg
}

func configureKCPSession(session *kcp.UDPSession) error {
	if !session.SetMtu(kcpMTU) {
		return fmt.Errorf("cannot set KCP MTU to %d", kcpMTU)
	}
	session.SetStreamMode(true)
	session.SetWindowSize(128, 128)
	session.SetNoDelay(1, 20, 2, 1)
	return nil
}

// reliableSessionError explains why a reliable session stopped: a closed
// transport carries the root cause, such as a lost TURN control connection.
func reliableSessionError(transport *peerTransport, err error) error {
	select {
	case <-transport.closed:
		return transport.closeErr
	default:
	}
	if isClosedErr(err) || errors.Is(err, io.ErrClosedPipe) {
		return errReliableSessionClosed
	}
	return err
}

func readTargetFromStream(r io.Reader) (string, int, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:1]); err != nil {
		return "", 0, err
	}
	var restLen int
	switch head[0] {
	case 1:
		restLen = 4 + 2
	case 4:
		restLen = 16 + 2
	case 3:
		if _, err := io.ReadFull(r, head[1:2]); err != nil {
			return "", 0, err
		}
		restLen = int(head[1]) + 2
	default:
		return "", 0, fmt.Errorf("unsupported address type %d", head[0])
	}
	buf := []byte{head[0]}
	if head[0] == 3 {
		buf = append(buf, head[1])
	}
	rest := make([]byte, restLen)
	if _, err := io.ReadFull(r, rest); err != nil {
		return "", 0, err
	}
	return decodeTargetAddr(append(buf, rest...))
}

// readStreamResult waits for the exit's one-byte SOCKS reply code.
func readStreamResult(stream *smux.Stream) (byte, error) {
	_ = stream.SetReadDeadline(time.Now().Add(reliableOpenTimeout.get()))
	defer stream.SetReadDeadline(time.Time{})
	var result [1]byte
	if _, err := io.ReadFull(stream, result[:]); err != nil {
		return 0, err
	}
	return result[0], nil
}

// stallGuardWriter refreshes the stream's write deadline before every write
// once the peer has finished sending. Progressing writes never time out; a
// write that gets no flow-control window for halfCloseStall fails.
type stallGuardWriter struct {
	stream   *smux.Stream
	peerDone *atomic.Bool
}

func (w stallGuardWriter) Write(p []byte) (int, error) {
	if w.peerDone.Load() {
		_ = w.stream.SetWriteDeadline(time.Now().Add(halfCloseStall.get()))
	}
	return w.stream.Write(p)
}

// copyReliableStream relays both directions and propagates half-closes: when
// one side finishes sending, the other side's write half is shut down while
// its remaining data still flows back.
func copyReliableStream(local net.Conn, stream *smux.Stream) {
	var peerDone atomic.Bool
	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		_, _ = io.Copy(stallGuardWriter{stream, &peerDone}, local)
		_ = stream.CloseWrite()
	}()
	_, err := io.Copy(local, stream)
	cw, canHalfClose := local.(interface{ CloseWrite() error })
	if (err == nil || errors.Is(err, io.EOF)) && canHalfClose && cw.CloseWrite() == nil {
		peerDone.Store(true)
		_ = stream.SetWriteDeadline(time.Now().Add(halfCloseStall.get()))
		<-upDone
	} else {
		// Unblocks a write that waits for flow-control window updates.
		_ = stream.Close()
	}
	_ = local.Close()
	<-upDone
}

// openReliableStream opens a client stream. smux only reports session-fatal
// errors here, so the session is closed and the SOCKS listener ends with it.
func openReliableStream(mux *smux.Session) (*smux.Stream, error) {
	stream, err := mux.OpenStream()
	if err != nil && !mux.IsClosed() {
		log.Printf("Reliable session failed: %v", err)
		_ = mux.Close()
	}
	return stream, err
}

// rejectPeerStreams closes every stream the exit opens. The exit only answers
// streams, so it must not be able to reach services on the client side.
func rejectPeerStreams(mux *smux.Session) {
	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			return
		}
		_ = stream.Close()
	}
}

func runReliableSocksClient(transport *peerTransport, listen string, auth socksAuth, verbose int) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen SOCKS5: %w", err)
	}
	defer ln.Close()
	log.Printf("Reliable SOCKS5 listening on %s", ln.Addr())
	peer, err := transport.waitPeer()
	if err != nil {
		return err
	}
	kcpSession, err := kcp.NewConn2(peer, nil, 0, 0, &kcpPacketConn{transport})
	if err != nil {
		return err
	}
	defer kcpSession.Close()
	if err := configureKCPSession(kcpSession); err != nil {
		return err
	}
	mux, err := smux.Client(kcpSession, reliableMuxConfig())
	if err != nil {
		return err
	}
	defer mux.Close()
	go rejectPeerStreams(mux)
	return serveReliableSocks(ln, mux, transport, auth, verbose)
}

// serveReliableSocks accepts SOCKS clients until the transport or the mux
// ends, and then reports why instead of leaving a dead listener behind.
func serveReliableSocks(ln net.Listener, mux *smux.Session, transport *peerTransport, auth socksAuth, verbose int) error {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-transport.closed:
		case <-mux.CloseChan():
		case <-stop:
			return
		}
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			return reliableSessionError(transport, err)
		}
		go func() {
			if err := handleReliableSocksClient(c, mux, auth); err != nil && verbose > 0 {
				log.Printf("reliable SOCKS connection: %v", err)
			}
		}()
	}
}

func handleReliableSocksClient(c net.Conn, mux *smux.Session, auth socksAuth) error {
	defer c.Close()
	if err := negotiateSocks5Auth(c, auth); err != nil {
		return err
	}
	request, err := readSocks5Request(c)
	if err != nil {
		writeSocks5Reply(c, 8)
		return err
	}
	if request[1] != 1 {
		if request[1] == 3 {
			return handleReliableUDPAssociate(c, request, mux)
		}
		writeSocks5Reply(c, 7)
		return fmt.Errorf("SOCKS command %d is unsupported", request[1])
	}
	host, port, err := parseSocks5RequestAddr(request)
	if err != nil || port == 0 {
		writeSocks5Reply(c, 8)
		return fmt.Errorf("invalid SOCKS target: %v", err)
	}
	addr, err := encodeTargetAddr(host, port)
	if err != nil {
		writeSocks5Reply(c, 8)
		return err
	}
	stream, err := openReliableStream(mux)
	if err != nil {
		writeSocks5Reply(c, 1)
		return err
	}
	defer stream.Close()
	if _, err := stream.Write(addr); err != nil {
		writeSocks5Reply(c, 1)
		return err
	}
	result, err := readStreamResult(stream)
	if err != nil {
		writeSocks5Reply(c, 1)
		return fmt.Errorf("no answer from exit: %w", err)
	}
	writeSocks5Reply(c, result)
	if result != 0 {
		return fmt.Errorf("exit refused target with SOCKS code %d", result)
	}
	copyReliableStream(c, stream)
	return nil
}

func runReliableSocksExit(transport *peerTransport, verbose int) error {
	listener, err := kcp.ServeConn(nil, 0, 0, &kcpPacketConn{transport})
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-transport.closed; _ = listener.Close() }()
	kcpSession, err := listener.AcceptKCP()
	if err != nil {
		return reliableSessionError(transport, err)
	}
	defer kcpSession.Close()
	if err := configureKCPSession(kcpSession); err != nil {
		return err
	}
	mux, err := smux.Server(kcpSession, reliableMuxConfig())
	if err != nil {
		return err
	}
	defer mux.Close()
	go func() {
		select {
		case <-transport.closed:
			_ = mux.Close()
		case <-mux.CloseChan():
		}
	}()
	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			return reliableSessionError(transport, err)
		}
		go func() {
			if err := handleReliableSocksExit(stream); err != nil && verbose > 0 {
				log.Printf("reliable exit stream: %v", err)
			}
		}()
	}
}

func handleReliableSocksExit(stream *smux.Stream) error {
	defer stream.Close()
	var first [1]byte
	if _, err := io.ReadFull(stream, first[:]); err != nil {
		return err
	}
	if first[0] == 0 {
		var command [1]byte
		if _, err := io.ReadFull(stream, command[:]); err != nil {
			return err
		}
		if command[0] == 3 {
			return handleReliableUDPExit(stream)
		}
		_, _ = stream.Write([]byte{7})
		return fmt.Errorf("unknown reliable stream command %d", command[0])
	}
	host, port, err := readTargetFromStream(io.MultiReader(bytes.NewReader(first[:]), stream))
	if err != nil || port == 0 {
		_, _ = stream.Write([]byte{8})
		return fmt.Errorf("invalid reliable target: %v", err)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 15*time.Second)
	if err != nil {
		_, _ = stream.Write([]byte{socksDialError(err)})
		return err
	}
	defer conn.Close()
	if _, err := stream.Write([]byte{0}); err != nil {
		return err
	}
	copyReliableStream(conn, stream)
	return nil
}
