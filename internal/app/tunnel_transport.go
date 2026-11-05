package app

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/transport/v4/deadline"
	"github.com/pion/transport/v4/packetio"
)

// peerTransport owns the relay's only reader. The application sees tunnel
// packets; DTLS and SRTP share the relay using RFC 7983 demultiplexing.
// Nothing is delivered to the application until pairing/verification succeeds.
type peerTransport struct {
	relay                       net.PacketConn
	identity                    *dtlsIdentity
	peer                        *net.UDPAddr
	secure                      *secureSession
	ready, closed, firstDTLS    chan struct{}
	data, handshake             *packetio.Buffer
	readDeadline, writeDeadline *deadline.Deadline
	pairMu, readMu, writeMu     sync.Mutex
	started                     bool
	closeOnce                   sync.Once
	closeErr                    error // Published by closing closed.
	lastSeen                    atomic.Int64
	stale                       atomic.Bool
	seenValid                   atomic.Bool
}

func newPeerTransport(relay net.PacketConn, identity *dtlsIdentity) *peerTransport {
	t := &peerTransport{
		relay: relay, identity: identity,
		ready: make(chan struct{}), closed: make(chan struct{}), firstDTLS: make(chan struct{}, 1),
		data: packetio.NewBuffer(), handshake: packetio.NewBuffer(),
		readDeadline: deadline.New(), writeDeadline: deadline.New(),
	}
	t.data.SetLimitCount(1024)
	t.handshake.SetLimitCount(128)
	return t
}

func (t *peerTransport) pair(ctx context.Context, peer *net.UDPAddr, fingerprint string, isClient bool) (err error) {
	if peer == nil {
		return fmt.Errorf("missing peer relay address")
	}
	if (t.identity != nil) != (fingerprint != "") {
		return fmt.Errorf("peers must use the same encryption mode")
	}
	if fingerprint != "" {
		if _, err := parseFingerprint(fingerprint); err != nil {
			return err
		}
	}
	t.pairMu.Lock()
	if t.started {
		t.pairMu.Unlock()
		return fmt.Errorf("transport already paired")
	}
	t.started = true
	t.peer = peer
	t.pairMu.Unlock()
	defer func() {
		if err != nil {
			// Keep the cause so the waiting tunnel reports why pairing failed.
			_ = t.closeWithError(fmt.Errorf("pairing failed: %w", err))
		}
	}()
	go t.readLoop()
	if t.identity != nil {
		// The exit waits for the user to paste its answer into the client. Start
		// the bounded handshake timeout only once the first DTLS packet arrives.
		if !isClient {
			select {
			case <-t.firstDTLS:
			case <-ctx.Done():
				return ctx.Err()
			case <-t.closed:
				return net.ErrClosed
			}
		}
		handshakeCtx, cancel := context.WithTimeout(ctx, dtlsHandshakeTimeout)
		defer cancel()
		endpoint := &dtlsEndpoint{transport: t}
		t.secure, err = handshakeDTLS(handshakeCtx, endpoint, peer, t.identity, fingerprint, isClient)
		if err != nil {
			return err
		}
		dc := t.secure.conn
		go func() { <-t.closed; _ = dc.Close() }()
		go func() {
			// DTLS continues handling retransmissions and alerts after key export.
			// Tunnel payloads are accepted only from the SRTP endpoint.
			_, err := io.Copy(io.Discard, dc)
			if err == nil {
				err = io.EOF
			}
			_ = t.closeWithError(fmt.Errorf("DTLS connection closed: %w", err))
		}()
	}
	select {
	case <-t.closed:
		return net.ErrClosed
	default:
	}
	close(t.ready)
	t.lastSeen.Store(time.Now().UnixNano())
	go t.heartbeat()
	return nil
}

const (
	heartbeatInterval = 15 * time.Second
	peerTimeout       = 60 * time.Second
)

func (t *peerTransport) heartbeat() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.closed:
			return
		case <-ticker.C:
			t.checkPeerTimeout(time.Now())
			if _, err := t.WriteTo(buildPacket(msgTypePing, 0, nil), t.peer); err != nil {
				log.Printf("heartbeat send failed; retrying while allocation is active: %v", err)
			}
		}
	}
}

func (t *peerTransport) checkPeerTimeout(now time.Time) {
	if now.Sub(time.Unix(0, t.lastSeen.Load())) <= peerTimeout {
		return
	}
	if t.stale.CompareAndSwap(false, true) {
		log.Printf("Peer inactive for %s; waiting on current TURN allocation", peerTimeout)
	}
}

func (t *peerTransport) noteValidPeerPacket() {
	t.lastSeen.Store(time.Now().UnixNano())
	if t.stale.Swap(false) {
		log.Printf("Peer traffic resumed on current TURN allocation")
	}
	if t.identity == nil && t.seenValid.CompareAndSwap(false, true) {
		log.Printf("First valid packet received from peer %s", t.peer)
	}
}

func sameUDPAddr(a net.Addr, b *net.UDPAddr) bool {
	u, ok := a.(*net.UDPAddr)
	return ok && b != nil && u.Port == b.Port && u.Zone == b.Zone && u.IP.Equal(b.IP)
}

func (t *peerTransport) readLoop() {
	defer t.Close()
	buf := make([]byte, 64*1024)
	for {
		n, from, err := t.relay.ReadFrom(buf)
		if err != nil {
			_ = t.closeWithError(fmt.Errorf("TURN relay read: %w", err))
			return
		}
		if n == 0 || n > maxPacketSize || !sameUDPAddr(from, t.peer) {
			continue
		}
		pkt := buf[:n]
		if t.identity == nil {
			_, _ = t.data.Write(pkt)
			continue
		}
		switch {
		case pkt[0] >= 20 && pkt[0] <= 63:
			if _, err := t.handshake.Write(pkt); err == nil {
				select {
				case t.firstDTLS <- struct{}{}:
				default:
				}
			}
		case pkt[0] == 0x80:
			_, _ = t.data.Write(pkt)
		default:
			// In encrypted mode, plaintext and unknown protocols never reach
			// the application.
		}
	}
}

func (t *peerTransport) waitReady(d *deadline.Deadline) error {
	select {
	case <-t.closed:
		return t.closeErr
	case <-d.Done():
		return os.ErrDeadlineExceeded
	default:
	}
	select {
	case <-t.ready:
		select {
		case <-t.closed:
			return t.closeErr
		default:
			return nil
		}
	case <-t.closed:
		return t.closeErr
	case <-d.Done():
		return os.ErrDeadlineExceeded
	}
}

func (t *peerTransport) waitPeer() (*net.UDPAddr, error) {
	if err := t.waitReady(t.writeDeadline); err != nil {
		return nil, err
	}
	return t.peer, nil
}

func (t *peerTransport) ReadFrom(p []byte) (int, net.Addr, error) {
	if err := t.waitReady(t.readDeadline); err != nil {
		return 0, nil, err
	}
	t.readMu.Lock()
	defer t.readMu.Unlock()
	var buf [maxPacketSize]byte
	for {
		n, err := t.data.Read(buf[:])
		if err != nil {
			select {
			case <-t.closed:
				return 0, nil, t.closeErr
			default:
			}
			return 0, nil, err
		}
		pkt := buf[:n]
		if t.secure != nil {
			pkt, err = t.secure.decrypt(pkt)
			if err != nil {
				// Includes failed authentication and replays.
				continue
			}
		}
		n = copy(p, pkt)
		h, _, headerErr := parseHeader(pkt)
		if headerErr == nil {
			t.noteValidPeerPacket()
			if h.Type == msgTypePing {
				_, _ = t.WriteTo(buildPacket(msgTypePong, 0, nil), t.peer)
				continue
			}
			if h.Type == msgTypePong {
				continue
			}
		}
		if n < len(pkt) {
			return n, t.peer, io.ErrShortBuffer
		}
		return n, t.peer, nil
	}
}

func (t *peerTransport) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := t.waitReady(t.writeDeadline); err != nil {
		return 0, err
	}
	if !sameUDPAddr(addr, t.peer) {
		return 0, fmt.Errorf("destination is not the paired peer")
	}
	if len(p) > t.maxPayload()+tunnelHeaderLen {
		return 0, fmt.Errorf("tunnel packet exceeds MTU")
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	pkt := p
	var err error
	if t.secure != nil {
		pkt, err = t.secure.encrypt(p)
		if err != nil {
			return 0, err
		}
	}
	if _, err := t.writeRelayPacket(pkt); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *peerTransport) writeRelayPacket(pkt []byte) (int, error) {
	n, err := t.relay.WriteTo(pkt, t.peer)
	if err != nil {
		return 0, err
	}
	// Pion TURN returns the complete STUN message length for SendIndication
	// while ChannelBind is pending/failed, but the payload length for ChannelData.
	// Normalize both successful paths to net.Conn/net.PacketConn semantics.
	if n < len(pkt) {
		return 0, io.ErrShortWrite
	}
	return len(pkt), nil
}

func (t *peerTransport) maxPayload() int {
	if t.identity != nil {
		return maxPacketSize - tunnelHeaderLen - srtpOverhead
	}
	return maxPacketSize - tunnelHeaderLen
}

func (t *peerTransport) Close() error {
	return t.closeWithError(net.ErrClosed)
}

func (t *peerTransport) closeWithError(reason error) error {
	var err error
	t.closeOnce.Do(func() {
		t.closeErr = reason
		close(t.closed)
		_ = t.data.Close()
		_ = t.handshake.Close()
		err = t.relay.Close()
	})
	return err
}

func (t *peerTransport) LocalAddr() net.Addr { return t.relay.LocalAddr() }
func (t *peerTransport) SetDeadline(v time.Time) error {
	if err := t.SetReadDeadline(v); err != nil {
		return err
	}
	return t.SetWriteDeadline(v)
}
func (t *peerTransport) SetReadDeadline(v time.Time) error {
	t.readDeadline.Set(v)
	return t.data.SetReadDeadline(v)
}
func (t *peerTransport) SetWriteDeadline(v time.Time) error {
	t.writeDeadline.Set(v)
	return t.relay.SetWriteDeadline(v)
}

// Closing the DTLS endpoint only releases its reader; peerTransport owns the
// relay and closes all endpoints together. This avoids competing relay reads.
type dtlsEndpoint struct{ transport *peerTransport }

func (e *dtlsEndpoint) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := e.transport.handshake.Read(p)
	return n, e.transport.peer, err
}
func (e *dtlsEndpoint) WriteTo(p []byte, _ net.Addr) (int, error) {
	return e.transport.writeRelayPacket(p)
}
func (e *dtlsEndpoint) Close() error        { return e.transport.handshake.Close() }
func (e *dtlsEndpoint) LocalAddr() net.Addr { return e.transport.LocalAddr() }
func (e *dtlsEndpoint) SetReadDeadline(v time.Time) error {
	return e.transport.handshake.SetReadDeadline(v)
}
func (e *dtlsEndpoint) SetWriteDeadline(v time.Time) error {
	return e.transport.relay.SetWriteDeadline(v)
}
func (e *dtlsEndpoint) SetDeadline(v time.Time) error {
	if err := e.SetReadDeadline(v); err != nil {
		return err
	}
	return e.SetWriteDeadline(v)
}
