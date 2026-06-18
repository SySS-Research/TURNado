package app

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tunnelProtoVersion = 1
	msgTypeOpen        = 1
	msgTypeData        = 2
	msgTypeClose       = 3
	msgTypeIP          = 4
	msgTypeFrag        = 6
)

type clientConn struct {
	id   uint32
	conn net.Conn
	mu   sync.Mutex
}

type peerState struct {
	mu     sync.RWMutex
	peer   *net.UDPAddr
	paired chan struct{} 
}

func newPeerState() *peerState {
	return &peerState{paired: make(chan struct{})}
}

func (ps *peerState) isPaired() bool {
	select {
	case <-ps.paired:
		return true
	default:
		return false
	}
}

func (ps *peerState) getPeer() *net.UDPAddr {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.peer
}

func (ps *peerState) setPeerOnce(p *net.UDPAddr) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.peer != nil {
		return false
	}
	ps.peer = p
	close(ps.paired)
	return true
}

func runTurnSocksClientWithLatePeer(relayConn net.PacketConn, ps *peerState, sec *secureSession, socksPort int, verbose int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen SOCKS5 on %s failed: %w", addr, err)
	}
	defer ln.Close()
	log.Printf("SOCKS5 listening on %s", addr)
	if !ps.isPaired() {
		log.Printf("Waiting for peer connection string on stdin (paste it and press Enter) ...")
	}

	var nextConnID uint32
	var conns sync.Map 
	var tcpUpBytes uint64
	var tcpDownBytes uint64

	if verbose > 1 {
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for range t.C {
				up := atomic.LoadUint64(&tcpUpBytes)
				down := atomic.LoadUint64(&tcpDownBytes)
				log.Printf("stats: tcp_up=%dB tcp_down=%dB", up, down)
			}
		}()
	}

	handlePacket := func(pkt []byte) {
		h, payload, err := parseHeader(pkt)
		if err != nil {
			if verbose > 0 {
				log.Printf("bad packet: %v", err)
			}
			return
		}
		switch h.Type {
		case msgTypeData:
			val, ok := conns.Load(h.ConnID)
			if !ok {
				return
			}
			cc := val.(*clientConn)
			cc.mu.Lock()
			nw, werr := cc.conn.Write(payload)
			cc.mu.Unlock()
			if nw > 0 {
				atomic.AddUint64(&tcpDownBytes, uint64(nw))
			}
			if werr != nil && verbose > 0 {
				log.Printf("tcp write error for conn %d: %v", h.ConnID, werr)
			}
		case msgTypeClose:
			val, ok := conns.LoadAndDelete(h.ConnID)
			if ok {
				_ = val.(*clientConn).conn.Close()
			}
		default:
			if verbose > 0 {
				log.Printf("unsupported msgType %d", h.Type)
			}
		}
	}

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, err := relayConn.ReadFrom(buf)
			if err != nil {
				if !isClosedErr(err) {
					log.Printf("relay read error: %v", err)
				}
				return
			}
			h, payload, err := parseHeader(buf[:n])
			if err != nil {
				if verbose > 0 {
					log.Printf("bad packet: %v", err)
				}
				continue
			}
			if h.Type == msgTypeSecure {
				if sec == nil {
					continue
				}
				inner, err := sec.unwrapInbound(payload)
				if err != nil {
					if verbose > 0 {
						log.Printf("decrypt failed: %v", err)
					}
					continue
				}
				handlePacket(inner)
				continue
			}
			handlePacket(buf[:n])
		}
	}()

	for {
		cliConn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept SOCKS5 failed: %w", err)
		}

		go func(c net.Conn) {
			defer c.Close()

			tmp := make([]byte, 262)
			n, err := c.Read(tmp)
			if err != nil {
				return
			}
			if n < 2 || tmp[0] != 0x05 {
				return
			}
			nmethods := int(tmp[1])
			if n < 2+nmethods {
				if _, err = io.ReadFull(c, tmp[n:2+nmethods]); err != nil {
					return
				}
			}
			if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
				return
			}

			n, err = c.Read(tmp)
			if err != nil {
				return
			}
			if n < 4 || tmp[0] != 0x05 {
				return
			}
			cmd := tmp[1]
			if cmd != 0x01 {
				_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}

			host, port, err := parseSocks5RequestAddr(tmp[:n])
			if err != nil {
				_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}

			<-ps.paired
			peer := ps.getPeer()
			if peer == nil {
				_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}

			connID := atomic.AddUint32(&nextConnID, 1)
			cc := &clientConn{id: connID, conn: c}
			conns.Store(connID, cc)

			openPayload, err := encodeTargetAddr(host, port)
			if err != nil {
				conns.Delete(connID)
				_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}

			pkt := buildPacket(msgTypeOpen, connID, openPayload)
			wrapped, err := wrapPacket(sec, pkt)
			if err != nil {
				conns.Delete(connID)
				_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}
			if _, err := relayConn.WriteTo(wrapped, peer); err != nil {
				conns.Delete(connID)
				_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}

			_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

			buf := make([]byte, 16*1024)
			for {
				n, err := c.Read(buf)
				if err != nil {
					closePkt := buildPacket(msgTypeClose, connID, nil)
					if wrapped, werr := wrapPacket(sec, closePkt); werr == nil {
						_, _ = relayConn.WriteTo(wrapped, peer)
					}
					conns.Delete(connID)
					return
				}
				if n == 0 {
					continue
				}
				atomic.AddUint64(&tcpUpBytes, uint64(n))
				offset := 0
				maxPayload := maxDataPayload(sec)
				for offset < n {
					end := offset + maxPayload
					if end > n {
						end = n
					}
					chunk := buf[offset:end]
					dataPkt := buildPacket(msgTypeData, connID, chunk)
					wrapped, werr := wrapPacket(sec, dataPkt)
					if werr != nil {
						conns.Delete(connID)
						return
					}
					if _, werr = relayConn.WriteTo(wrapped, peer); werr != nil {
						conns.Delete(connID)
						return
					}
					offset = end
				}
			}
		}(cliConn)
	}
}
