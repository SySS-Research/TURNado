package app

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type exitConn struct {
	id  uint32
	tcp net.Conn
	mu  sync.Mutex
}

func runTurnExit(relayConn net.PacketConn, peerUDP *net.UDPAddr, sec *secureSession, verbose int) error {
	conns := make(map[uint32]*exitConn)
	var mu sync.Mutex
	var tcpToPeerBytes uint64
	var peerToTCPBytes uint64

	if verbose > 1 {
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for range t.C {
				in := atomic.LoadUint64(&peerToTCPBytes)
				out := atomic.LoadUint64(&tcpToPeerBytes)
				log.Printf("stats: peer_to_tcp=%dB tcp_to_peer=%dB", in, out)
			}
		}()
	}

	handlePacket := func(pkt []byte) {
		h, payload, err := parseHeader(pkt)
		if err != nil {
			if verbose > 0 {
				log.Printf("exit: bad packet: %v", err)
			}
			return
		}

		mu.Lock()
		ec := conns[h.ConnID]

		switch h.Type {
		case msgTypeOpen:
			host, port, err := decodeTargetAddr(payload)
			if err != nil {
				mu.Unlock()
				return
			}
			addrStr := net.JoinHostPort(host, strconv.Itoa(port))
			if verbose > 0 {
				log.Printf("exit: OPEN conn=%d -> %s", h.ConnID, addrStr)
			}

			if ec != nil {
				_ = ec.tcp.Close()
			}

			dstTCP, err := net.Dial("tcp", addrStr)
			if err != nil {
				if verbose > 0 {
					log.Printf("exit: TCP dial failed: %v", err)
				}
				closePkt := buildPacket(msgTypeClose, h.ConnID, nil)
				if wrapped, werr := wrapPacket(sec, closePkt); werr == nil {
					_, _ = relayConn.WriteTo(wrapped, peerUDP)
				}
				mu.Unlock()
				return
			}

			ec = &exitConn{id: h.ConnID, tcp: dstTCP}
			conns[h.ConnID] = ec

			go func(id uint32, tcp net.Conn) {
				defer func() {
					_ = tcp.Close()
					mu.Lock()
					delete(conns, id)
					mu.Unlock()
					closePkt := buildPacket(msgTypeClose, id, nil)
					if wrapped, werr := wrapPacket(sec, closePkt); werr == nil {
						_, _ = relayConn.WriteTo(wrapped, peerUDP)
					}
				}()

				b := make([]byte, 16*1024)
				for {
					n, err := tcp.Read(b)
					if err != nil {
						return
					}
					if n > 0 {
						atomic.AddUint64(&tcpToPeerBytes, uint64(n))
					}
					offset := 0
					for offset < n {
						end := offset + maxDataPayload(sec)
						if end > n {
							end = n
						}
						chunk := b[offset:end]
						dataPkt := buildPacket(msgTypeData, id, chunk)
						wrapped, werr := wrapPacket(sec, dataPkt)
						if werr != nil {
							return
						}
						if _, werr = relayConn.WriteTo(wrapped, peerUDP); werr != nil {
							return
						}
						offset = end
					}
				}
			}(h.ConnID, dstTCP)

		case msgTypeData:
			if ec == nil {
				mu.Unlock()
				return
			}
			ec.mu.Lock()
			nw, _ := ec.tcp.Write(payload)
			ec.mu.Unlock()
			if nw > 0 {
				atomic.AddUint64(&peerToTCPBytes, uint64(nw))
			}

		case msgTypeClose:
			if ec != nil {
				_ = ec.tcp.Close()
				delete(conns, h.ConnID)
			}

		default:
			if verbose > 0 {
				log.Printf("exit: unsupported msgType %d", h.Type)
			}
		}

		mu.Unlock()
	}

	buf := make([]byte, 64*1024)
	for {
		n, _, err := relayConn.ReadFrom(buf)
		if err != nil {
			if isClosedErr(err) {
				return nil
			}
			return fmt.Errorf("exit relay read error: %w", err)
		}

		h, payload, err := parseHeader(buf[:n])
		if err != nil {
			if verbose > 0 {
				log.Printf("exit: bad packet: %v", err)
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
					log.Printf("exit: decrypt failed: %v", err)
				}
				continue
			}
			handlePacket(inner)
			continue
		}
		handlePacket(buf[:n])
	}
}
