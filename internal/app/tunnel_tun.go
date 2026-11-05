package app

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	fragHeaderLen = 8
	fragTimeout   = 10 * time.Second
)

type fragState struct {
	total    int
	buf      []byte
	received int
	seen     map[int]int
	updated  time.Time
}

type fragReassembler struct {
	mu   sync.Mutex
	seen map[uint32]*fragState
}

func newFragReassembler() *fragReassembler {
	return &fragReassembler{seen: make(map[uint32]*fragState)}
}

func (r *fragReassembler) add(id uint32, offset, total int, data []byte) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fs := r.seen[id]
	if fs == nil {
		fs = &fragState{
			total:   total,
			buf:     make([]byte, total),
			seen:    make(map[int]int),
			updated: time.Now(),
		}
		r.seen[id] = fs
	}
	if fs.total != total || offset < 0 || offset+len(data) > fs.total {
		delete(r.seen, id)
		return nil, false
	}
	if prev, ok := fs.seen[offset]; ok {
		if prev == len(data) {
			fs.updated = time.Now()
			return nil, false
		}
	}

	copy(fs.buf[offset:], data)
	if _, ok := fs.seen[offset]; !ok {
		fs.received += len(data)
	}
	fs.seen[offset] = len(data)
	fs.updated = time.Now()

	if fs.received >= fs.total {
		out := fs.buf
		delete(r.seen, id)
		return out, true
	}
	return nil, false
}

func (r *fragReassembler) cleanup(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, fs := range r.seen {
		if now.Sub(fs.updated) > fragTimeout {
			delete(r.seen, id)
		}
	}
}

func runTurnTunClientWithLatePeer(relayConn *peerTransport, cfg tunnelCfg, verbose int) error {
	return runTunEndpoint(relayConn, cfg, cfg.ClientIP, false, verbose)
}

func runTurnTunExit(relayConn *peerTransport, cfg tunnelCfg, verbose int) error {
	return runTunEndpoint(relayConn, cfg, cfg.ExitIP, true, verbose)
}

func runTunEndpoint(relayConn *peerTransport, cfg tunnelCfg, address string, exit bool, verbose int) error {
	tun, err := openTun("turn%d")
	if err != nil {
		return err
	}
	defer tun.Close()
	peerIP := cfg.ExitIP
	if exit {
		peerIP = cfg.ClientIP
	}
	if err := configureTun(tun.name, address, peerIP, "255.255.255.0", relayConn.maxPayload()); err != nil {
		return err
	}
	log.Printf("TUN device opened: %s", tun.name)
	return runTunSession(relayConn, tun, verbose)
}

// Either pump failing closes both resources and unblocks the other pump. In
// particular a lost TURN control connection must not leave an idle TUN hanging.
func runTunSession(relayConn *peerTransport, tun io.ReadWriteCloser, verbose int) error {
	defer tun.Close()
	peer, err := relayConn.waitPeer()
	if err != nil {
		return err
	}
	results := make(chan error, 2)
	go func() {
		err := turnToTunLoop(relayConn, tun, newFragReassembler(), verbose)
		results <- fmt.Errorf("TURN to TUN: %w", err)
	}()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := tun.Read(buf)
			if err != nil {
				results <- fmt.Errorf("TUN read: %w", err)
				return
			}
			if n == 0 {
				continue
			}
			if err := sendTunPayload(relayConn, peer, buf[:n]); err != nil {
				results <- fmt.Errorf("TUN to TURN: %w", err)
				return
			}
		}
	}()
	err = <-results
	_ = tun.Close()
	_ = relayConn.Close()
	<-results
	if isClosedErr(err) {
		return nil
	}
	return err
}

func handleTunInbound(pkt []byte, tun io.Writer, reasm *fragReassembler, verbose int) {
	h, payload, err := parseHeader(pkt)
	if err != nil {
		if verbose > 0 {
			log.Printf("tun: bad packet: %v", err)
		}
		return
	}
	switch h.Type {
	case msgTypeIP:
		if _, err := tun.Write(payload); err != nil && verbose > 0 {
			log.Printf("tun write error: %v", err)
		}
	case msgTypeFrag:
		if len(payload) < fragHeaderLen {
			if verbose > 0 {
				log.Printf("tun: fragment too short")
			}
			return
		}
		id := binary.BigEndian.Uint32(payload[0:4])
		offset := int(binary.BigEndian.Uint16(payload[4:6]))
		total := int(binary.BigEndian.Uint16(payload[6:8]))
		data := payload[fragHeaderLen:]
		if total == 0 {
			return
		}
		out, ok := reasm.add(id, offset, total, data)
		if !ok {
			return
		}
		if _, err := tun.Write(out); err != nil && verbose > 0 {
			log.Printf("tun write error: %v", err)
		}
	default:
		if verbose > 0 {
			log.Printf("tun: unsupported msgType %d", h.Type)
		}
	}
}

var fragSeq uint32

func sendTunPayload(relayConn net.PacketConn, peer *net.UDPAddr, data []byte) error {
	maxPayload := maxDataPayload(relayConn)
	clampTCPMSS(data, maxPayload)
	if len(data) <= maxPayload {
		pkt := buildPacket(msgTypeIP, 0, data)
		_, err := relayConn.WriteTo(pkt, peer)
		return err
	}
	return sendFragPackets(relayConn, peer, data, maxPayload)
}

func sendFragPackets(relayConn net.PacketConn, peer *net.UDPAddr, pkt []byte, maxPayload int) error {
	payloadMax := maxPayload - fragHeaderLen
	if payloadMax <= 0 {
		return fmt.Errorf("max payload too small for fragmentation")
	}
	id := atomic.AddUint32(&fragSeq, 1)
	total := len(pkt)
	for off := 0; off < total; off += payloadMax {
		end := off + payloadMax
		if end > total {
			end = total
		}
		frag := make([]byte, fragHeaderLen+(end-off))
		binary.BigEndian.PutUint32(frag[0:4], id)
		binary.BigEndian.PutUint16(frag[4:6], uint16(off))
		binary.BigEndian.PutUint16(frag[6:8], uint16(total))
		copy(frag[fragHeaderLen:], pkt[off:end])

		dataPkt := buildPacket(msgTypeFrag, 0, frag)
		if _, err := relayConn.WriteTo(dataPkt, peer); err != nil {
			return err
		}
	}
	return nil
}

func turnToTunLoop(relayConn net.PacketConn, tun io.Writer, reasm *fragReassembler, verbose int) error {
	cleanupTicker := time.NewTicker(2 * time.Second)
	defer cleanupTicker.Stop()
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-cleanupTicker.C:
			reasm.cleanup(time.Now())
			continue
		default:
		}
		n, _, err := relayConn.ReadFrom(buf)
		if err != nil {
			return err
		}
		handleTunInbound(buf[:n], tun, reasm, verbose)
	}
}
