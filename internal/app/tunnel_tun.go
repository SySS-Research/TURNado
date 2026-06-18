package app

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
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

func runAutoClientTun(cfg tunnelCfg) error {
	if err := ensureEncKey(&cfg); err != nil {
		return err
	}
	client, _, cleanup, err := newTurnClient(cfg.Common)
	if err != nil {
		return err
	}
	defer cleanup()

	if mapped, err := client.SendBindingRequestTo(client.TURNServerAddr()); err == nil && cfg.Common.Verbose > 0 {
		log.Printf("XOR-MAPPED-ADDRESS: %s", mapped.String())
	}

	relayConn, err := client.Allocate()
	if err != nil {
		return fmt.Errorf("Allocate (UDP) failed: %w", err)
	}
	defer relayConn.Close()

	relayAddr := relayConn.LocalAddr().String()
	log.Printf("TURN UDP relay allocated at: %s", relayAddr)

	if err := printThisConnString(cfg, relayAddr); err != nil {
		return err
	}

	ps := newPeerState()
	keyBytes, _ := decodeEncKey(cfg.EncKey)
	sec := newSecureSession(cfg.Encrypt, keyBytes)

	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			cs, err := decodeConnString(line)
			if err != nil {
				log.Printf("Pairing input ignored (not a valid connection string): %v", err)
				continue
			}
			peerUDP, err := net.ResolveUDPAddr("udp", cs.Relay)
			if err != nil {
				log.Printf("Pairing failed: resolve peer relay: %v", err)
				continue
			}
			if !ps.setPeerOnce(peerUDP) {
				log.Printf("Already paired; ignoring additional connection string.")
				continue
			}
			if err := client.CreatePermission(peerUDP); err != nil {
				log.Printf("Pairing failed: CreatePermission(%s): %v", peerUDP.String(), err)
				log.Printf("Paired peer set, but permission failed; tunnel likely won't pass traffic.")
				return
			}
			log.Printf("Paired! Permission created for peer %s", peerUDP.String())
			primeChannel(relayConn, peerUDP, sec, cfg.Common.Verbose)
			if sec != nil {
				if err := sec.Start(peerUDP); err != nil {
					log.Printf("Encrypt setup failed: %v", err)
				}
			}
			return
		}
		if err := sc.Err(); err != nil {
			log.Printf("stdin scanner error: %v", err)
		}
	}()

	return runTurnTunClientWithLatePeer(relayConn, ps, sec, "turn%d", cfg.Common.Verbose)
}

func runAutoExitTun(cfg tunnelCfg) error {
	offer, err := decodeConnString(cfg.Connect)
	if err != nil {
		return err
	}
	applyConnStringDefaults(&cfg, offer)
	if err := ensureEncKey(&cfg); err != nil {
		return err
	}

	client, _, cleanup, err := newTurnClient(cfg.Common)
	if err != nil {
		return err
	}
	defer cleanup()

	if mapped, err := client.SendBindingRequestTo(client.TURNServerAddr()); err == nil && cfg.Common.Verbose > 0 {
		log.Printf("XOR-MAPPED-ADDRESS: %s", mapped.String())
	}

	relayConn, err := client.Allocate()
	if err != nil {
		return fmt.Errorf("Allocate (UDP) failed: %w", err)
	}
	defer relayConn.Close()

	relayAddr := relayConn.LocalAddr().String()
	log.Printf("TURN UDP relay allocated at: %s", relayAddr)

	peerUDP, err := net.ResolveUDPAddr("udp", offer.Relay)
	if err != nil {
		return fmt.Errorf("ResolveUDPAddr(peer=%q) failed: %w", offer.Relay, err)
	}

	if err := client.CreatePermission(peerUDP); err != nil {
		return fmt.Errorf("CreatePermission(%s) failed: %w", peerUDP.String(), err)
	}
	log.Printf("Permission created for peer %s", peerUDP.String())

	if err := printThisConnString(cfg, relayAddr); err != nil {
		return err
	}

	keyBytes, _ := decodeEncKey(cfg.EncKey)
	sec := newSecureSession(cfg.Encrypt, keyBytes)
	if sec != nil {
		if err := sec.Start(peerUDP); err != nil {
			return err
		}
	}
	primeChannel(relayConn, peerUDP, sec, cfg.Common.Verbose)

	log.Printf("Exit role active: accepting IP packets over TURN.")
	return runTurnTunExit(relayConn, peerUDP, sec, "turn%d", cfg.Common.Verbose)
}

func runTurnTunClientWithLatePeer(relayConn net.PacketConn, ps *peerState, sec *secureSession, tunName string, verbose int) error {
	tun, err := openTun(tunName)
	if err != nil {
		return err
	}
	defer tun.Close()
	if err := configureTun(tun.name, "10.0.1.2", "255.255.255.0"); err != nil {
		return err
	}
	log.Printf("TUN device opened: %s", tun.name)

	reasm := newFragReassembler()

	// TURN -> TUN
	go func() {
		if err := turnToTunLoop(relayConn, tun, sec, reasm, verbose); err != nil && !isClosedErr(err) && verbose > 0 {
			log.Printf("relay read error: %v", err)
		}
	}()

	<-ps.paired
	peer := ps.getPeer()
	if peer == nil {
		return fmt.Errorf("missing peer for TUN traffic")
	}

	// TUN -> TURN
	buf := make([]byte, 64*1024)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			return fmt.Errorf("tun read error: %w", err)
		}
		if n == 0 {
			continue
		}
		if err := sendTunPayload(relayConn, peer, sec, buf[:n]); err != nil {
			return err
		}
	}
}

func runTurnTunExit(relayConn net.PacketConn, peerUDP *net.UDPAddr, sec *secureSession, tunName string, verbose int) error {
	tun, err := openTun(tunName)
	if err != nil {
		return err
	}
	defer tun.Close()
	if err := configureTun(tun.name, "10.0.1.1", "255.255.255.0"); err != nil {
		return err
	}
	log.Printf("TUN device opened: %s", tun.name)

	reasm := newFragReassembler()

	// TUN -> TURN
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := tun.Read(buf)
			if err != nil {
				if verbose > 0 {
					log.Printf("tun read error: %v", err)
				}
				return
			}
			if n == 0 {
				continue
			}
			if err := sendTunPayload(relayConn, peerUDP, sec, buf[:n]); err != nil {
				return
			}
		}
	}()

	// TURN -> TUN
	if err := turnToTunLoop(relayConn, tun, sec, reasm, verbose); err != nil {
		if isClosedErr(err) {
			return nil
		}
		return fmt.Errorf("exit relay read error: %w", err)
	}
	return nil
}

func handleTunInbound(pkt []byte, tun *tunDevice, sec *secureSession, reasm *fragReassembler, verbose int) {
	h, payload, err := parseHeader(pkt)
	if err != nil {
		if verbose > 0 {
			log.Printf("tun: bad packet: %v", err)
		}
		return
	}
	if h.Type == msgTypeSecure {
		if sec == nil {
			return
		}
		inner, err := sec.unwrapInbound(payload)
		if err != nil {
			if verbose > 0 {
				log.Printf("tun: decrypt failed: %v", err)
			}
			return
		}
		h, payload, err = parseHeader(inner)
		if err != nil {
			if verbose > 0 {
				log.Printf("tun: bad inner packet: %v", err)
			}
			return
		}
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

func sendTunPayload(relayConn net.PacketConn, peer *net.UDPAddr, sec *secureSession, data []byte) error {
	maxPayload := maxDataPayload(sec)
	if len(data) <= maxPayload {
		pkt := buildPacket(msgTypeIP, 0, data)
		wrapped, err := wrapPacket(sec, pkt)
		if err != nil {
			return err
		}
		_, err = relayConn.WriteTo(wrapped, peer)
		return err
	}
	return sendFragPackets(relayConn, peer, sec, data, maxPayload)
}

func sendFragPackets(relayConn net.PacketConn, peer *net.UDPAddr, sec *secureSession, pkt []byte, maxPayload int) error {
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
		wrapped, err := wrapPacket(sec, dataPkt)
		if err != nil {
			return err
		}
		if _, err := relayConn.WriteTo(wrapped, peer); err != nil {
			return err
		}
	}
	return nil
}

func turnToTunLoop(relayConn net.PacketConn, tun *tunDevice, sec *secureSession, reasm *fragReassembler, verbose int) error {
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
		handleTunInbound(buf[:n], tun, sec, reasm, verbose)
	}
}
