package app

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

const maxSocksUDPDatagram = 65507

func writeUDPRecord(w io.Writer, payload []byte) error {
	if len(payload) > maxSocksUDPDatagram {
		return fmt.Errorf("UDP datagram too large")
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(payload)))
	if n, err := w.Write(length[:]); err != nil {
		return err
	} else if n != len(length) {
		return io.ErrShortWrite
	}
	n, err := w.Write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}

func readUDPRecord(r io.Reader) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n == 0 || n > maxSocksUDPDatagram {
		return nil, fmt.Errorf("invalid UDP record length %d", n)
	}
	payload := make([]byte, n)
	_, err := io.ReadFull(r, payload)
	return payload, err
}

func parseSocksUDPDatagram(payload []byte) (string, int, []byte, error) {
	if len(payload) < 4 || payload[0] != 0 || payload[1] != 0 || payload[2] != 0 {
		return "", 0, nil, fmt.Errorf("invalid or fragmented SOCKS UDP datagram")
	}
	addr := payload[3:]
	var n int
	switch addr[0] {
	case 1:
		n = 1 + 4 + 2
	case 4:
		n = 1 + 16 + 2
	case 3:
		if len(addr) < 2 {
			return "", 0, nil, io.ErrUnexpectedEOF
		}
		n = 2 + int(addr[1]) + 2
	default:
		return "", 0, nil, fmt.Errorf("invalid SOCKS UDP address type")
	}
	if len(addr) < n {
		return "", 0, nil, io.ErrUnexpectedEOF
	}
	host, port, err := decodeTargetAddr(addr[:n])
	return host, port, addr[n:], err
}

func socksUDPDatagram(host string, port int, payload []byte) ([]byte, error) {
	addr, err := encodeTargetAddr(host, port)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 3, 3+len(addr)+len(payload))
	out = append(out, addr...)
	return append(out, payload...), nil
}

func writeSocks5BindReply(c net.Conn, code byte, addr *net.UDPAddr) error {
	if addr == nil {
		writeSocks5Reply(c, code)
		return nil
	}
	bind, err := encodeTargetAddr(addr.IP.String(), addr.Port)
	if err != nil {
		return err
	}
	_, err = c.Write(append([]byte{5, code, 0}, bind...))
	return err
}

func handleReliableUDPAssociate(c net.Conn, request []byte, mux *smux.Session) error {
	local := c.LocalAddr().(*net.TCPAddr)
	requestedHost, requestedPort, err := parseSocks5RequestAddr(request)
	if err != nil {
		writeSocks5Reply(c, 8)
		return err
	}
	remote := c.RemoteAddr().(*net.TCPAddr)
	requestedIP := net.ParseIP(requestedHost)
	if requestedIP == nil || !requestedIP.IsUnspecified() && !requestedIP.Equal(remote.IP) {
		writeSocks5Reply(c, 2)
		return fmt.Errorf("SOCKS UDP source must match the TCP client")
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		writeSocks5Reply(c, 1)
		return err
	}
	defer udp.Close()
	stream, err := openReliableStream(mux)
	if err != nil {
		writeSocks5Reply(c, 1)
		return err
	}
	defer stream.Close()
	if _, err := stream.Write([]byte{0, 3}); err != nil {
		writeSocks5Reply(c, 1)
		return err
	}
	result, err := readStreamResult(stream)
	if err != nil {
		writeSocks5Reply(c, 1)
		return fmt.Errorf("no answer from exit: %w", err)
	}
	if result != 0 {
		writeSocks5Reply(c, result)
		return fmt.Errorf("UDP exit refused association")
	}
	if err := writeSocks5BindReply(c, 0, udp.LocalAddr().(*net.UDPAddr)); err != nil {
		return err
	}
	var sender *net.UDPAddr
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, maxSocksUDPDatagram)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !from.IP.Equal(remote.IP) || requestedPort != 0 && from.Port != requestedPort {
				continue
			}
			if _, _, _, err := parseSocksUDPDatagram(buf[:n]); err != nil {
				continue
			}
			mu.Lock()
			if sender == nil {
				sender = from
			}
			allowed := sender.IP.Equal(from.IP) && sender.Port == from.Port
			mu.Unlock()
			if allowed {
				if err := writeUDPRecord(stream, buf[:n]); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		for {
			pkt, err := readUDPRecord(stream)
			if err != nil {
				_ = udp.Close()
				_ = c.Close()
				return
			}
			mu.Lock()
			to := sender
			mu.Unlock()
			if to != nil {
				_, _ = udp.WriteToUDP(pkt, to)
			}
		}
	}()
	_, _ = io.Copy(io.Discard, c) // The TCP control connection owns the association.
	_ = udp.Close()
	_ = stream.Close()
	<-done
	return nil
}

func handleReliableUDPExit(stream *smux.Stream) error {
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		_, _ = stream.Write([]byte{1})
		return err
	}
	defer udp.Close()
	if _, err := stream.Write([]byte{0}); err != nil {
		return err
	}
	allowed := make(map[string]time.Time)
	var mu sync.RWMutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, maxSocksUDPDatagram)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.RLock()
			last, ok := allowed[from.String()]
			mu.RUnlock()
			if !ok || time.Since(last) > time.Minute {
				continue
			}
			pkt, err := socksUDPDatagram(from.IP.String(), from.Port, buf[:n])
			if err == nil {
				if err := writeUDPRecord(stream, pkt); err != nil {
					return
				}
			}
		}
	}()
	for {
		pkt, err := readUDPRecord(stream)
		if err != nil {
			break
		}
		host, port, body, err := parseSocksUDPDatagram(pkt)
		if err != nil || port == 0 {
			continue
		}
		to, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(port)))
		if err != nil {
			continue
		}
		mu.Lock()
		if len(allowed) >= 1024 {
			for addr, last := range allowed {
				if time.Since(last) > time.Minute {
					delete(allowed, addr)
				}
			}
			if len(allowed) >= 1024 {
				mu.Unlock()
				continue
			}
		}
		allowed[to.String()] = time.Now()
		mu.Unlock()
		_ = udp.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = udp.WriteToUDP(body, to)
	}
	_ = udp.Close()
	<-done
	return nil
}
