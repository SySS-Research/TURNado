package app

import (
	"fmt"
	"io"
	"log"
	"net"
)

func writeSocks5Reply(c net.Conn, code byte) {
	_, _ = c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}

func runDirectSocks(cfg commonConfig, listen string, auth socksAuth) error {
	if cfg.Transport == "udp" {
		cfg.Transport = "tcp"
	}
	if cfg.Transport == "dtls" {
		return fmt.Errorf("RFC 6062 TCP allocations require -T tcp or -T tls")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen SOCKS5: %w", err)
	}
	defer ln.Close()
	log.Printf("Direct TURN SOCKS5 listening on %s", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			if isClosedErr(err) {
				return nil
			}
			return fmt.Errorf("accept SOCKS5: %w", err)
		}
		go func() {
			if err := handleDirectSocksConn(c, cfg, auth); err != nil && cfg.Verbose > 0 {
				log.Printf("direct SOCKS connection: %v", err)
			}
		}()
	}
}

func handleDirectSocksConn(c net.Conn, cfg commonConfig, auth socksAuth) error {
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
		writeSocks5Reply(c, 7)
		return fmt.Errorf("SOCKS command %d is unsupported", request[1])
	}
	host, port, err := parseSocks5RequestAddr(request)
	if err != nil || port == 0 {
		writeSocks5Reply(c, 8)
		return fmt.Errorf("invalid SOCKS target: %v", err)
	}
	target, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		writeSocks5Reply(c, 4)
		return err
	}
	client, _, cleanup, err := newTurnClient(cfg)
	if err != nil {
		writeSocks5Reply(c, 1)
		return err
	}
	defer cleanup()
	allocation, err := client.AllocateTCP()
	if err != nil {
		writeSocks5Reply(c, 1)
		return err
	}
	defer allocation.Close()
	raw, err := dialTurnDataConn(cfg)
	if err != nil {
		writeSocks5Reply(c, 1)
		return err
	}
	remote, err := allocation.DialTCPWithConn(asTURNTCPConn(raw), "tcp", target)
	if err != nil {
		_ = raw.Close()
		writeSocks5Reply(c, socksDialError(err))
		return err
	}
	defer remote.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	upDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(remote, c)
		_ = remote.CloseWrite()
		close(upDone)
	}()
	_, downErr := io.Copy(c, remote)
	_ = c.Close()
	<-upDone
	return downErr
}
