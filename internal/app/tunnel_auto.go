package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

func runTunnelAutoSocks(cfg tunnelCfg) error { return runTunnelAuto(cfg, false) }
func runTunnelAutoTun(cfg tunnelCfg) error   { return runTunnelAuto(cfg, true) }

func printThisConnString(cfg tunnelCfg, relayAddr string, identity *dtlsIdentity, replyTo string, tunMode bool) error {
	cs := connString{
		V: 1, Turn: cfg.Common.Turn, User: cfg.Common.Username, Pass: cfg.Common.Password,
		Control: cfg.Common.Transport, Insec: cfg.Common.Insecure, Enc: cfg.Encrypt, Relay: relayAddr,
		Reliable: !tunMode,
	}
	cs.ReplyTo = replyTo
	if identity != nil {
		cs.V, cs.Fingerprint = 2, identity.fingerprint
	}
	if !tunMode {
		cs.V = 3
	}
	s, err := encodeConnString(cs, cfg.Passphrase)
	if err != nil {
		return err
	}
	fmt.Printf("Connection string:\n%s\n", s)
	return nil
}

// Both modes use the same pairing and encryption lifecycle.
func runTunnelAuto(cfg tunnelCfg, tunMode bool) error {
	var offer connString
	var err error
	if cfg.Connect != "" {
		offer, err = decodeConnString(cfg.Connect, cfg.Passphrase)
		if err != nil {
			return err
		}
		if err = applyConnStringDefaults(&cfg, offer); err != nil {
			return err
		}
	}
	if cfg.Connect != "" && offer.Reliable == tunMode {
		return fmt.Errorf("connection string is for a different tunnel mode")
	}
	if cfg.RootlessExit && (!tunMode || cfg.Connect == "") {
		return fmt.Errorf("--rootless-exit requires the tunnel exit role")
	}
	if err = validateCommon(cfg.Common); err != nil {
		return err
	}
	var identity *dtlsIdentity
	if cfg.Encrypt {
		identity, err = newDTLSIdentity()
		if err != nil {
			return fmt.Errorf("generate DTLS identity: %w", err)
		}
	}
	client, control, cleanup, err := newTurnClient(cfg.Common)
	if err != nil {
		return err
	}
	defer cleanup()
	if mapped, err := client.SendBindingRequestTo(client.TURNServerAddr()); err == nil && cfg.Common.Verbose > 0 {
		log.Printf("XOR-MAPPED-ADDRESS: %s", mapped.String())
	}
	relay, err := client.Allocate()
	if err != nil {
		return fmt.Errorf("Allocate (UDP) failed: %w", err)
	}
	transport := newPeerTransport(relay, identity)
	defer transport.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchTunnelControl(ctx, control, transport)
	log.Printf("TURN UDP relay allocated at: %s", relay.LocalAddr())
	if cfg.Connect == "" {
		if err = printThisConnString(cfg, relay.LocalAddr().String(), identity, "", tunMode); err != nil {
			return err
		}
		go readPeerAnswer(ctx, os.Stdin, client, transport, cfg.Passphrase, !tunMode, cfg.Common.Verbose)
		if tunMode {
			return runTurnTunClientWithLatePeer(transport, cfg, cfg.Common.Verbose)
		}
		listen := net.JoinHostPort(cfg.SocksListen, fmt.Sprint(cfg.SocksPort))
		return runReliableSocksClient(transport, listen, socksAuth{cfg.SocksUser, cfg.SocksPass}, cfg.Common.Verbose)
	}
	peer, err := net.ResolveUDPAddr("udp", offer.Relay)
	if err != nil {
		return fmt.Errorf("resolve peer relay: %w", err)
	}
	if err = client.CreatePermission(peer); err != nil {
		return err
	}
	log.Printf("Permission created for peer %s", peer)
	// Print before waiting for DTLS: the client needs this fingerprint first.
	if err = printThisConnString(cfg, relay.LocalAddr().String(), identity, offer.Relay, tunMode); err != nil {
		return err
	}
	if cfg.Encrypt {
		log.Printf("Waiting for authenticated DTLS handshake from client ...")
	}
	if err = transport.pair(ctx, peer, offer.Fingerprint, false); err != nil {
		return err
	}
	logPeerReady(cfg.Encrypt, peer)
	if !cfg.Encrypt {
		primeChannel(transport, peer, cfg.Common.Verbose)
	}
	if tunMode {
		log.Printf("Exit role active: accepting IP packets over TURN.")
		if cfg.RootlessExit {
			return runTurnTunRootlessExit(transport, cfg.ExitIP, cfg.Common.Verbose)
		}
		return runTurnTunExit(transport, cfg, cfg.Common.Verbose)
	}
	log.Printf("Exit role active: accepting OPEN over TURN.")
	return runReliableSocksExit(transport, cfg.Common.Verbose)
}

func watchTunnelControl(ctx context.Context, control net.PacketConn, transport *peerTransport) {
	observed, ok := control.(*observedControlConn)
	if !ok {
		return
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-transport.closed:
		case <-observed.failed:
			_ = transport.closeWithError(fmt.Errorf("TURN control connection lost: %w", observed.failure))
		}
	}()
}

type permissionClient interface {
	CreatePermission(...net.Addr) error
}

func readPeerAnswer(ctx context.Context, in io.Reader, client permissionClient, transport *peerTransport, passphrase string, reliable bool, verbose int) {
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if pairPeerAnswer(ctx, client, transport, line, passphrase, reliable, verbose) {
			return
		}
	}
	err := errors.New("pairing input closed before a peer connection string was supplied")
	if scanErr := sc.Err(); scanErr != nil {
		err = fmt.Errorf("read pairing input: %w", scanErr)
	}
	_ = transport.closeWithError(err)
}

func pairPeerAnswer(ctx context.Context, client permissionClient, transport *peerTransport, line, passphrase string, reliable bool, verbose int) bool {
	cs, err := decodeConnString(line, passphrase)
	if err != nil {
		log.Printf("Pairing input ignored: %v", err)
		return false
	}
	if cs.Enc != (transport.identity != nil) {
		log.Printf("Pairing input ignored: peers must use the same encryption mode")
		return false
	}
	if cs.Reliable != reliable {
		log.Printf("Pairing input ignored: connection string is for a different tunnel mode")
		return false
	}
	if cs.ReplyTo != "" && cs.ReplyTo != transport.LocalAddr().String() {
		log.Printf("Pairing input ignored: answer is for relay %s, not %s", cs.ReplyTo, transport.LocalAddr())
		return false
	}
	peer, err := net.ResolveUDPAddr("udp", cs.Relay)
	if err != nil {
		log.Printf("Pairing failed: resolve peer relay: %v", err)
		return false
	}
	if err = client.CreatePermission(peer); err != nil {
		log.Printf("Pairing failed: %v", err)
		return false
	}
	if err = transport.pair(ctx, peer, cs.Fingerprint, true); err != nil {
		// The tunnel waiting for the peer reports this error and exits.
		_ = transport.closeWithError(fmt.Errorf("pairing failed: %w", err))
		return true
	}
	logPeerReady(cs.Enc, peer)
	if !cs.Enc {
		primeChannel(transport, peer, verbose)
	}
	return true
}

func logPeerReady(encrypted bool, peer *net.UDPAddr) {
	if encrypted {
		log.Printf("Paired with %s: DTLS fingerprint verified; SRTP_AES128_CM_HMAC_SHA1_80 active", peer)
	} else {
		log.Printf("Permission ready for peer %s; waiting for peer traffic", peer)
	}
}
