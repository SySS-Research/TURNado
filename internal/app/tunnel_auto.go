package app

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

func ensureEncKey(cfg *tunnelCfg) error {
	if !cfg.Encrypt || cfg.EncKey != "" {
		return nil
	}
	_, k, err := generateEncKey()
	if err != nil {
		return err
	}
	cfg.EncKey = k
	return nil
}

func runTunnelAutoSocks(cfg tunnelCfg) error {
	if cfg.Connect == "" {
		return runAutoClient(cfg)
	}
	return runAutoExit(cfg)
}

func runTunnelAutoTun(cfg tunnelCfg) error {
	if cfg.Connect == "" {
		return runAutoClientTun(cfg)
	}
	return runAutoExitTun(cfg)
}

func printThisConnString(cfg tunnelCfg, relayAddr string) error {
	cs := connStringV1{
		V:       1,
		Turn:    cfg.Common.Turn,
		User:    cfg.Common.Username,
		Pass:    cfg.Common.Password,
		Control: cfg.Common.Transport,
		Insec:   cfg.Common.Insecure,
		Enc:     cfg.Encrypt,
		Key:     cfg.EncKey,
		Relay:   relayAddr,
	}
	s, err := encodeConnString(cs)
	if err != nil {
		return err
	}
	fmt.Printf("Connection string:\n%s\n", s)
	return nil
}

func runAutoClient(cfg tunnelCfg) error {
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

	return runTurnSocksClientWithLatePeer(relayConn, ps, sec, cfg.SocksPort, cfg.Common.Verbose)
}

func runAutoExit(cfg tunnelCfg) error {
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

	log.Printf("Exit role active: accepting OPEN over TURN.")
	return runTurnExit(relayConn, peerUDP, sec, cfg.Common.Verbose)
}
