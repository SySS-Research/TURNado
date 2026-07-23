package app

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/spf13/pflag"
)

type forwardCfg struct {
	Common  commonConfig
	Listen  string
	Peer    string
}

func RunForward(argv []string) error {
	fs := pflag.NewFlagSet("forward", pflag.ContinueOnError)

	origOut := io.Discard
	fs.SetOutput(origOut)

	var cfg forwardCfg
	cfg.Common.Software = "turnado/forward"
	addCommonFlags(fs, &cfg.Common)

	fs.StringVarP(&cfg.Listen, "listen", "l", "0.0.0.0:9999", "Local UDP listen address")
	fs.StringVarP(&cfg.Peer, "peer", "P", "", "Remote target UDP address ip:port")

	help := fs.BoolP("help", "h", false, "Show help message")

	fs.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: turnado forward [options]")
		fs.SetOutput(os.Stdout)
		fs.PrintDefaults()
		fs.SetOutput(origOut)
	}

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *help {
		fs.Usage()
		return nil
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if err := requireTurn(fs, cfg.Common.Turn); err != nil {
		return err
	}
	if err := validateCommon(cfg.Common); err != nil {
		return err
	}

	if cfg.Peer == "" {
		return errors.New("missing --peer")
	}

	peerUDP, err := net.ResolveUDPAddr("udp", cfg.Peer)
	if err != nil {
		return fmt.Errorf("ResolveUDPAddr(peer=%q) failed: %w", cfg.Peer, err)
	}

	client, _, cleanup, err := newTurnClient(cfg.Common)
	if err != nil {
		return err
	}
	defer cleanup()

	relayConn, err := client.Allocate()
	if err != nil {
		return fmt.Errorf("Allocate (UDP) failed: %w", err)
	}
	defer relayConn.Close()

	if err := client.CreatePermission(peerUDP); err != nil {
		return fmt.Errorf("CreatePermission(%s) failed: %w", peerUDP, err)
	}

	localUDP, err := net.ListenUDP("udp4", mustResolveUDP(cfg.Listen))
	if err != nil {
		return fmt.Errorf("ListenUDP(local=%q) failed: %w", cfg.Listen, err)
	}
	defer localUDP.Close()

	log.Printf("Forward listening on %s, forwarding via TURN to %s", localUDP.LocalAddr(), peerUDP.String())

	var lastSrcMu sync.RWMutex
	var lastSrc *net.UDPAddr

	go func() {
		b := make([]byte, 2048)
		for {
			n, _, err := relayConn.ReadFrom(b)
			if err != nil {
				return
			}
			lastSrcMu.RLock()
			dst := lastSrc
			lastSrcMu.RUnlock()
			if dst == nil {
				continue
			}
			_, _ = localUDP.WriteToUDP(b[:n], dst)
		}
	}()

	b := make([]byte, 2048)
	for {
		n, src, err := localUDP.ReadFromUDP(b)
		if err != nil {
			if isClosedErr(err) {
				return nil
			}
			return err
		}
		lastSrcMu.Lock()
		lastSrc = src
		lastSrcMu.Unlock()

		_, _ = relayConn.WriteTo(b[:n], peerUDP)
	}
}
