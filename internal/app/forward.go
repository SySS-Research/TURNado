package app

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v4"
	"github.com/spf13/pflag"
)

type forwardCfg struct {
	Common commonConfig
	Listen string
	Peer   string
}

type forwardPeerAddress struct{ *net.UDPAddr }

func (a forwardPeerAddress) AddTo(m *stun.Message) error {
	return (stun.XORMappedAddress{IP: a.IP, Port: a.Port}).AddToAs(m, stun.AttrXORPeerAddress)
}

func buildForwardIndication(peer *net.UDPAddr, payload []byte) (*stun.Message, error) {
	return stun.Build(
		stun.TransactionID,
		stun.NewType(stun.MethodSend, stun.ClassIndication),
		stun.RawAttribute{Type: stun.AttrData, Value: payload},
		forwardPeerAddress{peer},
		stun.Fingerprint,
	)
}

// Send Indications preserve the exact UDP payload length. Some TURN servers
// include ChannelData's four-byte padding in packets sent to the peer.
func sendForwardIndication(client *turn.Client, peer *net.UDPAddr, payload []byte) error {
	msg, err := buildForwardIndication(peer, payload)
	if err != nil {
		return err
	}
	n, err := client.WriteTo(msg.Raw, client.TURNServerAddr())
	if err != nil {
		return err
	}
	if n != len(msg.Raw) {
		return io.ErrShortWrite
	}
	return nil
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
		printModeExamples(os.Stdout, "forward")
		fs.SetOutput(origOut)
	}

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *help {
		fs.Usage()
		return nil
	}
	if err := resolveCommonFlags(fs, &cfg.Common); err != nil {
		return err
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

	listenAddr, err := net.ResolveUDPAddr("udp4", cfg.Listen)
	if err != nil {
		return fmt.Errorf("invalid --listen %q: %w", cfg.Listen, err)
	}
	localUDP, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		return fmt.Errorf("ListenUDP(local=%q) failed: %w", cfg.Listen, err)
	}
	defer localUDP.Close()

	log.Printf("Forward listening on %s, forwarding via TURN to %s", localUDP.LocalAddr(), peerUDP.String())

	var lastSrcMu sync.RWMutex
	var lastSrc *net.UDPAddr

	go func() {
		b := make([]byte, 65535)
		for {
			n, from, err := relayConn.ReadFrom(b)
			if err != nil {
				if !isClosedErr(err) {
					log.Printf("forward relay read failed: %v", err)
				}
				return
			}
			lastSrcMu.RLock()
			dst := lastSrc
			lastSrcMu.RUnlock()
			if dst == nil {
				continue
			}
			if cfg.Common.Verbose > 1 {
				log.Printf("forward relay->local: %d bytes from %s to %s", n, from, dst)
			}
			if _, err := localUDP.WriteToUDP(b[:n], dst); err != nil {
				log.Printf("forward local send failed: %v", err)
			}
		}
	}()

	b := make([]byte, 65535)
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

		if cfg.Common.Verbose > 1 {
			log.Printf("forward local->relay: %d bytes from %s to %s", n, src, peerUDP)
		}
		if err := sendForwardIndication(client, peerUDP, b[:n]); err != nil {
			log.Printf("forward relay send failed: %v", err)
		}
	}
}
