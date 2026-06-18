package app

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v2"
	"github.com/spf13/pflag"
)

type commonConfig struct {
	Turn      string
	Username  string
	Password  string
	Transport string 
	Insecure  bool
	Timeout   time.Duration
	Verbose   int
	Software  string
}

func addCommonFlags(fs *pflag.FlagSet, cfg *commonConfig) {
	fs.StringVarP(&cfg.Turn, "turn", "t", "", "TURN server address (host:port) (required)")
	fs.StringVarP(&cfg.Username, "username", "u", "", "TURN username")
	fs.StringVarP(&cfg.Password, "password", "p", "", "TURN password")

	fs.StringVarP(&cfg.Transport, "transport", "T", "udp", "Transport type (udp|tcp|tls)")
	fs.BoolVarP(&cfg.Insecure, "insecure", "k", false, "Skip TLS certificate verification")

	fs.DurationVarP(&cfg.Timeout, "timeout", "o", 10*time.Second, "Dial timeout for control connection")
	fs.IntVarP(&cfg.Verbose, "verbose", "v", 0, "Verbosity level (0=quiet, 1=verbose, 2=very verbose)")
}

func requireTurn(fs *pflag.FlagSet, turn string) error {
	if strings.TrimSpace(turn) != "" {
		return nil
	}
	fmt.Fprintln(os.Stderr, "Warning: missing --turn (TURN server address)")
	fs.Usage()
	return errors.New("missing --turn")
}

type leveledLoggerFactory struct{ verbose bool }

func (f leveledLoggerFactory) NewLogger(scope string) logging.LeveledLogger {
	if !f.verbose {
		return nopLogger{}
	}
	prefix := fmt.Sprintf("[pion/%s] ", scope)
	return stdLogger{prefix: prefix}
}

type stdLogger struct{ prefix string }

func (l stdLogger) Trace(msg string) { log.Print(l.prefix + "TRACE: " + msg) }
func (l stdLogger) Tracef(format string, args ...interface{}) {
	log.Printf(l.prefix+"TRACE: "+format, args...)
}
func (l stdLogger) Debug(msg string) { log.Print(l.prefix + "DEBUG: " + msg) }
func (l stdLogger) Debugf(format string, args ...interface{}) {
	log.Printf(l.prefix+"DEBUG: "+format, args...)
}
func (l stdLogger) Info(msg string) { log.Print(l.prefix + "INFO: " + msg) }
func (l stdLogger) Infof(format string, args ...interface{}) {
	log.Printf(l.prefix+"INFO: "+format, args...)
}
func (l stdLogger) Warn(msg string) { log.Print(l.prefix + "WARN: " + msg) }
func (l stdLogger) Warnf(format string, args ...interface{}) {
	log.Printf(l.prefix+"WARN: "+format, args...)
}
func (l stdLogger) Error(msg string) { log.Print(l.prefix + "ERROR: " + msg) }
func (l stdLogger) Errorf(format string, args ...interface{}) {
	log.Printf(l.prefix+"ERROR: "+format, args...)
}

type nopLogger struct{}

func (nopLogger) Trace(string)                  {}
func (nopLogger) Tracef(string, ...interface{}) {}
func (nopLogger) Debug(string)                  {}
func (nopLogger) Debugf(string, ...interface{}) {}
func (nopLogger) Info(string)                   {}
func (nopLogger) Infof(string, ...interface{})  {}
func (nopLogger) Warn(string)                   {}
func (nopLogger) Warnf(string, ...interface{})  {}
func (nopLogger) Error(string)                  {}
func (nopLogger) Errorf(string, ...interface{}) {}

func dialControlConn(cfg commonConfig) (net.PacketConn, func() error, error) {
	switch cfg.Transport {
	case "udp":
		pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			return nil, nil, fmt.Errorf("ListenPacket(udp) failed: %w", err)
		}
		return pc, pc.Close, nil
	case "tcp":
		d := net.Dialer{Timeout: cfg.Timeout}
		c, err := d.Dial("tcp", cfg.Turn)
		if err != nil {
			return nil, nil, fmt.Errorf("Dial TCP failed: %w", err)
		}
		pc := turn.NewSTUNConn(c)
		return pc, pc.Close, nil
	case "tls":
		d := &net.Dialer{Timeout: cfg.Timeout}
		tc := &tls.Config{InsecureSkipVerify: cfg.Insecure}
		c, err := tls.DialWithDialer(d, "tcp", cfg.Turn, tc)
		if err != nil {
			return nil, nil, fmt.Errorf("Dial TLS failed: %w", err)
		}
		pc := turn.NewSTUNConn(c)
		return pc, pc.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported transport %q (use udp, tcp, or tls)", cfg.Transport)
	}
}

func newTurnClient(cfg commonConfig) (*turn.Client, net.PacketConn, func(), error) {
	if cfg.Turn == "" {
		return nil, nil, nil, errors.New("missing --turn")
	}
	if cfg.Username == "" {
		return nil, nil, nil, errors.New("missing --username")
	}
	if cfg.Password == "" {
		return nil, nil, nil, errors.New("missing --password")
	}

	pc, closeFn, err := dialControlConn(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	if cfg.Verbose > 1 {
		log.Printf("Control socket local=%s -> TURN=%s via %s", pc.LocalAddr(), cfg.Turn, cfg.Transport)
	}

	lf := leveledLoggerFactory{verbose: cfg.Verbose > 0}
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: cfg.Turn,
		TURNServerAddr: cfg.Turn,
		Username:       cfg.Username,
		Password:       cfg.Password,
		Software:       cfg.Software,
		Conn:           pc,
		RTO:            500 * time.Millisecond,
		LoggerFactory:  lf,
	})
	if err != nil {
		_ = closeFn()
		return nil, nil, nil, fmt.Errorf("NewClient failed: %w", err)
	}

	cleanup := func() {
		client.Close()
		_ = closeFn()
	}

	if err = client.Listen(); err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("Client.Listen failed: %w", err)
	}

	return client, pc, cleanup, nil
}

func isClosedErr(err error) bool { return errors.Is(err, net.ErrClosed) }
