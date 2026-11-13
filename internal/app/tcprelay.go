package app

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/spf13/pflag"
)

func RunTCPRelay(argv []string) error {
	fs := pflag.NewFlagSet("tcprelay", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var cfg commonConfig
	cfg.Software = "turnado/tcprelay"
	addCommonFlags(fs, &cfg)
	target := fs.StringP("target", "a", "", "TCP target host:port")
	help := fs.BoolP("help", "h", false, "Show help message")
	fs.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: turnado tcprelay -t host:port -u user -p pass -a target:port [options]")
		fs.SetOutput(os.Stdout)
		fs.PrintDefaults()
		printModeExamples(os.Stdout, "tcprelay")
		fs.SetOutput(io.Discard)
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *help {
		fs.Usage()
		return nil
	}
	if err := resolveCommonFlags(fs, &cfg); err != nil {
		return err
	}
	if err := requireTurn(fs, cfg.Turn); err != nil {
		return err
	}
	if cfg.Transport == "udp" {
		cfg.Transport = "tcp"
	}
	if cfg.Transport == "dtls" {
		return fmt.Errorf("RFC 6062 TCP allocations require -T tcp or -T tls")
	}
	if err := validateCommon(cfg); err != nil {
		return err
	}
	if *target == "" {
		return fmt.Errorf("provide a TCP target with -a/--target")
	}
	addr, err := net.ResolveTCPAddr("tcp", *target)
	if err != nil || addr.Port == 0 {
		return fmt.Errorf("invalid target %q: %v", *target, err)
	}
	client, _, cleanup, err := newTurnClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()
	allocation, err := client.AllocateTCP()
	if err != nil {
		return fmt.Errorf("TCP allocation failed: %w", err)
	}
	defer allocation.Close()
	dataConn, err := dialTurnDataConn(cfg)
	if err != nil {
		return fmt.Errorf("data connection failed: %w", err)
	}
	conn, err := allocation.DialTCPWithConn(asTURNTCPConn(dataConn), "tcp", addr)
	if err != nil {
		_ = dataConn.Close()
		return fmt.Errorf("TCP CONNECT/ConnectionBind failed: %w", err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
	if _, err := conn.Write([]byte("tcpoverturn")); err != nil {
		return fmt.Errorf("send payload failed: %w", err)
	}
	fmt.Printf("Sent tcpoverturn to %s via TURN\n", addr)
	return nil
}
