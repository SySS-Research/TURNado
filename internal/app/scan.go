package app

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

type scanResult struct {
	Target    string `json:"target"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

func readTargetList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var targets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	return targets, sc.Err()
}

func RunScan(argv []string) error {
	fs := pflag.NewFlagSet("scan", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var cfg commonConfig
	cfg.Software = "turnado/scan"
	addCommonFlags(fs, &cfg)
	var targets []string
	fs.StringArrayVarP(&targets, "target", "a", nil, "TCP target ip:port (repeat for multiple targets)")
	listFile := fs.String("targets-file", "", "Read TCP targets from a file, one ip:port per line")
	jsonOutput := fs.Bool("json", false, "Print machine-readable results")
	help := fs.BoolP("help", "h", false, "Show help message")
	fs.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: turnado scan -t host:port -u user -p pass -a target:port [options]")
		fs.SetOutput(os.Stdout)
		fs.PrintDefaults()
		printModeExamples(os.Stdout, "scan")
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
	if *listFile != "" {
		fromFile, err := readTargetList(*listFile)
		if err != nil {
			return fmt.Errorf("read --targets-file: %w", err)
		}
		targets = append(targets, fromFile...)
	}
	if len(targets) == 0 {
		return fmt.Errorf("provide at least one --target or --targets-file")
	}
	resolved := make([]*net.TCPAddr, len(targets))
	for i, target := range targets {
		addr, err := net.ResolveTCPAddr("tcp", target)
		if err != nil || addr.Port == 0 {
			return fmt.Errorf("invalid target %q: %v", target, err)
		}
		resolved[i] = addr
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
	results := make([]scanResult, 0, len(targets))
	for i, target := range targets {
		_, err := allocation.Connect(resolved[i])
		result := scanResult{Target: target, Reachable: err == nil}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}
	if *jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(results)
	}
	for _, result := range results {
		if result.Reachable {
			fmt.Printf("%s: open\n", result.Target)
		} else {
			fmt.Printf("%s: no connection (%s)\n", result.Target, result.Error)
		}
	}
	return nil
}
