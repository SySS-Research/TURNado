package app

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/pflag"
)

type tunnelCfg struct {
	Common    commonConfig
	SocksPort int
	Connect   string
	Encrypt   bool
	EncKey    string
}

func RunSocks(argv []string) error {
	fs := pflag.NewFlagSet("socks", pflag.ContinueOnError)

	origOut := io.Discard
	fs.SetOutput(origOut)

	var cfg tunnelCfg
	cfg.Common.Software = "turnado/socks"
	addCommonFlags(fs, &cfg.Common)

	fs.IntVarP(&cfg.SocksPort, "socks-port", "s", 1080, "Local SOCKS5 TCP listen port")
	fs.StringVarP(&cfg.Connect, "connect", "c", "", "Connection string for pairing")
	fs.BoolVarP(&cfg.Encrypt, "encrypt", "E", false, "Encrypt payloads between peers using AES-CTR")

	help := fs.BoolP("help", "h", false, "Show help message")

	fs.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: turnado socks [options]")
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

	if cfg.Connect == "" {
		if err := requireTurn(fs, cfg.Common.Turn); err != nil {
			return err
		}
	}
	return runTunnelAutoSocks(cfg)
}
