package app

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/pflag"
)

func RunTunnel(argv []string) error {
	fs := pflag.NewFlagSet("tunnel", pflag.ContinueOnError)

	origOut := io.Discard
	fs.SetOutput(origOut)

	var cfg tunnelCfg
	cfg.Common.Software = "turnado/tunnel"
	addCommonFlags(fs, &cfg.Common)

	fs.StringVarP(&cfg.Connect, "connect", "c", "", "Connection string for pairing")
	fs.BoolVarP(&cfg.Encrypt, "encrypt", "E", false, "Encrypt payloads between peers using AES-CTR")

	help := fs.BoolP("help", "h", false, "Show help message")

	fs.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: turnado tunnel [options]")
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
		if err := validateCommon(cfg.Common); err != nil {
			return err
		}
	}
	return runTunnelAutoTun(cfg)
}
