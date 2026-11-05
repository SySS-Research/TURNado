package app

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"os"
)

type socksAuth struct{ user, password string }

const envSocksPassword = "TURNADO_SOCKS_PASSWORD"

func resolveSocksAuth(cfg *tunnelCfg) error {
	cfg.SocksPass = os.Getenv(envSocksPassword)
	if cfg.SocksUser == "" && cfg.SocksPass != "" || cfg.SocksUser != "" && cfg.SocksPass == "" {
		return fmt.Errorf("SOCKS authentication requires --socks-user and a password")
	}
	if len(cfg.SocksUser) > 255 || len(cfg.SocksPass) > 255 {
		return fmt.Errorf("SOCKS username and password must be at most 255 bytes")
	}
	return nil
}

func negotiateSocks5Auth(c net.Conn, auth socksAuth) error {
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != 5 || greeting[1] == 0 {
		return fmt.Errorf("invalid SOCKS5 greeting")
	}
	methods := make([]byte, greeting[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	wanted := byte(0)
	if auth.user != "" {
		wanted = 2
	}
	selected := false
	for _, method := range methods {
		if method == wanted {
			selected = true
			break
		}
	}
	if !selected {
		_, _ = c.Write([]byte{5, 0xff})
		return fmt.Errorf("required SOCKS5 authentication method not offered")
	}
	if _, err := c.Write([]byte{5, wanted}); err != nil {
		return err
	}
	if wanted == 0 {
		return nil
	}
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return err
	}
	if head[0] != 1 || head[1] == 0 {
		return fmt.Errorf("invalid SOCKS5 username/password request")
	}
	user := make([]byte, head[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return err
	}
	var plen [1]byte
	if _, err := io.ReadFull(c, plen[:]); err != nil {
		return err
	}
	password := make([]byte, plen[0])
	if _, err := io.ReadFull(c, password); err != nil {
		return err
	}
	valid := subtle.ConstantTimeCompare(user, []byte(auth.user)) == 1 && subtle.ConstantTimeCompare(password, []byte(auth.password)) == 1
	status := byte(1)
	if valid {
		status = 0
	}
	_, err := c.Write([]byte{1, status})
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("SOCKS5 authentication failed")
	}
	return nil
}
