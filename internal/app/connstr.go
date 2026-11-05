package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// Passphrase-protected strings: sealedPrefix + base64url(salt|nonce|AES-GCM(json)).
// The prefix is authenticated as additional data so it cannot be swapped.
const (
	sealedPrefix  = "tz1."
	sealSaltLen   = 16
	scryptN       = 1 << 15
	scryptR       = 8
	scryptP       = 1
	sealKeyLength = 32
)

type connString struct {
	V           int    `json:"v"`
	Turn        string `json:"turn"`
	User        string `json:"user"`
	Pass        string `json:"pass"`
	Control     string `json:"control"`
	Insec       bool   `json:"insecure"`
	Enc         bool   `json:"enc"`
	Reliable    bool   `json:"reliable,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Relay       string `json:"relay"`
	ReplyTo     string `json:"reply_to,omitempty"`
}

func encodeConnString(cs connString, passphrase string) (string, error) {
	if err := validateConnString(cs); err != nil {
		return "", err
	}
	b, err := json.Marshal(cs)
	if err != nil {
		return "", err
	}
	if passphrase == "" {
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	salt := make([]byte, sealSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	aead, err := connStringAEAD(passphrase, salt)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := append(append(salt, nonce...), aead.Seal(nil, nonce, b, []byte(sealedPrefix))...)
	return sealedPrefix + base64.RawURLEncoding.EncodeToString(out), nil
}

func connStringAEAD(passphrase string, salt []byte) (cipher.AEAD, error) {
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, sealKeyLength)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func openConnString(s, passphrase string) ([]byte, error) {
	if !strings.HasPrefix(s, sealedPrefix) {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("invalid connection string encoding: %w", err)
		}
		return raw, nil
	}
	if passphrase == "" {
		return nil, fmt.Errorf("connection string is passphrase-protected; use --passphrase")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, sealedPrefix))
	if err != nil {
		return nil, fmt.Errorf("invalid connection string encoding: %w", err)
	}
	if len(sealed) < sealSaltLen {
		return nil, fmt.Errorf("connection string too short")
	}
	aead, err := connStringAEAD(passphrase, sealed[:sealSaltLen])
	if err != nil {
		return nil, err
	}
	rest := sealed[sealSaltLen:]
	if len(rest) < aead.NonceSize() {
		return nil, fmt.Errorf("connection string too short")
	}
	raw, err := aead.Open(nil, rest[:aead.NonceSize()], rest[aead.NonceSize():], []byte(sealedPrefix))
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt connection string (wrong passphrase?)")
	}
	return raw, nil
}

func decodeConnString(s, passphrase string) (connString, error) {
	var cs connString
	raw, err := openConnString(strings.TrimSpace(s), passphrase)
	if err != nil {
		return cs, err
	}
	if err := json.Unmarshal(raw, &cs); err != nil {
		return cs, fmt.Errorf("invalid connection string json: %w", err)
	}
	return cs, validateConnString(cs)
}

func validateConnString(cs connString) error {
	if cs.V != 1 && cs.V != 2 && cs.V != 3 {
		return fmt.Errorf("unsupported connection string version %d", cs.V)
	}
	if cs.Relay == "" || cs.Turn == "" {
		return fmt.Errorf("connection string missing fields")
	}
	if cs.ReplyTo != "" {
		if _, err := net.ResolveUDPAddr("udp", cs.ReplyTo); err != nil {
			return fmt.Errorf("invalid reply_to: %w", err)
		}
	}
	if cs.Enc {
		// Version 1 identifies the unencrypted IP tunnel.
		if cs.V == 1 {
			return fmt.Errorf("encrypted connection strings require version 2 or 3")
		}
		if _, err := parseFingerprint(cs.Fingerprint); err != nil {
			return err
		}
	} else if cs.V == 2 || cs.Fingerprint != "" {
		return fmt.Errorf("DTLS connection string requires encryption and a fingerprint")
	}
	if cs.V == 3 && !cs.Reliable || cs.Reliable && cs.V != 3 {
		return fmt.Errorf("reliable SOCKS requires connection string version 3")
	}
	return nil
}

// applyConnStringDefaults completes the exit configuration. Explicit flags win
// over the client's connection string, which wins over environment defaults.
func applyConnStringDefaults(cfg *tunnelCfg, cs connString) error {
	if cfg.Encrypt && !cs.Enc {
		return fmt.Errorf("unencrypted peer connection string requires --no-tunnel-encryption on both peers")
	}
	if cfg.NoTunnelEncryption && cs.Enc {
		return fmt.Errorf("--no-tunnel-encryption cannot be used with an encrypted peer connection string")
	}
	if cfg.Common.Turn == "" {
		cfg.Common.Turn = cs.Turn
	}
	if cfg.Common.Username == "" {
		cfg.Common.Username = cs.User
	}
	if cfg.Common.Password == "" {
		cfg.Common.Password = cs.Pass
	}
	if !cfg.Common.transportSet && cs.Control != "" {
		cfg.Common.Transport = cs.Control
	}
	cfg.Common.Insecure = cfg.Common.Insecure || cs.Insec
	cfg.Encrypt = cs.Enc
	applyCredentialEnv(&cfg.Common)
	return nil
}
