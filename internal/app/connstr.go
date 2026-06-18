package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type connStringV1 struct {
	V       int    `json:"v"`
	Turn    string `json:"turn"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
	Control string `json:"control"` 
	Insec   bool   `json:"insecure"`
	Enc     bool   `json:"enc"`
	Key     string `json:"key"`
	Relay   string `json:"relay"` 
}

func encodeConnString(cs connStringV1) (string, error) {
	b, err := json.Marshal(cs)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeConnString(s string) (connStringV1, error) {
	var cs connStringV1
	s = strings.TrimSpace(s)
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cs, fmt.Errorf("invalid connection string encoding: %w", err)
	}
	if err := json.Unmarshal(raw, &cs); err != nil {
		return cs, fmt.Errorf("invalid connection string json: %w", err)
	}
	if cs.V != 1 {
		return cs, fmt.Errorf("unsupported connection string version %d", cs.V)
	}
	if cs.Relay == "" || cs.Turn == "" {
		return cs, fmt.Errorf("connection string missing fields")
	}
	return cs, nil
}

func applyConnStringDefaults(cfg *tunnelCfg, cs connStringV1) {
	if cfg.Common.Turn == "" {
		cfg.Common.Turn = cs.Turn
	}
	if cfg.Common.Username == "" {
		cfg.Common.Username = cs.User
	}
	if cfg.Common.Password == "" {
		cfg.Common.Password = cs.Pass
	}
	if cfg.Common.Transport == "" || cfg.Common.Transport == "udp" {
		cfg.Common.Transport = cs.Control
	}
	cfg.Common.Insecure = cfg.Common.Insecure || cs.Insec
	cfg.Encrypt = cfg.Encrypt || cs.Enc
	if cfg.EncKey == "" {
		cfg.EncKey = cs.Key
	}
}
