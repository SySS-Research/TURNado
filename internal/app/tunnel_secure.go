package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
)

const (
	msgTypeSecure = 5
	aesIVLen      = 16
)

type secureSession struct {
	enabled bool
	key     []byte
	peer    *net.UDPAddr
}

func newSecureSession(enabled bool, key []byte) *secureSession {
	if !enabled {
		return nil
	}
	if len(key) == 0 {
		return nil
	}
	return &secureSession{
		enabled: true,
		key:     key,
	}
}

func (s *secureSession) Start(peer *net.UDPAddr) error {
	if s == nil || !s.enabled {
		return nil
	}
	if peer == nil {
		return fmt.Errorf("missing peer for encryption")
	}
	s.peer = peer
	if len(s.key) != 16 && len(s.key) != 24 && len(s.key) != 32 {
		return fmt.Errorf("invalid encryption key length %d", len(s.key))
	}
	return nil
}

func (s *secureSession) wrapOutbound(pkt []byte) ([]byte, error) {
	if s == nil || !s.enabled {
		return pkt, nil
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aesIVLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	enc := make([]byte, len(pkt))
	stream.XORKeyStream(enc, pkt)

	payload := append(iv, enc...)
	return buildPacket(msgTypeSecure, 0, payload), nil
}

func (s *secureSession) unwrapInbound(payload []byte) ([]byte, error) {
	if s == nil || !s.enabled {
		return payload, nil
	}
	if len(payload) < aesIVLen {
		return nil, fmt.Errorf("encrypted payload too short")
	}
	iv := payload[:aesIVLen]
	ciphertext := payload[aesIVLen:]
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	plain := make([]byte, len(ciphertext))
	stream.XORKeyStream(plain, ciphertext)
	return plain, nil
}

func wrapPacket(sec *secureSession, pkt []byte) ([]byte, error) {
	if sec == nil || !sec.enabled {
		return pkt, nil
	}
	return sec.wrapOutbound(pkt)
}

func generateEncKey() ([]byte, string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, "", err
	}
	return key, base64.RawURLEncoding.EncodeToString(key), nil
}

func decodeEncKey(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
