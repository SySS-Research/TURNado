package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/srtp/v3"
)

const (
	srtpHeaderLen        = 12
	srtpAuthTagLen       = 10
	srtpOverhead         = srtpHeaderLen + srtpAuthTagLen
	tunnelPayloadType    = 96
	dtlsHandshakeTimeout = 5 * time.Minute
)

// Each process generates its own certificate. Only its SHA-256 fingerprint is
// signaled; private keys and the DTLS-derived session keys stay in memory.
type dtlsIdentity struct {
	certificate tls.Certificate
	fingerprint string
}

func newDTLSIdentity() (*dtlsIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "TURNado ephemeral peer"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return &dtlsIdentity{
		certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		fingerprint: "sha-256 " + strings.Join(parts, ":"),
	}, nil
}

func parseFingerprint(s string) ([]byte, error) {
	fields := strings.Fields(s)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "sha-256") {
		return nil, fmt.Errorf("DTLS fingerprint must use sha-256")
	}
	parts := strings.Split(fields[1], ":")
	if len(parts) != sha256.Size {
		return nil, fmt.Errorf("DTLS fingerprint must contain 32 bytes")
	}
	for _, p := range parts {
		if len(p) != 2 {
			return nil, fmt.Errorf("invalid DTLS fingerprint byte")
		}
	}
	b, err := hex.DecodeString(strings.Join(parts, ""))
	if err != nil {
		return nil, fmt.Errorf("invalid DTLS fingerprint: %w", err)
	}
	return b, nil
}

func (id *dtlsIdentity) config(peerFingerprint string) (*dtls.Config, error) {
	expected, err := parseFingerprint(peerFingerprint)
	if err != nil {
		return nil, err
	}
	return &dtls.Config{
		Certificates:           []tls.Certificate{id.certificate},
		CipherSuites:           []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
		ClientAuth:             dtls.RequireAnyClientCert,
		// Self-signed certificates are authenticated by the exchanged fingerprint
		// on BOTH sides, independently of --insecure for the TURN control socket.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer did not provide a DTLS certificate")
			}
			actual := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
				return fmt.Errorf("DTLS peer fingerprint mismatch")
			}
			return nil
		},
		MTU:           maxPacketSize,
		LoggerFactory: leveledLoggerFactory{},
	}, nil
}

// The handshake is driven explicitly by HandshakeContext so that pairing
// honours the caller's deadline.
func newDTLSConn(conn net.PacketConn, peer net.Addr, config *dtls.Config, isClient bool) (*dtls.Conn, error) {
	if isClient {
		return dtls.Client(conn, peer, config) //nolint:staticcheck // Config-based API keeps tests able to tweak profiles.
	}
	return dtls.Server(conn, peer, config) //nolint:staticcheck
}

// Contexts are unidirectional and protected by the transport's read/write locks.
type secureSession struct {
	conn          *dtls.Conn
	send, receive *srtp.Context
	ssrc          uint32
	remoteSSRC    uint32
	sequence      uint16
	clockStart    time.Time
}

func handshakeDTLS(ctx context.Context, conn net.PacketConn, peer net.Addr, id *dtlsIdentity, fingerprint string, isClient bool) (*secureSession, error) {
	config, err := id.config(fingerprint)
	if err != nil {
		return nil, err
	}
	dc, err := newDTLSConn(conn, peer, config, isClient)
	if err != nil {
		return nil, fmt.Errorf("DTLS handshake: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = dc.Close()
		}
	}()
	if err = dc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("DTLS handshake: %w", err)
	}
	profile, negotiated := dc.SelectedSRTPProtectionProfile()
	if !negotiated || profile != dtls.SRTP_AES128_CM_HMAC_SHA1_80 {
		return nil, fmt.Errorf("DTLS peer did not negotiate SRTP_AES128_CM_HMAC_SHA1_80")
	}
	state, stateOK := dc.ConnectionState()
	if !stateOK {
		return nil, fmt.Errorf("DTLS connection state unavailable")
	}
	keys := &srtp.Config{Profile: srtp.ProtectionProfileAes128CmHmacSha1_80}
	if err = keys.ExtractSessionKeysFromDTLS(&state, isClient); err != nil {
		return nil, err
	}
	s := &secureSession{conn: dc, clockStart: time.Now()}
	s.send, err = srtp.CreateContext(keys.Keys.LocalMasterKey, keys.Keys.LocalMasterSalt, keys.Profile)
	if err != nil {
		return nil, err
	}
	s.receive, err = srtp.CreateContext(keys.Keys.RemoteMasterKey, keys.Keys.RemoteMasterSalt, keys.Profile, srtp.SRTPReplayProtection(128))
	if err != nil {
		return nil, err
	}
	// Derive the two SSRCs from this DTLS session so the receiver can reject
	// unknown streams before SRTP allocates replay state for untrusted input.
	ssrcs, err := state.ExportKeyingMaterial("EXPORTER-TURNado-SSRC", nil, 8)
	if err != nil {
		return nil, err
	}
	s.ssrc, s.remoteSSRC = binary.BigEndian.Uint32(ssrcs[:4]), binary.BigEndian.Uint32(ssrcs[4:])
	if !isClient {
		s.ssrc, s.remoteSSRC = s.remoteSSRC, s.ssrc
	}
	var seed [2]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return nil, err
	}
	// Start in the lower half so the first rollover cannot occur before the
	// receiver has seen a packet, even if some initial packets are lost.
	s.sequence = binary.BigEndian.Uint16(seed[:]) & 0x7fff
	ok = true
	return s, nil
}

// encrypt protects one tunnel packet. pion/srtp ends the session with an
// error before the RFC 3711 limit of 2^48 packets per key is exceeded.
func (s *secureSession) encrypt(payload []byte) ([]byte, error) {
	pkt := make([]byte, srtpHeaderLen+len(payload))
	pkt[0], pkt[1] = 0x80, tunnelPayloadType
	binary.BigEndian.PutUint16(pkt[2:4], s.sequence)
	// RTP uses a 90 kHz media clock. A packet counter would expose the tunnel
	// directly through implausible timestamps during bursts and idle periods.
	elapsed := time.Since(s.clockStart)
	timestamp := uint32(elapsed/time.Second)*90_000 + uint32((elapsed%time.Second).Nanoseconds()*90_000/1_000_000_000)
	binary.BigEndian.PutUint32(pkt[4:8], timestamp)
	binary.BigEndian.PutUint32(pkt[8:12], s.ssrc)
	copy(pkt[srtpHeaderLen:], payload)
	// Never reuse an index, including after a failed write.
	s.sequence++
	return s.send.EncryptRTP(nil, pkt, nil)
}

func (s *secureSession) decrypt(pkt []byte) ([]byte, error) {
	// TURNado uses one fixed RTP header without padding, CSRCs or extensions.
	if len(pkt) < srtpOverhead || pkt[0] != 0x80 || pkt[1] != tunnelPayloadType {
		return nil, fmt.Errorf("invalid SRTP tunnel packet")
	}
	if binary.BigEndian.Uint32(pkt[8:12]) != s.remoteSSRC {
		return nil, fmt.Errorf("unexpected SRTP stream")
	}
	plain, err := s.receive.DecryptRTP(nil, pkt, nil)
	if err != nil {
		return nil, err
	}
	return plain[srtpHeaderLen:], nil
}
