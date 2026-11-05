package app

import (
	"bytes"
	"net"
	"testing"

	"github.com/pion/stun/v3"
)

func TestForwardIndicationPreservesUnalignedUDPPayload(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 443}
	payload := bytes.Repeat([]byte{0xa7}, 1406)
	msg, err := buildForwardIndication(peer, payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded := stun.Message{Raw: append([]byte(nil), msg.Raw...)}
	if err := decoded.Decode(); err != nil || decoded.Type != stun.NewType(stun.MethodSend, stun.ClassIndication) {
		t.Fatalf("invalid Send Indication: %v", err)
	}
	data, err := decoded.Get(stun.AttrData)
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("UDP payload changed: length=%d err=%v", len(data), err)
	}
	var target stun.XORMappedAddress
	if err := target.GetFromAs(&decoded, stun.AttrXORPeerAddress); err != nil || !target.IP.Equal(peer.IP) || target.Port != peer.Port {
		t.Fatalf("peer address changed: %v err=%v", target, err)
	}
}
