package app

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/pion/stun/v3"
)

type allocationProbe struct {
	Address         string `json:"relay_address,omitempty"`
	LifetimeSeconds uint32 `json:"lifetime_seconds,omitempty"`
	ErrorCode       int    `json:"error_code,omitempty"`
	Error           string `json:"error,omitempty"`
	// FamilyMismatch is set when the server ignored REQUESTED-ADDRESS-FAMILY
	// and returned a relay address of the other family.
	FamilyMismatch bool `json:"family_mismatch,omitempty"`
}

// relayFamilyMismatch reports whether ip is not of the RFC 6156 family
// (1 = IPv4, 2 = IPv6) requested for the allocation.
func relayFamilyMismatch(ip net.IP, family byte) bool {
	switch family {
	case 1:
		return ip.To4() == nil
	case 2:
		return ip.To4() != nil
	}
	return false
}

func probeAllocationFamily(cfg commonConfig, family byte) allocationProbe {
	result := allocationProbe{}
	client, _, cleanup, err := newTurnClient(cfg)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer cleanup()
	attrs := []stun.Setter{stun.RawAttribute{Type: attrRequestedTrans, Value: []byte{17, 0, 0, 0}}}
	if family != 0 {
		attrs = append(attrs, stun.RawAttribute{Type: stun.AttrRequestedAddressFamily, Value: []byte{family, 0, 0, 0}})
	}
	build := func(method stun.Method, authenticated bool, nonce stun.Nonce, realm stun.Realm, extra []stun.Setter) (*stun.Message, error) {
		setters := []stun.Setter{stun.TransactionID, stun.NewType(method, stun.ClassRequest)}
		setters = append(setters, extra...)
		if authenticated {
			setters = append(setters, stun.NewUsername(cfg.Username), nonce, realm, stun.NewLongTermIntegrity(cfg.Username, realm.String(), cfg.Password))
		}
		setters = append(setters, stun.Fingerprint)
		return stun.Build(setters...)
	}
	transact := func(msg *stun.Message) (*stun.Message, error) {
		tr, err := client.PerformTransaction(msg, client.TURNServerAddr(), false)
		if err != nil {
			return nil, err
		}
		return tr.Msg, nil
	}
	first, err := build(stun.MethodAllocate, false, nil, nil, attrs)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	response, err := transact(first)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	var nonce stun.Nonce
	var realm stun.Realm
	authenticated := false
	if response.Type.Class == stun.ClassErrorResponse {
		if err := nonce.GetFrom(response); err != nil {
			result.Error = err.Error()
			return result
		}
		if err := realm.GetFrom(response); err != nil {
			result.Error = err.Error()
			return result
		}
		authenticated = true
		request, err := build(stun.MethodAllocate, true, nonce, realm, attrs)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		response, err = transact(request)
		if err != nil {
			result.Error = err.Error()
			return result
		}
	}
	if response.Type.Class == stun.ClassErrorResponse {
		var code stun.ErrorCodeAttribute
		if code.GetFrom(response) == nil {
			result.ErrorCode = int(code.Code)
			result.Error = formatTURNCode(int(code.Code), string(code.Reason))
		} else {
			result.Error = "TURN allocation failed"
		}
		return result
	}
	if response.Type.Class != stun.ClassSuccessResponse {
		result.Error = "unexpected TURN allocation response"
		return result
	}
	var relay stun.XORMappedAddress
	if err := relay.GetFromAs(response, stun.AttrXORRelayedAddress); err == nil {
		result.Address = net.JoinHostPort(relay.IP.String(), fmt.Sprint(relay.Port))
		result.FamilyMismatch = relayFamilyMismatch(relay.IP, family)
	}
	if raw, err := response.Get(stun.AttrLifetime); err == nil && len(raw) == 4 {
		result.LifetimeSeconds = binary.BigEndian.Uint32(raw)
	}
	// Release the probe allocation immediately on the same control connection.
	refresh, err := build(stun.MethodRefresh, authenticated, nonce, realm, []stun.Setter{stun.RawAttribute{Type: stun.AttrLifetime, Value: []byte{0, 0, 0, 0}}})
	if err == nil {
		_, _ = transact(refresh)
	}
	return result
}
