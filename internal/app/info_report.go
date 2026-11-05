package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// peerProbe is one peer address of the permission survey.
type peerProbe struct {
	Address      string
	Permission   error  // CreatePermission result
	Tested       bool   // a STUN Binding request was sent through the relay
	SendErr      error  // sending that request failed
	ResponseFrom string // responder of the STUN request, "" without answer
}

// infoReport collects all info observations before they are printed, so the
// text and JSON output describe the same results.
type infoReport struct {
	Turn, Transport, Realm, Software, Probe string
	TurnPort                                int
	Status                                  string

	Anonymous      serverHello
	AnonymousKnown bool
	IPv4, IPv6     allocationProbe

	ClientErr error
	Mapped    string
	MappedErr error
	Relay     string
	AllocErr  error

	Peers    []peerProbe
	External peerProbe

	TCPTransport, TCPTarget string
	TCP                     tcpRelayProbe
}

var (
	turnErrorTextRE  = regexp.MustCompile(`error ([0-9]{3}): ([^)]*)\)`)
	infoColorEnabled = sync.OnceValue(func() bool {
		return os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" && enableANSI(os.Stdout)
	})
)

const (
	infoLabelWidth      = 18 // Result labels and peer addresses.
	infoPermissionWidth = 24 // Permission column of the peer table.
)

func infoStyle(text, code string) string {
	if !infoColorEnabled() {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func infoStatus(ok bool) string {
	if ok {
		return infoStyle("[+]", "1;32")
	}
	return infoStyle("[!]", "1;31")
}

func infoUnknown() string { return infoStyle("[*]", "1;34") }

// isTURNTimeout reports a transaction that got no answer at all.
func isTURNTimeout(err error) bool {
	var ne net.Error
	return err != nil && (strings.Contains(err.Error(), "all retransmissions failed") || errors.As(err, &ne) && ne.Timeout())
}

// Standard reason phrases (RFC 8489, 8656, 6062, 6156) for servers that send
// an ERROR-CODE without one.
var turnReasons = map[int]string{
	300: "Try Alternate", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
	420: "Unknown Attribute", 437: "Allocation Mismatch", 438: "Stale Nonce",
	440: "Address Family not Supported", 441: "Wrong Credentials", 442: "Unsupported Transport Protocol",
	443: "Peer Address Family Mismatch", 446: "Connection Already Exists", 447: "Connection Timeout or Failure",
	486: "Allocation Quota Reached", 500: "Server Error", 508: "Insufficient Capacity",
}

// formatTURNCode renders an error code as "403 Forbidden".
func formatTURNCode(code int, reason string) string {
	if reason = strings.TrimSpace(reason); reason == "" {
		reason = turnReasons[code]
	}
	return strings.TrimSpace(fmt.Sprintf("%d %s", code, reason))
}

// describeTURNError shortens TURN errors to "403 Forbidden" style text.
func describeTURNError(err error) string {
	if err == nil {
		return ""
	}
	if m := turnErrorTextRE.FindStringSubmatch(err.Error()); m != nil {
		code, _ := strconv.Atoi(m[1])
		return formatTURNCode(code, m[2])
	}
	if isTURNTimeout(err) {
		return "no answer (timeout)"
	}
	return err.Error()
}

// errorMarker shows timeouts as inconclusive and everything else as failure.
func errorMarker(err error) string {
	if isTURNTimeout(err) {
		return infoUnknown()
	}
	return infoStatus(false)
}

func pad(s string, width int) string {
	if len(s) >= width {
		return s + " "
	}
	return s + strings.Repeat(" ", width-len(s))
}

func writeInfoLine(w io.Writer, marker, label, value string) {
	fmt.Fprintf(w, "%s %s%s\n", marker, pad(label, infoLabelWidth), value)
}

func writeInfoSection(w io.Writer, title string) {
	fmt.Fprintf(w, "\n%s\n", infoStyle(title, "1"))
}

func writeInfoText(w io.Writer, r infoReport) {
	field := func(label, value string) { fmt.Fprintf(w, "%s%s\n", pad(label, infoLabelWidth+4), value) }
	field("TURN server", fmt.Sprintf("%s (%s)", r.Turn, r.Transport))
	if r.Realm != "" {
		field("Realm", r.Realm)
	} else {
		field("Realm", "unknown")
	}
	if r.Software != "" {
		field("Software", r.Software)
	}
	field("Probe target", r.Probe)

	writeInfoSection(w, "Allocation")
	switch r.Status {
	case "missing_credentials":
		writeAnonymousLine(w, r)
		writeInfoLine(w, infoUnknown(), "Authenticated", "skipped: no credentials (-u/-p or $"+envUsername+"/$"+envPassword+")")
		return
	case "auth_client_failed":
		writeAnonymousLine(w, r)
		writeInfoLine(w, infoStatus(false), "Control channel", "failed: "+r.ClientErr.Error())
		return
	}
	if r.MappedErr != nil {
		writeInfoLine(w, infoUnknown(), "Mapped address", "unknown ("+describeTURNError(r.MappedErr)+")")
	} else {
		writeInfoLine(w, infoStatus(true), "Mapped address", r.Mapped)
	}
	if r.AllocErr != nil {
		writeInfoLine(w, errorMarker(r.AllocErr), "UDP relay", "allocation failed ("+describeTURNError(r.AllocErr)+")")
	} else {
		writeInfoLine(w, infoStatus(true), "UDP relay", r.Relay)
	}
	writeFamilyLine(w, "IPv4 relay", "IPv4", r.IPv4)
	writeFamilyLine(w, "IPv6 relay", "IPv6", r.IPv6)
	writeAnonymousLine(w, r)
	if r.Status != "ok" {
		return
	}
	writePeerTable(w, r)
	writeExternalProbe(w, r.External)
	writeTCPRelay(w, r)
}

func writeAnonymousLine(w io.Writer, r infoReport) {
	switch {
	case !r.AnonymousKnown:
		writeInfoLine(w, infoUnknown(), "Anonymous relay", "unknown (no answer to an unauthenticated Allocate)")
	case r.Anonymous.Code == 0:
		writeInfoLine(w, infoStatus(true), "Anonymous relay", "allowed without credentials")
	case r.Anonymous.Code < 0:
		writeInfoLine(w, infoStatus(false), "Anonymous relay", "rejected")
	default:
		writeInfoLine(w, infoStatus(false), "Anonymous relay", "rejected ("+formatTURNCode(r.Anonymous.Code, r.Anonymous.Reason)+")")
	}
}

func writeFamilyLine(w io.Writer, label, family string, p allocationProbe) {
	switch {
	case p.Error != "" && p.ErrorCode != 0:
		writeInfoLine(w, infoStatus(false), label, "not provided ("+p.Error+")")
	case p.Error != "":
		writeInfoLine(w, errorMarker(errors.New(p.Error)), label, "probe failed ("+describeTURNError(errors.New(p.Error))+")")
	case p.Address == "":
		writeInfoLine(w, infoUnknown(), label, "unknown (no relay address in the response)")
	case p.FamilyMismatch:
		writeInfoLine(w, infoStatus(false), label, fmt.Sprintf("not provided: requested %s, server returned %s", family, p.Address))
	default:
		writeInfoLine(w, infoStatus(true), label, fmt.Sprintf("%s (lifetime %d s)", p.Address, p.LifetimeSeconds))
	}
}

func peerPermissionText(p peerProbe) string {
	switch {
	case p.Permission == nil:
		return "granted"
	case isTURNTimeout(p.Permission):
		return "no answer (timeout)"
	default:
		return "denied (" + describeTURNError(p.Permission) + ")"
	}
}

func writePeerTable(w io.Writer, r infoReport) {
	// Long reasons such as "443 Peer Address Family Mismatch" widen the
	// column for all rows so the STUN column stays aligned.
	width := infoPermissionWidth
	for _, p := range r.Peers {
		width = max(width, len(peerPermissionText(p))+2)
	}
	writeInfoSection(w, "Peer permissions")
	fmt.Fprintf(w, "    %s%s%s\n", pad("Peer", infoLabelWidth), pad("Permission", width), fmt.Sprintf("STUN via relay to port %d", r.TurnPort))
	inconclusive := false
	for _, p := range r.Peers {
		marker := infoStatus(true)
		if p.Permission != nil {
			marker = errorMarker(p.Permission)
		}
		if p.Tested && p.SendErr == nil && p.ResponseFrom == "" {
			inconclusive = true
		}
		fmt.Fprintf(w, "%s %s%s%s\n", marker, pad(p.Address, infoLabelWidth), pad(peerPermissionText(p), width), peerSTUNText(p, r.TurnPort))
	}
	if inconclusive {
		fmt.Fprintln(w, "    A STUN response proves that the relay reached the address; no response is inconclusive.")
	}
}

func peerSTUNText(p peerProbe, port int) string {
	switch {
	case p.Permission != nil:
		return "-"
	case !p.Tested:
		return "not tested"
	case p.SendErr != nil:
		return "send failed (" + p.SendErr.Error() + ")"
	case p.ResponseFrom == "":
		return infoStyle("no response", "34")
	case p.ResponseFrom == net.JoinHostPort(p.Address, fmt.Sprint(port)):
		return infoStyle("received", "1;32")
	default:
		return infoStyle("received from "+p.ResponseFrom, "1;32")
	}
}

func writeExternalProbe(w io.Writer, p peerProbe) {
	writeInfoSection(w, "External probe "+p.Address)
	if p.Permission != nil {
		writeInfoLine(w, errorMarker(p.Permission), "Permission", "denied ("+describeTURNError(p.Permission)+")")
		return
	}
	writeInfoLine(w, infoStatus(true), "Permission", "granted")
	switch {
	case p.SendErr != nil:
		writeInfoLine(w, infoStatus(false), "STUN via relay", "send failed ("+p.SendErr.Error()+")")
	case p.ResponseFrom == "":
		writeInfoLine(w, infoUnknown(), "STUN via relay", "no response (inconclusive: the target may not answer STUN)")
	case p.ResponseFrom == p.Address:
		writeInfoLine(w, infoStatus(true), "STUN via relay", "response received")
	default:
		writeInfoLine(w, infoStatus(true), "STUN via relay", "response received from "+p.ResponseFrom)
	}
}

func writeTCPRelay(w io.Writer, r infoReport) {
	writeInfoSection(w, "TCP relay (RFC 6062, control over "+r.TCPTransport+")")
	t := r.TCP
	switch {
	case t.ClientErr != nil:
		writeInfoLine(w, infoStatus(false), "Allocation", "control connection failed ("+t.ClientErr.Error()+")")
		return
	case t.AllocErr != nil:
		writeInfoLine(w, errorMarker(t.AllocErr), "Allocation", "rejected ("+describeTURNError(t.AllocErr)+")")
		return
	}
	writeInfoLine(w, infoStatus(true), "Allocation", "allowed")
	target := r.TCPTarget
	switch {
	case t.Connected:
		writeInfoLine(w, infoStatus(true), "CONNECT", target+" connected")
	case isTURNTimeout(t.ConnectErr):
		writeInfoLine(w, infoUnknown(), "CONNECT", target+" no answer (timeout; inconclusive)")
	case strings.Contains(t.ConnectErr.Error(), "error 447"):
		writeInfoLine(w, infoStatus(false), "CONNECT", target+" unreachable ("+describeTURNError(t.ConnectErr)+"); CONNECT itself is supported")
	default:
		writeInfoLine(w, infoStatus(false), "CONNECT", target+" failed ("+describeTURNError(t.ConnectErr)+")")
	}
}

type infoCheck struct {
	Allowed bool   `json:"allowed"`
	Error   string `json:"error,omitempty"`
}

type internalProbeResult struct {
	Address          string    `json:"address"`
	Permission       infoCheck `json:"permission"`
	STUNTested       bool      `json:"stun_tested"`
	STUNResponse     bool      `json:"stun_response"`
	STUNResponseFrom string    `json:"stun_response_from,omitempty"`
}

func checkInfo(err error) infoCheck {
	if err == nil {
		return infoCheck{Allowed: true}
	}
	return infoCheck{Error: err.Error()}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func emitInfoJSON(v any) error { return json.NewEncoder(os.Stdout).Encode(v) }

var errInfoSkipped = errors.New("skipped")

// jsonFields keeps the established JSON keys of earlier versions.
func (r infoReport) jsonFields() map[string]any {
	out := map[string]any{
		"turn_server": r.Turn, "realm": r.Realm, "software": r.Software, "probe_address": r.Probe,
		"anonymous_allocate_error_code": r.Anonymous.Code, "anonymous_allocation": r.AnonymousKnown && r.Anonymous.Code == 0,
		"status": r.Status,
	}
	if r.Status == "missing_credentials" {
		return out
	}
	out["ipv4_relay"], out["ipv6_relay"] = r.IPv4, r.IPv6
	if r.Status == "auth_client_failed" {
		out["error"] = errorText(r.ClientErr)
		return out
	}
	out["xor_mapped_address"] = r.Mapped
	if r.Status == "allocation_failed" {
		out["allocation"] = checkInfo(r.AllocErr)
		return out
	}
	out["relay_address"] = r.Relay
	peers := make([]internalProbeResult, len(r.Peers))
	for i, p := range r.Peers {
		peers[i] = internalProbeResult{
			Address: p.Address, Permission: checkInfo(p.Permission),
			STUNTested: p.Tested, STUNResponse: p.ResponseFrom != "", STUNResponseFrom: p.ResponseFrom,
		}
	}
	for _, loopback := range []struct{ key, address string }{{"ipv4", "127.0.0.1"}, {"ipv6", "::1"}} {
		for _, p := range peers {
			if p.Address == loopback.address {
				out["loopback_"+loopback.key+"_permission"] = p.Permission
				out["loopback_"+loopback.key+"_stun_response"] = p.STUNResponse
			}
		}
	}
	out["internal_probes"] = peers
	ext := r.External
	out["udp_permission"] = checkInfo(ext.Permission)
	sendErr := ext.SendErr
	if ext.Permission != nil {
		sendErr = errInfoSkipped
	}
	out["udp_send"], out["udp_stun_response"] = checkInfo(sendErr), ext.ResponseFrom != ""

	allocErr, connectErr, sendTCPErr := r.TCP.AllocErr, r.TCP.ConnectErr, r.TCP.SendErr
	if r.TCP.ClientErr != nil {
		allocErr = r.TCP.ClientErr
	}
	if allocErr != nil {
		connectErr = errInfoSkipped
	}
	if !r.TCP.Connected && sendTCPErr == nil {
		sendTCPErr = errInfoSkipped
	}
	out["tcp_allocation"] = checkInfo(allocErr)
	out["tcp_connect_bind_supported"] = allocErr == nil && (connectErr == nil || strings.Contains(connectErr.Error(), "error 447"))
	out["tcp_connect_bind_error"] = errorText(connectErr)
	out["tcp_send"] = checkInfo(sendTCPErr)
	return out
}
