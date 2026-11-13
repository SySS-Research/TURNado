package app

import (
	"fmt"
	"io"
)

var modeExamples = map[string][]string{
	"info": {
		"turnado info -t turn.example.org:3478 -u user -p -",
	},
	"scan": {
		"turnado scan -t turn.example.org:3478 -T tcp -u user -p - -a example.org:443",
	},
	"tcprelay": {
		"turnado tcprelay -t turn.example.org:3478 -T tcp -u user -p - -a example.org:443",
	},
	"socks": {
		"turnado socks -t turn.example.org:3478 -u user -p -",
		"turnado socks -c OFFER",
	},
	"tunnel": {
		"sudo turnado tunnel -t turn.example.org:3478 -u user -p -",
		"turnado tunnel --rootless-exit -c OFFER",
	},
	"forward": {
		"turnado forward -t turn.example.org:3478 -u user -p - -P ipinfo.io:443",
		"curl --http3-only --connect-to ipinfo.io:443:127.0.0.1:9999 https://ipinfo.io/ip",
	},
	"dos": {
		"turnado dos -t turn.example.org:3478 -u user -p - -s 10 --rate 2",
	},
}

var modeRequirements = map[string]string{
	"info":    "UDP checks work without RFC 6062; TCP allocation/CONNECT checks require RFC 6062.",
	"scan":    "Requires RFC 6062 TCP allocations and CONNECT support on the TURN server.",
	"tcprelay": "Requires RFC 6062 TCP allocations, CONNECT and ConnectionBind support on the TURN server.",
	"socks":   "Paired SOCKS uses TURN UDP allocations. Only --direct requires RFC 6062 TCP allocations (CONNECT only).",
	"tunnel":  "Uses TURN UDP allocations; RFC 6062 is not required.",
	"forward": "Uses a TURN UDP allocation; RFC 6062 is not required.",
	"dos":     "Uses TURN UDP allocations; RFC 6062 is not required.",
}

func printModeExamples(w io.Writer, mode string) {
	if requirement := modeRequirements[mode]; requirement != "" {
		fmt.Fprintf(w, "\nTURN requirements:\n  %s\n", requirement)
	}
	examples := modeExamples[mode]
	if len(examples) == 0 {
		return
	}
	fmt.Fprintln(w, "\nExamples:")
	for _, example := range examples {
		fmt.Fprintf(w, "  %s\n", example)
	}
	if mode == "socks" || mode == "tunnel" {
		fmt.Fprintln(w, "Start the client first. Use its offer as OFFER on the exit, then paste the exit's answer into the client.")
	}
	if mode == "socks" {
		fmt.Fprintln(w, "\nRFC 6062 direct SOCKS example:")
		fmt.Fprintln(w, "  turnado socks --direct -t turn.example.org:3478 -u user -p -")
	}
	if mode == "info" {
		fmt.Fprintln(w, "Result markers: [+] yes/granted/working (green), [!] no/denied/failed (red), [*] unknown or inconclusive (blue).")
	}
}
