# 🌪️ TURNado 🦈

A TURN test suite for testing and (ab)using TURN servers.

Check out the [blog post](https://blog.syss.com/posts/turnado/)!



## Features

TURNado supports several modes to effectively test modern TURN implementations for security issues and misconfigurations.
It also supports tunneling arbitrary traffic through TURN channels, e.g., for bypassing Internet restrictions.

The following modes are implemented:

- `info`: Inspect TURN server details and probe UDP/TCP capabilities.
- `scan`: Probe TCP targets using RFC 6062 CONNECT requests from the TURN server.
- `socks`: SOCKS5-over-TURN tunnel.
- `tunnel`: Full IP tunnel for tunneling arbitrary traffic through TURN.
- `forward`: UDP forwarder over TURN.
- `dos`: Create many allocations for load testing.

The UDP control socket supports IPv4 and IPv6 TURN servers. TCP, TLS and DTLS control connections can also use IPv6 addresses. Select TURN over DTLS (RFC 7350) with `-T dtls`; server certificate verification is enabled by default, and `-k` skips it for test servers.



## Build instructions

TURNado requires Go 1.25.3 or newer.

To build it on Linux:

```sh
$ git clone https://github.com/SySS-Research/TURNado

$ cd TURNado

$ go mod tidy

$ go build ./cmd/turnado
```

Cross-compile for Windows:

```
$ GOOS=windows GOARCH=amd64 go build ./cmd/turnado 
```

Windows TUN mode needs the [Wintun DLL](https://www.wintun.net/) beside the executable and permission to configure the adapter. macOS TUN mode uses the system `utun` device.


Run the protocol and integration tests:

```sh
go test ./...
go test -race ./...
```

The tests run real DTLS handshakes, SRTP traffic, TURN allocations and a SOCKS stream over an in-memory network; they do not require an external TURN server or a privileged TUN device.

## Usage Examples and Modes

The following subsections describe the basic usage and different modes of TURNado.


### info

Probes TURN server properties: allocations, the peer permission policy, whether the relay reaches the TURN host itself, and RFC 6062 TCP relaying.

```sh
turnado info -t turn.example.com:3478 -u user -p -

TURN server           turn.example.com:3478 (udp)
Realm                 turn.example
Probe target          203.0.113.200:3478

Allocation
[+] Mapped address    198.51.100.1:50238
[+] UDP relay         203.0.113.200:49163
[+] IPv4 relay        203.0.113.200:49162 (lifetime 600 s)
[!] IPv6 relay        not provided: requested IPv6, server returned 203.0.113.200:49164
[!] Anonymous relay   rejected (401 Unauthorized)

Peer permissions
    Peer              Permission              STUN via relay to port 3478
[+] 127.0.0.1         granted                 no response
[+] ::1               granted                 no response
[+] 0.0.0.0           granted                 no response
[+] 127.0.0.2         granted                 received
[+] ::                granted                 no response
[+] 64:ff9b::7f00:1   granted                 no response
[!] 10.0.0.1          denied (403 Forbidden)  -
[!] 172.16.0.1        denied (403 Forbidden)  -
[!] 192.168.0.1       denied (403 Forbidden)  -
[!] 100.64.0.1        denied (403 Forbidden)  -
[!] 169.254.169.254   denied (403 Forbidden)  -
    A STUN response proves that the relay reached the address; no response is inconclusive.

External probe 203.0.113.200:3478
[+] Permission        granted
[+] STUN via relay    response received

TCP relay (RFC 6062, control over tcp)
[+] Allocation        allowed
[*] CONNECT           203.0.113.200:3478 no answer (timeout; inconclusive)
```

Each result line starts with a marker: green `[+]` means yes, granted or working; red `[!]` means no, denied or failed; blue `[*]` means unknown or inconclusive. TURN errors are shown as code and reason, for example `denied (403 Forbidden)`.

- **Allocation:** the mapped address, the authenticated UDP relay and separate IPv4 and IPv6 relay probes with REQUESTED-ADDRESS-FAMILY, including the granted lifetime and errors such as 440, 486 or 508. A server that ignores the requested family and returns an address of the other family is reported as `not provided`. `Anonymous relay` shows the answer to an Allocate without credentials. Without credentials, only this check runs.
- **Peer permissions:** a CreatePermission survey for wildcard, alternate loopback and NAT64 forms of the TURN host and for RFC 1918 ranges, 100.64/10 and 169.254.169.254. For addresses of the TURN host itself, a STUN Binding request is sent through the relay to the TURN port. A response proves that the relay forwarded traffic there; `received from` names a responder whose address differs from the probed one. No response is inconclusive because the destination might not answer STUN. All requests share one wait of at most two seconds.
- **External probe:** permission and STUN response for `-a/--probe` (default: the TURN server's address and port).
- **TCP relay:** an RFC 6062 TCP allocation, followed by CONNECT and ConnectionBind to the probe target. With `-T dtls`, this uses TLS on the same port. `447` means the server supports CONNECT but could not reach the target. A timeout is inconclusive; the target may be filtered.

The UDP checks do not require RFC 6062; the TCP allocation and CONNECT checks do. Set `NO_COLOR=1` to disable ANSI colors; redirected output and `--json` contain no color codes. `--json` prints the same observations as structured fields.

### scan

`scan` requests a TCP allocation and sends an RFC 6062 CONNECT request for each target. A successful response means the TURN server established a TCP connection to that address and port. Failed responses include the TURN error. Targets are resolved locally before the request.
RFC 6062 requires a TCP or TLS control connection; `scan` and `socks --direct` use TCP when no transport is selected. Use `-T tls` for a TLS-only server.

```sh
turnado scan -t turn.example.com:3478 -u user -p - -a 192.0.2.10:80 -a 192.0.2.10:443 --json
turnado scan -t turn.example.com:3478 -u user -p - --targets-file targets.txt
```

The target file contains one `ip:port` per line; empty lines and lines starting with `#` are ignored. `--json` returns an array of `{target, reachable, error}` objects.

### socks

The `socks` mode allows tunneling TCP traffic encapsulated within a custom protocol over TURN and through an exit node via a SOCKS proxy.
This could be used e.g. for bypassing outgoing Internet restrictions or for C2 communication.

1. Start the `socks` mode on the client you want to have the SOCKS proxy listen on:

```sh
$ turnado socks -t worldaz-msit.relay.teams.microsoft.com:443 -T tls -u <username> -p <password>
2026/02/06 12:59:30.526128 TURN UDP relays allocated at: [52.114.237.180:51601]
Connection string:
eyJ2IjozL[...]
2026/02/06 12:59:30.526475 Reliable SOCKS5 listening on 127.0.0.1:1080
2026/02/06 12:59:30.526485 Waiting for peer connection string on stdin (paste it and press Enter) ...
```

2. Copy the base64-encoded connection string and use it to start the `socks` mode on the exit node:

```sh
$ turnado socks -c eyJ2IjozL[...]
2026/02/06 13:01:12.355942 TURN UDP relays allocated at: [52.114.251.48:51486]
2026/02/06 13:01:12.421888 Permission created for peer 52.114.237.180:51601
Connection string:
eyJ2IjozL[...]
2026/02/06 13:01:12.786007 Waiting for authenticated DTLS handshake from client ...

```

3. Copy the connection string generated on the exit node and paste it into the client:

```
$ turnado socks -t worldaz-msit.relay.teams.microsoft.com:443 -T tls -u <username> -p <password>
2026/02/06 12:59:30.526128 TURN UDP relays allocated at: [52.114.237.180:51601]
Connection string:
eyJ2IjozL[...]
2026/02/06 12:59:30.526475 Reliable SOCKS5 listening on 127.0.0.1:1080
2026/02/06 12:59:30.526485 Waiting for peer connection string on stdin (paste it and press Enter) ...
eyJ2IjozL[...]
2026/02/06 13:02:03.710369 Paired with 52.114.251.48:51486: DTLS fingerprint verified; SRTP_AES128_CM_HMAC_SHA1_80 active
```

4. Now, the local SOCKS proxy on the client can be used to tunnel communication through TURN to the exit node (e.g. to the Internet):

```sh
$ curl -x socks5://127.0.0.1:1080 http://example.com | html2text

****** Example Domain ******
This domain is for use in documentation examples without needing permission.
Avoid use in operations.
Learn more
```

The SOCKS server replies with success only after the exit has established the target TCP connection. Failed target connections return a SOCKS error, as does an exit that does not answer within 30 seconds. Half-closed TCP connections are preserved: a client may finish sending and still receive the complete response. It listens on `127.0.0.1` by default; `--socks-listen IP` and `--socks-port PORT` change the address. `--socks-user NAME` plus `TURNADO_SOCKS_PASSWORD` require SOCKS5 username/password authentication. This password protects the local SOCKS listener and is separate from the TURN password.

SOCKS tunnels always use KCP and smux for ordered, retransmitted streams. They support UDP ASSOCIATE, including DNS datagrams; fragmented SOCKS UDP packets are rejected. The direct RFC 6062 mode supports CONNECT only.

Only the client opens streams. The client closes any stream the exit tries to open, so an exit cannot reach services on the client side.

For a direct test of the TURN server's TCP reachability, use `socks --direct` without an exit peer. Each SOCKS CONNECT opens its own RFC 6062 TCP allocation and uses the server to connect to the requested destination:

```sh
turnado socks --direct -t turn.example.com:3478 -u user -p - --socks-port 1080
curl --proxy socks5://127.0.0.1:1080 http://example.com/
```

The direct mode supports SOCKS5 CONNECT only and has no peer tunnel to encrypt.

Peer traffic is encrypted with DTLS-SRTP by default. To disable tunnel encryption, set `--no-tunnel-encryption` on both peers; a plaintext connection string is rejected unless the exit explicitly opts out too.

#### Peer encryption (`socks` and `tunnel`)

At startup, each encrypted peer generates an ECDSA P-256 key pair and a self-signed certificate. The private key stays in process memory and signs the DTLS handshake; it is never written to disk or included in a connection string. The connection string carries only the certificate's SHA-256 fingerprint in `fingerprint`, formatted as `sha-256 AA:BB:...`.

Both peers verify the other's certificate against the exchanged fingerprint during a DTLS 1.2 handshake. The client starts the handshake as soon as the exit's answer is pasted. The exit waits without a time limit for the first handshake packet, so copying the connection strings may take as long as needed; from then on, the handshake must complete within five minutes. An invalid fingerprint or a failed handshake aborts pairing without falling back to plaintext.

The handshake uses `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, requires Extended Master Secret, and negotiates **`SRTP_AES128_CM_HMAC_SHA1_80`**. As specified by [RFC 5764](https://www.rfc-editor.org/rfc/rfc5764.html), the SRTP profile protects the subsequent data packets; it is not a DTLS record cipher. Separate keys for each direction are derived from the DTLS session using the standard SRTP exporter. All tunnel messages (IP packets, fragments, reliable stream packets and heartbeats) are carried as SRTP payloads with AES-128 counter-mode encryption, 80-bit HMAC-SHA1 authentication and replay protection. DTLS and SRTP use the existing TURN relay allocation, without an additional direct connection between peers.

RTP timestamps use a 90 kHz clock from the start of the peer session; sequence numbers remain per-packet counters.

Both peers must agree on encryption. `-k/--insecure` only affects TLS to the TURN server; it never disables peer fingerprint verification.

Exchange connection strings through an authenticated, confidential channel: the fingerprint is the peer's trust anchor, and TURN credentials are still included. By default, the connection string is base64url-encoded JSON and is not encrypted; the optional passphrase protection described below encrypts it.

DTLS-SRTP preserves the underlying datagram transport semantics. SOCKS always uses KCP and smux for ordered streams with retransmission and flow control. KCP control data is authenticated by SRTP by default. The packet size limit remains 1200 bytes, including the SRTP header and authentication tag.

Each peer uses one TURN UDP allocation. Connection string version 3 identifies the KCP/smux SOCKS tunnel; version 1 or 2 identifies an IP tunnel.

#### Credentials and connection strings

The common `-u` and `-p` flags can be replaced with `TURNADO_USERNAME` and `TURNADO_PASSWORD`. `-p -` prompts for the password on a terminal. These methods avoid putting the password in the command line. On an exit started with `-c`, explicit flags take precedence over the credentials in the client's connection string, which take precedence over the environment variables.

Connection strings contain the TURN credentials. Set `TURNADO_PASSPHRASE` or use `--passphrase -` to encrypt them with a shared passphrase. Encrypted strings start with `tz1.` and require the same passphrase on the other peer. Strings without a passphrase are accepted as well. Supplying a passphrase as the value of `--passphrase` exposes it in the process command line.

Start the client and give its offer to the exit with `-c/--connect`. Enter the exit's answer once on the client's stdin.

If peer traffic stops for a minute, TURNado keeps the current allocations and sends heartbeats until valid traffic returns; a temporary interruption therefore needs no new connection strings. This applies to both modes: SOCKS streams stay open during the interruption and resume afterwards, and failed sends (for example while the network is unreachable) are retransmitted. If the TURN control connection is lost or pairing fails, TURNado exits with the cause. The exit's plaintext "permission ready" message only means it can send to the client relay; it has not yet observed client traffic.

If either process stops or receives a new relay address after its TURN allocation is lost, the saved peer address is stale. Pair again with new strings in that case.



### tunnel

The `tunnel` mode extends the custom encapsulation protocol of the `socks` mode to use it in combination with full layer 3 IP tunneling and packet fragmentation.
This way, high throughput can be achieved when tunneling arbitrary UDP and TCP traffic similar to a VPN:

1. Start the tunnel on the client side:

```sh
$ sudo turnado tunnel -t worldaz-msit.relay.teams.microsoft.com:443 -T tls -u <username> -p <password>
2026/02/06 13:13:46.229394 TURN UDP relays allocated at: [52.112.213.49:52523]
Connection string:
eyJ2IjoyL[...]
2026/02/06 13:13:46.230802 TUN device opened: turn0
```

2. Copy the connection string and use it to start the exit node tunnel:

```sh
$ sudo turnado tunnel -c eyJ2IjoyL[...]
2026/02/06 13:14:58.522896 TURN UDP relays allocated at: [52.112.213.45:51315]
2026/02/06 13:14:58.539115 Permission created for peer 52.112.213.49:52523
Connection string:
eyJ2IjoyL[...]
2026/02/06 13:14:58.857267 Waiting for authenticated DTLS handshake from client ...
```

3. Copy the connection string generated by the exit node and paste it into the client:

```sh
$ sudo turnado tunnel -t worldaz-msit.relay.teams.microsoft.com:443 -T tls -u <username> -p <password>
2026/02/06 13:13:46.229394 TURN UDP relays allocated at: [52.112.213.49:52523]
Connection string:
eyJ2IjoyL[...]
2026/02/06 13:13:46.230802 TUN device opened: turn0
eyJ2IjoyL[...]
2026/02/06 13:15:42.941983 Paired with 52.112.213.45:51315: DTLS fingerprint verified; SRTP_AES128_CM_HMAC_SHA1_80 active

```

4. Now, a virtual IP interface is created on both ends which can be used as usual:

```sh
$ ip -brief addr show dev turn0
turn0            UNKNOWN        10.0.1.2/24

$ ping 10.0.1.1 -c 4
PING 10.0.1.1 (10.0.1.1) 56(84) bytes of data.
64 bytes from 10.0.1.1: icmp_seq=1 ttl=64 time=68.3 ms
64 bytes from 10.0.1.1: icmp_seq=2 ttl=64 time=68.9 ms
64 bytes from 10.0.1.1: icmp_seq=3 ttl=64 time=71.7 ms
64 bytes from 10.0.1.1: icmp_seq=4 ttl=64 time=65.3 ms

--- 10.0.1.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3003ms
rtt min/avg/max/mdev = 65.308/68.560/71.726/2.278 ms

$ sudo ip route add 1.1.1.1 via 10.0.1.1 dev turn0

$ traceroute 1.1.1.1
traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 60 byte packets
 1  10.0.1.1 (10.0.1.1)  71.865 ms  71.858 ms  71.848 ms
    [...]
10  one.one.one.one (1.1.1.1)  74.671 ms  74.664 ms  74.670 ms
```

To effectively route traffic through the exit node, IP forwarding and NAT settings should be made, e.g.:

```sh
$ sudo sysctl -w net.ipv4.ip_forward=1

$ sudo iptables -t nat -A POSTROUTING -s 10.0.1.2 -o eth0 -j MASQUERADE
```

As with the `socks` mode, fingerprint-verified DTLS-SRTP is enabled by default. The exit creates its TUN interface after the handshake succeeds.

The TUN interface MTU follows the tunnel payload limit: 1194 bytes without peer encryption or 1172 bytes with SRTP. TCP SYN packets crossing the tunnel have their MSS clamped to that limit, with the TCP checksum updated. This avoids tunnel-level fragmentation for packets generated with the interface MTU. Larger forwarded packets can still be fragmented by TURNado.

Use `--client-ip` and `--exit-ip` on both peers to choose the IPv4 addresses. The defaults are `10.0.1.2` and `10.0.1.1` with a fixed `/24` netmask. The interface is named `turn%d` on Linux and assigned by the OS on macOS or Windows. Add destination routes with the operating system's routing tools. A default route can capture the TURN control connection, so add a server exception before changing it manually. A conventional TUN exit requires host forwarding and NAT configured separately.

On the exit, `turnado tunnel --rootless-exit -c OFFER` automatically sends TCP and UDP through a userspace NAT. No host forwarding, NAT rule, TUN device, or root privileges are needed on the exit. The client still needs a TUN device and a route for the desired destinations. The exit answers ICMP Echo requests to its own tunnel IP (default `10.0.1.1`); other ICMP traffic is not routed by the userspace stack. macOS assigns `utun` names automatically; Windows TUN needs Wintun and adapter configuration rights. The macOS and Windows implementations compile, but have not been run on those operating systems yet.


### forward

The `forward` mode allows blind UDP forwarding over TURN.
Therefore, a peer address must be supplied for which a UDP allocation and permissions are requested on the TURN server.
After successful allocation, arbitrary UDP traffic can be sent through the TURN server via a local listener created by TURNado:
The forwarder uses TURN Send Indications to preserve the exact UDP payload length, including for QUIC packets whose length is not divisible by four.


1. Start the `forward` mode and supply a peer on which the data to be sent:

```sh
$ turnado forward -t worldaz-msit.relay.teams.microsoft.com:443 -T tls -u <username> -p <password> -P ipinfo.io:443
2026/02/06 13:25:29.227356 Forward listening on 0.0.0.0:9999, forwarding via TURN to 34.117.59.81:443
```

2. Send UDP traffic, e.g., HTTP/3 (QUIC) via the local listener through the TURN server:

```sh
$ curl --http3-only --connect-to ipinfo.io:443:127.0.0.1:9999 https://ipinfo.io/
{
  "ip": "52.114.237.168",
  "city": "Gävle",
  "region": "Gävleborg",
  "country": "SE",
  "loc": "60.6745,17.1417",
  "org": "AS8075 Microsoft Corporation",
  "postal": "800 02",
  "timezone": "Europe/Stockholm",
  "readme": "https://ipinfo.io/missingauth"
}
```


### dos

The `dos` mode creates as many allocations as specified within the `-s/--sessions` parameter.
Since possible relayed address pairs are finite due to port exhaustion on the TURN server, this could cause a denial of service of the TURN service:

Use `--parallel N` to bound concurrent attempts (default 16), `--rate N` to limit new attempts per second, and `--stop-first` to stop after the first failed allocation. The output includes the number of successful and failed attempts and a histogram of TURN error codes. With `--stop-first`, a failure closes successful allocations and exits with an error; otherwise allocations stay active until Ctrl+C.

```sh
$ turnado dos -t <turnserver> -u <username> -p <password> -s 10000

    [...]

2026/01/30 10:25:57.216069 [session 3413] allocate failed: all retransmissions failed for J/4JdOaPqaazJbB1
2026/01/30 10:25:57.218983 [session 3933] allocate failed: all retransmissions failed for ncDklprMUn2ZZIw1
2026/01/30 10:25:57.220065 [session 3545] allocate failed: all retransmissions failed for AGpSwfIc7wbkVMuM
2026/01/30 10:25:57.220080 Active allocations: 3917/10000. Press Ctrl+C to close.
```

As shown above, only 3917 allocations were made successfully before the TURN service went into a denial of service state.

**USE THIS MODE WITH CAUTION!**



## Proxy support

Some enterprise infrastructures require proxy use even for non-HTTP protocols.
Therefore, turnado can route the connection to the TURN server through a proxy via the `--proxy` flag.

Supported schemes: `socks5://`, `socks5h://`, `http://`, `https://` (with optional `user:pass@` credentials).

```sh
turnado info -t worldaz-msit.relay.teams.microsoft.com:443 -T tls --proxy socks5://127.0.0.1:1080 -u <username> -p <password>

turnado socks -t <turnserver>:443 -T tls --proxy http://user:pass@proxy.local:8080 -u <username> -p <password>
```


## Blog Post

For more information on how to use it, common TURN pitfalls, and countermeasures, check out the [blog post](https://blog.syss.com/posts/turnado/)!



## Disclaimer

Use responsibly and only with permission from all relevant parties.
This toolkit is intended for **educational** and **research** purposes only.
