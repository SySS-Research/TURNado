# Local coturn lab

These configurations bind only to host loopback and use example credentials. They use host networking, so they are intended for a Linux development machine. The default `restricted` server listens on `127.0.0.1:3478`, limits allocations and blocks internal peers. The optional `permissive` server listens on `127.0.0.1:3479` and permits loopback peers and TCP relays. It is for local tests only.

```sh
docker compose -f lab/compose.yaml up -d
docker compose -f lab/compose.yaml --profile permissive up -d
go run ./cmd/turnado info -t 127.0.0.1:3478 -u test -p password
go run ./cmd/turnado info -t 127.0.0.1:3479 -u test -p password
docker compose -f lab/compose.yaml --profile permissive down
```

The restricted server's `--user-quota=4` can be tested with `dos --sessions 8 --parallel 1 --stop-first`. The permissive server is intended for the relay response and RFC 6062 probes. The two servers use separate relay port ranges.
