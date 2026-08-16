# Iroh Sidecar Contract

DeskAccess can use the official Rust iroh stack through a local sidecar while
keeping pairing, session tokens, and TCP service bridging in Go.

When the iroh backend is active, DeskAccess looks for a bundled
`deskaccess-iroh-sidecar` binary and starts it automatically. There is no
`[iroh.sidecar]` user config block. DeskAccess launches the sidecar with
`--listen 127.0.0.1:0`, waits for a ready file, and then talks to the
dynamically assigned local control URL.

The sidecar binary lives in `sidecars/iroh-sidecar` and can be built with:

```powershell
cargo build --manifest-path sidecars\iroh-sidecar\Cargo.toml --release
```

For a local repo build, DeskAccess finds the binary under
`sidecars/iroh-sidecar/target/release` or `sidecars/iroh-sidecar/target/debug`.
Packaged builds should place `deskaccess-iroh-sidecar` beside the DeskAccess
executable, in `sidecars`, or in `bin`.

The same sidecar binary is used on the sharing host and on the pairing/client
machine. It owns one iroh endpoint, registers callback TCP listeners from
DeskAccess for incoming pairing/tunnel streams, and exposes outgoing streams as
temporary local TCP sockets for the existing Go backend interfaces.

## HTTP Control API

### `GET /status`

Returns:

```json
{
  "running": true,
  "ready": true,
  "endpoint_id": "...",
  "relay_urls": 1,
  "direct_addrs": 2,
  "last_error": ""
}
```

### `POST /handlers`

Called once by DeskAccess after it starts local callback listeners.

Request:

```json
{
  "pairing_addr": "127.0.0.1:50001",
  "tunnel_addr": "127.0.0.1:50002",
  "pairing_alpn": "DeskAccess/pairing/iroh/1",
  "tunnel_alpn": "DeskAccess/tunnel/iroh/1"
}
```

When the sidecar accepts an incoming iroh pairing or tunnel stream, it connects
to the matching callback address, writes one JSON metadata line, then forwards
raw stream bytes:

```json
{"peer_id":"12D3...","path":"direct","remote_addr":"..."}
```

The newline after that JSON object is required. Everything after it is raw
DeskAccess protocol bytes.

### `POST /ticket`

Returns the current iroh endpoint ticket:

```json
{
  "ticket": "...",
  "endpoint_id": "..."
}
```

### `POST /open`

Opens an outgoing iroh stream and exposes it as a temporary local TCP stream.

Request:

```json
{
  "kind": "tunnel",
  "ticket": "..."
}
```

`kind` is either `pairing` or `tunnel`.

Response:

```json
{
  "addr": "127.0.0.1:50003",
  "path": "direct",
  "remote_addr": "..."
}
```

DeskAccess dials `addr` and then sends raw pairing/tunnel protocol bytes.

### `POST /close_tunnel`

Best-effort cleanup for cached tunnel state.

Request:

```json
{
  "peer_id": "12D3...",
  "reason": "local proxy closed"
}
```

Response:

```json
{
  "closed": 1
}
```

### `POST /shutdown`

Optional. Called when DeskAccess stops the sidecar backend.
