# tarnet

An anonymous peer-to-peer overlay network. Peers form encrypted links over TCP, route messages via distance-vector routing, and provide a DHT and decentralized and private naming system (TNS).

Early, experimental software. Not audited.

## Building

```
cargo build --release
```

Produces `tarnetd` (daemon) and `tarnet` (CLI) in `target/release/`.

## Quick start

Start a node:

```
tarnetd
```

On first run it generates an identity key, listens on `0.0.0.0:7946`, and starts a SOCKS5 proxy on `127.0.0.1:1080`.

Start a second node and connect it to the first:

```
tarnetd \
  --data-dir /tmp/node2 \
  --config-dir /tmp/node2/config \
  --listen 127.0.0.1:7947 \
  --connect 127.0.0.1:7946
```

Check status:

```
tarnet status
tarnet --data-dir /tmp/node2 status
```

## Connecting to peers

Open a bidirectional tunnel (netcat-style):

```
tarnet listen                    # node A waits for a connection
tarnet connect --peer <peer_id>  # node B connects
```

Or point any application at the SOCKS5 proxy (`127.0.0.1:1080`) — hostnames are resolved via TNS.

## Exposing services

Make a local TCP service reachable over the overlay. Drop a file in `~/.config/tarnet/services.d/`:

```toml
name = "my-web-server"
local = "127.0.0.1:8080"
publish = true
```

Reload with `tarnet reload` or `kill -HUP $(pidof tarnetd)`.

## DHT

Content-addressed storage:

```
tarnet dht put "hello world"     # prints hash
tarnet dht get <hash>            # retrieve by hash
```

## TNS (Tarnet Name System)

Zone-based decentralized naming. Each identity key defines a zone.

```
tarnet tns publish mysite peer <peer_id>     # publish a record
tarnet tns resolve alice.mysite              # resolve through delegation
```

## Tarify

Route a command's traffic through tarnet (like `torify`).

```
tarnet tarify -- curl http://somehost
```

## Configuration

tarnetd uses layered config: **code defaults < config file < CLI flags**.

On startup it writes `~/.config/tarnet/tarnetd.defaults.toml` as a reference. Override settings in `~/.config/tarnet/tarnetd.toml`:

```toml
[socks]
allow_clearnet = true # enables `tarify`-ed clients to access clearnet
```

Run `tarnetd --help` for all CLI options.

## License

Not yet specified.
