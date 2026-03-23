# tarnetd

`tarnetd` is the daemon that runs the tarnet node. It manages peer links, routing, the DHT, name resolution, and all identities. The CLI and other tools communicate with it over a Unix socket.

## Starting

```plaintext
tarnetd
```

Optional flags:

```plaintext
tarnetd --data-dir <path>    # default: $XDG_DATA_HOME/tarnet
tarnetd --config-dir <path>  # default: $XDG_CONFIG_HOME/tarnet
```

## Configuration

The config file is at `~/.config/tarnet/tarnetd.toml`. It is created with defaults on first run.

**Transports:**

```toml
[transport.tcp]
listen = ["0.0.0.0:7946"]

[transport.webrtc]
enabled = true   # NAT traversal via WebRTC

[transport.ws]
enabled = false  # WebSocket (useful behind reverse proxies)
```

**Bootstrap:**

```toml
[bootstrap]
peers = [
  "tcp://relay.example.com:7946",
]
mdns = true      # LAN peer discovery
mainline = false # Announce on BitTorrent DHT
```

Bootstrap peers can also be passed on the command line. A single known address is enough - the routing algorithm discovers the rest. IPv6 link-local addresses with interface scope are supported.

```plaintext
tarnetd --bootstrap tcp://192.168.1.50:7946
tarnetd --bootstrap tcp://[fe80::1%eth0]:7946
```

Tarnet does not require the internet. The distance-vector routing handles arbitrary topologies. If two separate networks gain a node in common, routes and the DHT merge automatically. Private and link-local addresses are never advertised beyond the local network.

**Bandwidth limits:**

```toml
[core]
upload_limit = "10Mbps"
download_limit = ""     # empty = unlimited
```

**SOCKS proxy:**

```toml
[socks]
enabled = true
bind = ["127.0.0.1:1080"]
allow_clearnet = false
```

The SOCKS proxy resolves names through TNS first. If TNS finds an identity record, the connection is routed over tarnet. If TNS resolution fails, `allow_clearnet` controls what happens next: when `false` (the default), the connection is refused. When `true`, unresolved names fall through to regular DNS and are connected over the internet. See [Tarify and SOCKS](tarify.md) for details.

## Reloading

To apply config changes without restarting:

```plaintext
tarnet reload
```

## Logs

Set `RUST_LOG` to control log verbosity:

```plaintext
RUST_LOG=info tarnetd
RUST_LOG=debug tarnetd
```
