# tarnet

A peer-to-peer overlay network that doesn't assume the internet exists.

Early, experimental software. Not audited.

## What you get

- **Cryptographic identities** - flat address space derived from public keys, decoupled from machine or network identity
- **Onion-routed circuits** - configurable privacy per identity, from direct connections to multi-hop hidden services
- **Name system (TNS)** - decentralised name resolution with zone delegation, private by default
- **Message-based channels** - four delivery modes (reliable ordered, reliable unordered, unreliable unordered, sequenced datagram) with multipath failover
- **Service exposure** - reverse proxy local TCP/UDP services onto the network
- **Tarify** - route any application through tarnet transparently (like torify)
- **NAT traversal** - WebRTC and STUN support
- **Works offline** - runs on a LAN, air-gapped network, or the internet. If two separate networks gain a node in common, they merge

## Building

```bash
cargo build --release
```

Produces `tarnetd` (daemon) and `tarnet` (CLI) in `target/release/`.

## Quick start

Start a node:

```bash
tarnetd
```

On first run it generates a default identity, listens on `0.0.0.0:7946`, and starts a SOCKS5 proxy on `127.0.0.1:1080`.

```plaintext
$ tarnet status
tarnetd up 40m0s peer b34a658630bb740f
  name      privacy  hops   address
  default   public   1      6D36JJHJ...KFP0

  -> f73300e9f2e8d6f8  ws      -  idle 27s
  -> 6ed62053e1f5bb6d  webrtc  -  idle 5s

  f73300e9f2e8d6f8  direct                cost 1
  6ed62053e1f5bb6d  direct                cost 1

  dht 18 records / 18 keys  kbucket 2  watches none  nse ~16
  circuits none

            total       5m       1h       1d
       ↑     2.9K     2.9K     2.9K     2.9K
       ↓     1.4M   152.6K     1.4M     1.4M
    pkt↑       10       10       10       10
    pkt↓      626       68      626      626
```

The ServiceId is your address on the network. Listen on it, connect to it. Ports are arbitrary strings.

```plaintext
$ tarnet listen default
Listening on Y5W91FTBT93YMEZ7ZNKZ4AKCJQPSCHDJPV6CQ7K8XJGMJBBK21X0 port 'tarnet-echo'.
Waiting for connections... (Ctrl-C to quit)
[+] Connection from 6D36JJHJ9W3W0CYSZB8ME7RG1C12V78G9255AJMXBYFJ2KMTKFP0
```

```plaintext
$ tarnet connect Y5W91FTBT93YMEZ7ZNKZ4AKCJQPSCHDJPV6CQ7K8XJGMJBBK21X0
Connecting to Y5W91FTBT93YMEZ7ZNKZ4AKCJQPSCHDJPV6CQ7K8XJGMJBBK21X0 port 'tarnet-echo'...
Connected. Type to send, Ctrl-C to quit.
```

Or use TNS names and existing applications:

```plaintext
$ tarnet tns set alice zone <alice-service-id>
$ tarnet tarify ssh alice
```

See the [tutorial](docs/tutorial/) for the full guide.
