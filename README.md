# tarnet

An overlay network reimagining how the internet should be and does not assume the internet exists. 

Early, experimental software. Not audited.

## Features

* Cryptographic and flat address space
* Idententies decoupled from machine ID
* Decentralized name resoulution and zone delegation
* Reverse proxy to expose TCP/UDP services to Tarnet
* Multipath connections to tolorate unstable intermideate nodes
* All traffic end to end and hop to hop encrypted
* NAT punching support via WebRTC

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

On first run it generates machine and default identity key, listens on `0.0.0.0:7946`, and starts a SOCKS5 proxy on `127.0.0.1:1080`. Then `tarnet status` to check if things are working as expected:

```plaintext
❯ tarnet status
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

A default idententity is creatred. `tarnet identity list` to view avaliable identities.

```plaintext
❯ tarnet identity list
default
  ServiceId:     Y5W91FTBT93YMEZ7ZNKZ4AKCJQPSCHDJPV6CQ7K8XJGMJBBK21X0
  Scheme:        falcon_ed25519
  Signing:       falcon_ed25519
  KEM:           mlkem_x25519
  Privacy:       Public
  Outbound hops: 1
```

In Tarnet, the service id associated with the identity is the equlivant of an IP addresse that can be listened on and connected to. Ports are arbitrary strings. 

```plaintext
❯ tarnet listen default
Listening on Y5W91FTBT93YMEZ7ZNKZ4AKCJQPSCHDJPV6CQ7K8XJGMJBBK21X0 port 'tarnet-echo'.
Waiting for connections... (Ctrl-C to quit)

(in another terminal, or a different machine)
❯ tarnet connect Y5W91FTBT93YMEZ7ZNKZ4AKCJQPSCHDJPV6CQ7K8XJGMJBBK21X0
Connecting to Y5W91FTBT93YMEZ7ZNKZ4AKCJQPSCHDJPV6CQ7K8XJGMJBBK21X0 port 'tarnet-echo'...
Connected to Y5W91FTBT93YMEZ7ZNKZ4AKCJQPSCHDJPV6CQ7K8XJGMJBBK21X0. Type to send, Ctrl-C to quit.
```
