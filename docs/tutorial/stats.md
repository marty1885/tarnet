# Stats

`tarnet status` shows a snapshot of the running daemon's state. It is the first thing to check when diagnosing connectivity issues or getting a sense of how your node is participating in the network.

```plaintext
$ tarnet status
tarnetd up 2h34m  peer f73300e9

  name       privacy   hops   address
  default    public    1      K8SGMKEV...AXSG

  -> f73300e9f2e8d6f8  ws   12ms  idle 4s
     + 2 standby: 2-> tcp

  dht 18 records / 18 keys  kbucket 2  watches none  nse ~16
  circuits 3 out  1 fwd  5 end  2 rdv

           total      5m      1h      1d
      ↑     2.9K    2.9K    2.9K    2.9K
      ↓     1.4M  152.6K    1.4M    1.4M
   pkt↑       10      10      10      10
   pkt↓      626      68     626     626
```

## Header

```plaintext
tarnetd up 2h34m  peer f73300e9
```

Uptime and the local peer ID (first 8 hex chars). The peer ID identifies your node on the link layer - it is not the same as a ServiceId.

## Identities

```plaintext
  name       privacy   hops   address
  default    public    1      K8SGMKEV...AXSG
```

Each identity's name, privacy level, outbound hop count, and a truncated ServiceId. Public identities show in green, hidden in yellow.

## Peers

```plaintext
  -> f73300e9f2e8d6f8  ws   12ms  idle 4s
     + 2 standby: 2-> tcp
```

Active links to other nodes. Each line shows:

- Direction: `->` (you initiated) or `<-` (they initiated)
- Peer ID (16 hex chars)
- Transport (tcp, ws, webrtc)
- RTT (round-trip time, blank if unknown)
- Idle time since last activity

Standby links are summarised below the active link, grouped by transport and direction. A node may have multiple links to the same peer over different transports - only one is active at a time.

## Routes

```plaintext
  6ed62053e1f5bb6d  direct       cost 1
  f73300e9f2e8d6f8  via a1b2c3d4  cost 5
```

Destinations reachable through the routing table. Each entry shows the destination peer, next hop (`direct` if the peer is a neighbour), and path cost. An empty routes section means you only know about directly connected peers.

## DHT

```plaintext
  dht 18 records / 18 keys  kbucket 2  watches none  nse ~16
```

- **records / keys** - how many records and distinct keys are stored locally
- **kbucket** - peers in the routing table (used for DHT queries, not the same as the peers section)
- **watches** - active watch subscriptions (local/remote), shown as `none` if zero
- **nse** - network size estimate, a rough count of how many nodes the DHT thinks exist

## Circuits

```plaintext
  circuits 3 out  1 fwd  5 end  2 rdv
```

Onion routing circuit counts by your node's role:

- **out** - circuits you originated (your outbound connections)
- **fwd** - circuits you are relaying as a middle hop
- **end** - circuits where you are the destination endpoint
- **rdv** - rendezvous points you are serving (connecting two hidden parties)
- **intro** - introduction points you are serving for hidden identities

Roles with zero circuits are omitted. A healthy relay node will show `fwd` and possibly `rdv` or `intro` counts in addition to `out`.

## Traffic

```plaintext
           total      5m      1h      1d
      ↑     2.9K    2.9K    2.9K    2.9K
      ↓     1.4M  152.6K    1.4M    1.4M
   pkt↑       10      10      10      10
   pkt↓      626      68     626     626
```

Upload and download totals in bytes and packets, broken down by time window: total since startup, last 5 minutes, last hour, and last day. Upload is green, download is blue. A `relay` row appears if your node is forwarding cells for other circuits.
