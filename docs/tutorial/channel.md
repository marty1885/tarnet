# Channels

Channels are the individual streams multiplexed over a tarnet connection. Each channel is addressed by a port name and a delivery mode. The mode controls reliability and ordering guarantees, and is negotiated when the connection is established.

## Modes

| Mode | Flag | Guarantees |
|---|---|---|
| Reliable ordered | `ro` | Delivered once, in order. Retransmits lost packets. |
| Reliable unordered | `ru` | Delivered once, in any order. Retransmits lost packets. |
| Unreliable unordered | `uu` | Best-effort. No retransmits, no ordering. |
| Sequenced datagram | `su` | In-order, but drops late packets instead of retransmitting. |

The default mode is `reliable-ordered`, suitable for most use cases. Use `unreliable-unordered` for latency-sensitive traffic like voice or real-time telemetry where retransmission would make things worse, not better.

Only reliable modes (`ro`, `ru`) can detect a broken link. They track ACKs and declare the channel dead after 60 seconds without a response. Unreliable modes (`uu`, `su`) have no acknowledgements, so they cannot tell whether the other side is still there - packets simply stop arriving with no notification.

Tarnet builds resilience at two layers. At the link layer, multiple transports to the same peer (e.g., TCP and WebRTC) are kept on standby - if the active link drops, the next-best is promoted automatically. At the circuit layer, tarnet maintains backup circuits through node-disjoint paths where possible, so a failure anywhere along one path doesn't take down the connection. If the primary circuit dies, a backup is promoted instantly. In reliable modes, any packets lost during a switch are retransmitted - the channel survives transport and path failures without the application noticing.

## Using Modes

Pass `--mode` to `tarnet connect` or `tarnet listen`:

```plaintext
tarnet listen default --port myport --mode ro
tarnet connect <service-id> --port myport --mode ro
```

Both sides must use the same mode. If they differ, the connection is rejected.

## Port Names

Port names are arbitrary strings. There are no reserved or well-known ports. By convention, use the service name (e.g., `ssh`, `http`, `myapp`).
