# Channels

Channels are multiplexed message streams over a tarnet connection. Each channel is addressed by a port name and a delivery mode. The mode controls reliability and ordering guarantees, and is negotiated when the connection is established.

Tarnet delivers discrete messages, not byte streams. Each send is received as a complete message on the other side, preserving boundaries - more like UDP datagrams or WebSocket frames than TCP. The delivery mode controls what happens to those messages in transit.

## Modes

| Mode | Flag | Guarantees |
|---|---|---|
| Reliable ordered | `ro` | Delivered once, in order. Retransmits lost packets. |
| Reliable unordered | `ru` | Delivered once, in any order. Retransmits lost packets. |
| Unreliable unordered | `uu` | Best-effort. No retransmits, no ordering. |
| Sequenced datagram | `su` | In-order, but drops late packets instead of retransmitting. |

The default mode is `reliable-ordered`, suitable for most use cases. Use `unreliable-unordered` for latency-sensitive traffic like voice or real-time telemetry where retransmission would make things worse, not better.

Only reliable modes (`ro`, `ru`) can detect a broken link. They track ACKs and declare the channel dead after 60 seconds without a response. Unreliable modes (`uu`, `su`) have no acknowledgements, so they cannot tell whether the other side is still there - packets simply stop arriving with no notification.

At the link layer, multiple transports to the same peer (e.g., TCP and WebRTC) can be kept on standby. Reliable channels recover lost packets while their circuit remains usable, including losses during a link transport switch. An explicitly destroyed circuit closes its connection; automatic migration of an established channel to a replacement circuit is not guaranteed.

## Reliability over circuits

Circuit connections use the same `Channel` sequencing, acknowledgements, deduplication, and retransmission machinery as tunnel channels. A circuit is a datagram carrier: its crypto handles authenticity, nonce uniqueness, and replay protection, not delivery or ordering. Links carry opaque cells over whichever transport is available and do not track end-to-end acknowledgements.

Each reliable channel retains its unacknowledged packets within a bounded sending window. An acknowledgement includes a cumulative sequence position and selective acknowledgements for out-of-order packets. If an acknowledgement is lost, a duplicate packet is acknowledged again without being delivered twice. Retransmissions keep their channel sequence number but are encrypted as new circuit cells with fresh crypto nonces.

For circuit connections, final EOF is also sequenced and acknowledged. It closes only the sending direction, after earlier data has arrived; the opposite direction can continue. Circuit destruction is an abrupt failure instead. Unreliable connections have no delivery acknowledgements or retransmissions.

Channel DATA and ACKs are inside the onion-encrypted, fixed-size cells and follow the circuit, so intermediate relays cannot read delivery metadata. Nonce origin domains are blinded at each onion layer rather than exposing an identical domain along the path. This does not eliminate traffic analysis of timing and volume.

These circuit framing and nonce changes require wire protocol version **3**. All participating nodes must be upgraded; version 2 is incompatible.

## Using Modes

Pass `--mode` to `tarnet connect` or `tarnet listen`:

```plaintext
tarnet listen default --port myport --mode ro
tarnet connect <service-id> --port myport --mode ro
```

Both sides must use the same mode. If they differ, the connection is rejected.

## Port Names

Port names are arbitrary strings. There are no reserved or well-known ports. By convention, use the service name (e.g., `ssh`, `http`, `myapp`).
