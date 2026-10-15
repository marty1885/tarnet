# Identity

Identities can be thought of as different names for your tarnet instance, similar to an IP address on the network. Identities can sign their own data, be listened on, and connect to other identities.

Each identity is associated with a public/private key pair and a ServiceId derived from the public key. The cryptographic scheme is pluggable - the default `falcon_ed25519` is a hybrid post-quantum scheme, but the protocol does not assume any specific algorithm. A pure `ed25519` scheme is available and has better performance, but should be avoided as it offers no post-quantum protection.

A node can have multiple identities - for example, separate identities for different services or contexts, each with its own privacy level. Connecting or publishing records as one identity reveals nothing about your other identities.

The `default` identity is created automatically on first run and cannot be deleted.

The `identity` subcommand performs operations on identities. `identity list` shows all available identities at the time of invocation.

```plaintext
$ tarnet identity list
default
  ServiceId:     K8SGMKEVVV0R4C9SRFKN92RS4RTKWTTCTK146RYSQZEJ0K63AXSG
  Scheme:        falcon_ed25519
  Signing:       falcon_ed25519
  KEM:           mlkem_x25519
  Privacy:       Public
  Outbound hops: 1
```

`identity create <name>` creates a new identity.

```plaintext
$ tarnet identity create alice
Created identity 'alice': Y8VQVBC11TYHCHAJP1HG3ZAAVQ5GDT4CWKG4H7G86AKD3XKWRR0G
  Scheme:        falcon_ed25519
  Privacy:       Public
  Outbound hops: 1
```

And `identity delete` removes an identity permanently.

```plaintext
tarnet identity delete alice
Delete identity 'alice'? This is irreversible. [N/y] y
Deleted identity 'alice'.
```

## Privacy

All identities have an anonymity level, set to `public` by default.

A public identity publishes a peer record in TNS, mapping its ServiceId to the underlying peer ID. Anyone who resolves the ServiceId learns the peer ID and can look up the hello record - which advertises transports and addresses. This allows direct circuit building but means your node's network identity is discoverable.

Hidden identities publish no peer record and refuse direct connections. Instead, they register introduction points - relays that hold a circuit open to the identity and pass on connection requests - and meet the connecting peer at a rendezvous point. The connecting peer never learns the hidden identity's peer ID or location. The tradeoff is that direct connections are impossible: every connection takes at least two circuits, one from each side. This applies symmetrically: both the connecting and listening side independently choose their privacy level.

```plaintext
tarnet identity update --privacy hidden alice
Updated identity 'alice':
  Privacy:       Hidden { intro_points: 3 }
  Outbound hops: 3
```

`intro_points` is the number of introduction points the identity registers (and so how many places a client can ask to be introduced). It does not add hops. `outbound_hops` is the length of every circuit the identity builds: the circuits to its introduction points, the circuits to rendezvous points, and its own outgoing connections. The two are independent. Hidden identities should use an `outbound_hops` of at least 3: with fewer, the circuits have few or no waypoints between you and the relay at the far end.

## Hop Counts

**Public Identities** connect directly to other identities with minimal hops (the actual hop count may be higher than `outbound_hops` due to network topology):

```plaintext
┌─────────────┐         ┌──────────────┐
│   Alice     │ direct  │    Bob       │
│  (Public)   │────────>│  (Public)    │
└─────────────┘         └──────────────┘
   1 hop                    1 hop
```

**Hidden Identities** reach each other through a rendezvous point. The client picks the rendezvous point and builds a circuit to it using the client's `outbound_hops`. It then sends an introduction request through one of the service's introduction points. The service builds its own circuit to the rendezvous point using the service's `outbound_hops`, and the rendezvous point joins the two:

```plaintext
Bob (any type) connects to Alice (Hidden):

┌──────────────┐  Bob's outbound_hops   ┌────────────┐  Alice's outbound_hops  ┌─────────────┐
│    Bob       │───> ··· ──────────────>│ Rendezvous │<────────────── ··· <────│   Alice     │
│  (any type)  │                        │   point    │                         │  (Hidden)   │
└──────────────┘                        └────────────┘                         └─────────────┘
        │                                                                              ▲
        └──── introduction request via one of Alice's intro_points ────────────────────┘
```

The introduction request is sealed to Alice's key, so the introduction point can't read it. Alice's circuits to her introduction points stay open, but they only carry the request. The data flows through the rendezvous point, with an extra end-to-end encryption layer that the rendezvous point can't remove.

Hop counts are additive. If Bob uses 2 outbound hops and Alice uses 3, the path between the two machines is 2 + 3 hops, each ending at the rendezvous point:

```plaintext
┌─────────────┐   ┌───────┐   ┌─────────────┐   ┌───────┐   ┌───────┐   ┌─────────────┐
│    Bob      │──>│ Hop 1 │──>│ Rendezvous  │<──│ Hop 2 │<──│ Hop 1 │<──│   Alice     │
│ out_hops: 2 │   └───────┘   │   point     │   └───────┘   └───────┘   │ out_hops: 3 │
└─────────────┘               └─────────────┘                           └─────────────┘
│<──── 2 hops ────>│          │<────────────── 3 hops ────────────────>│
```
