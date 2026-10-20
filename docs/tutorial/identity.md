# Identity

Identities can be thought of as different names for your tarnet instance, similar to an IP address on the network. Identities can sign their own data, be listened on, and connect to other identities.

Each identity is a set of keys derived from one secret seed, and its ServiceId is a hash over its public keys. Identities are hybrid post-quantum: they sign with Ed25519 and Falcon-512, and their ServiceId also commits to backup ML-DSA and SLH-DSA keys. If Falcon ever has to be retired, a software update switches the signatures to a backup and every ServiceId stays the same. The KEM is ML-KEM-768 combined with X25519.

A node can have multiple identities - for example, separate identities for different services or contexts, each with its own privacy level. Connecting or publishing records as one identity reveals nothing about your other identities.

Every connection carries the connecting identity's ServiceId, proven with a signature, so a service always knows which ServiceId is calling: think of it as the caller's IP address. A connection comes from your `default` identity unless the application picks another. To stay anonymous, connect from a throwaway identity (below) that leads back to nobody, over enough hops that the service can't see your node.

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

And `identity delete` removes an identity permanently, along with everything filed under it: its TNS labels, its published records and its listeners. A new identity created later under the same name starts empty.

```plaintext
tarnet identity delete alice
Delete identity 'alice'? This is irreversible. [N/y] y
Deleted identity 'alice'.
```

## Throwaway identities

An application can ask the daemon for a throwaway identity: a fresh ServiceId that lives only in the daemon's memory and belongs to that application's connection. It can connect out and listen like any identity. It is gone when the application drops it, when the application disconnects, or when the daemon restarts, and nothing of it is ever written to disk. A throwaway is Hidden by default, with at least 3 hops. It can be Public when you only want a new name and don't need to hide where it runs. It can't own TNS labels set by applications: anything that needs a lasting name should use an ordinary identity.

Applications get them through the API (`create_ephemeral_identity`). From the command line, `--ephemeral` gives `listen` and `connect` a fresh Hidden throwaway for as long as the command runs:

```plaintext
$ tarnet listen --ephemeral --port hello
Publishing intro points for throwaway identity WCM0FGX0QSKSGH2YEH6SMCTD9QDG8NKKWJ5RBW8F445ZN9AK9N90...
Listening on WCM0FGX0QSKSGH2YEH6SMCTD9QDG8NKKWJ5RBW8F445ZN9AK9N90 mode ReliableOrdered port 'hello'.

$ tarnet connect --ephemeral --port hello WCM0FGX0QSKSGH2YEH6SMCTD9QDG8NKKWJ5RBW8F445ZN9AK9N90
Connecting as throwaway identity QMEC9NVN45X0DMM3ADW2W9F55RZVP97EASXC7TY0HBHE6HDBGNSG.
```

The listener sees the connection come from `QMEC9…`, not from your `default` identity. Both identities are erased when their command exits.

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
