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

Hidden identities publish no peer record. Instead, they register introduction points - relay nodes that accept connections on the identity's behalf via rendezvous. The connecting peer never learns the hidden identity's peer ID or location. The tradeoff is that direct connections are impossible - a minimum of two hops is needed. This applies symmetrically: both the connecting and listening side independently choose their privacy level.

```plaintext
tarnet identity update --privacy hidden alice
Updated identity 'alice':
  Privacy:       Hidden { intro_points: 3 }
  Outbound hops: 1
```

`intro_points` controls the number of onion-routed hops guarding inbound connections. `outbound_hops` controls outbound hops. Both are independent.

## Hop Counts

**Public Identities** connect directly to other identities with minimal hops (the actual hop count may be higher than `outbound_hops` due to network topology):

```plaintext
┌─────────────┐         ┌──────────────┐
│   Alice     │ direct  │    Bob       │
│  (Public)   │────────>│  (Public)    │
└─────────────┘         └──────────────┘
   1 hop                    1 hop
```

**Hidden Identities** add anonymity by routing through onion-routed hops. The outbound path depends on Alice's `outbound_hops`; the inbound path depends on Alice's `intro_points`. Bob's own hops are added on top:

```plaintext
Outbound Connection (Alice connects to Bob):
┌─────────────┐     ┌─────────┐           ┌─────────┐     ┌──────────────┐
│   Alice     │────>│  Hop 1  │── ··· ───>│  Hop N  │────>│    Bob       │
│  (Hidden)   │     │         │           │         │     │  (any type)  │
└─────────────┘     └─────────┘           └─────────┘     └──────────────┘
   Alice's outbound hops                    + Bob's intro_points (if hidden)

Inbound Connection (Bob connects to Alice):
┌──────────────┐     ┌──────────┐           ┌──────────┐     ┌─────────────┐
│    Bob       │────>│  Hop 1   │── ··· ───>│ Intro Pt │────>│   Alice     │
│  (any type)  │     │          │           │    N     │     │  (Hidden)   │
└──────────────┘     └──────────┘           └──────────┘     └─────────────┘
   Bob's outbound hops                       + Alice's intro_points
```

Hop counts are additive. Bob with 3 `intro_points` and Alice with 2 outbound hops means 5 hops between the two machines:

```plaintext
┌─────────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌─────────────┐
│   Alice     │────>│  Hop 1   │────>│  Hop 2   │────>│ Intro Pt │────>│ Intro Pt │────>│    Bob      │
│  (Hidden)   │     │          │     │          │     │    1     │     │    2     │     │  (Hidden)   │
│out_hops:  2 │     └──────────┘     └──────────┘     └──────────┘     └──────────┘     │intro_pts: 3 │
└─────────────┘                                                                         └─────────────┘
               │<──────────── 2 out ────────────>│<──────── 3 intro_points (inbound) ───>│
               │<──────────────────────────── 5 total hops ─────────────────────────────>│
```
