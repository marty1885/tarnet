# Identity

Identities can be thought of as different names for your tarnet instance, similar to an IP address on the network. Identities can sign their own data, be listened on, and connect to other identities.

Each identity is associated with a public/private key pair and a ServiceId derived from the public key.

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

All identities have an anonymity level, set to `public` by default. You can use `identity update --privacy hidden` to make them hidden. Hidden identities set `intro_points` - the number of onion-routed hops that guard inbound connections, so that connecting peers never learn your node's real location. Both public and hidden identities have `outbound_hops`, controlling the number of onion-routed hops for outbound connections.

```plaintext
tarnet identity update --privacy hidden alice
Updated identity 'alice':
  Privacy:       Hidden { intro_points: 3 }
  Outbound hops: 1
```

See the following diagrams for details. **Public Identities** connect directly to other identities with minimal hops (the actual hop count may be higher than `outbound_hops` due to network topology):

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

Note that hop counts are additive. Bob with 3 `intro_points` and Alice with 2 outbound hops means 5 hops between the two machines:


```plaintext
┌─────────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌─────────────┐
│   Alice     │────>│  Hop 1   │────>│  Hop 2   │────>│ Intro Pt │────>│ Intro Pt │────>│    Bob      │
│  (Hidden)   │     │          │     │          │     │    1     │     │    2     │     │  (Hidden)   │
│out_hops:  2 │     └──────────┘     └──────────┘     └──────────┘     └──────────┘     │intro_pts: 3 │
└─────────────┘                                                                         └─────────────┘
               │<──────────── 2 out ────────────>│<──────── 3 intro_points (inbound) ───>│
               │<──────────────────────────── 5 total hops ─────────────────────────────>│
```
