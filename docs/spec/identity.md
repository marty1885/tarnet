# Identity and cryptography v2

Status: **implemented (2026-10-20)**, except key lifetime on circuits (see
"Key lifetime"). This is the spec for one hard break, wire version 10. It replaces how identities are built, how
every handshake derives keys, how clients authenticate and how the daemon
serves applications. After it, identities and the crypto wire format are
frozen or extensible. Everything under "Local policy" may change without a
break.

The break comes before the messenger (a shared message bus, roughly GNUnet's
gnunet-messenger). The messenger needs authenticated members, signing bound
to identities, and per-application isolation in the daemon. Doing the
identity and post-quantum work in the same break means it never has to
happen again.

## Goals

* **Post-quantum now.** Confidentiality is always hybrid (ML-KEM + X25519).
  Authentication is hybrid for every long-lived identity.
* **Identities survive future algorithm changes.** A SID commits to backup
  keys, so retiring an algorithm changes the verification rule, not the SID.
* **No negotiation, no fallback.** Each version accepts exactly one
  algorithm per role. Anything else is refused, never downgraded.
* **Keys are bound to transcripts.** Every handshake derives its keys from
  the secrets *and* a hash of everything exchanged.
* **Every connection names its client.** The client's SID is authenticated
  on every connection. Hiding means using a throwaway SID.

Out of scope: the DHT's walks and placement, and routing. The DHT *record
encoding* does change, because records carry the signer's keys (see
"Compatibility").

## Model

* **A PeerId is a MAC address.** It names a node's location. Link
  neighbours see it, and so does anyone the node reaches over a 1-hop
  circuit or who resolves a Public identity's `peer` record.
* **A ServiceId (SID) is an IP address.** Applications talk to SIDs. Every
  connection carries the client's authenticated SID.
* **There are three kinds of identity:**
  * **Persistent:** stored, named, may own a TNS zone; Public or Hidden.
  * **Pseudonym:** a persistent identity that isn't your main one, usually
    Hidden. Messenger room membership and anything else that must last uses
    one.
  * **Throwaway:** lives in memory only and belongs to one IPC client. It
    can connect and listen (see "Throwaway identities").
* **A client is anonymous only with both of:**
  * a SID that leads back to nobody: a throwaway;
  * enough hops that the host can't see the client's PeerId: Hidden with
    `outbound_hops ≥ 3`.

  A long-lived SID over 3 hops is an unlocatable pseudonym whose
  connections can be linked. A fresh SID over 1 hop hides nothing.

## Primitives

| Role | Algorithm | Standard | Sizes |
|---|---|---|---|
| Classical signature | Ed25519 | RFC 8032 | pk 32, sig 64 |
| PQ signature (active) | Falcon-512 | round 3; FIPS 206 (FN-DSA) not yet final | pk 897, sig ≈ 660 (≤ 666) |
| PQ signature (backup) | ML-DSA-44 | FIPS 204 | pk 1312, sig 2420 |
| PQ signature (backup) | SLH-DSA-SHA2-128s | FIPS 205 | pk 32, sig 7856 |
| KEM | ML-KEM-768 + X25519, combined as below | FIPS 203; X-Wing structure | pk 1216, ct 1120, ss 32 |
| Hash / KDF / MAC | BLAKE3 (`derive_key`, keyed) | | 32 B |
| AEAD | XChaCha20-Poly1305 | | |

* **v1 used Kyber768 round 3 and called it ML-KEM.** `pqcrypto-kyber 0.8`
  derives a different shared secret from FIPS 203, so the two don't
  interoperate. v2 uses FIPS 203.
* **Security levels.** Falcon-512 is NIST level 1 and ML-KEM-768 level 3.
  That pairing is accepted: Falcon-1024 would double every signature.
* **Crates.**
  * RustCrypto `ml-kem` 0.3 (FIPS 203), `ml-dsa` 0.1 (FIPS 204) and
    `slh-dsa` 0.2.0-rc.5 (FIPS 205, pinned). They are wrapped in
    `crates/tarnet-pq` behind non-generic functions, so they compile
    optimised in debug builds too. Unoptimised, an SLH-DSA key generation
    takes about half a second.
  * Falcon-512 is `pqcrypto-falcon` 0.3 (round 3).
  * `fn-dsa` was not used: it implements the FN-DSA *draft*, and its own
    docs warn that its keys may not match the final standard.
* Measured on an Apple-silicon Mac (pqcrypto, release build): Falcon-512
  keygen 3.9 ms, sign 86 µs, verify 13 µs; ML-KEM-768 keygen 7 µs; Ed25519
  keygen 8 µs. A Pi Zero is expected to be 30–60× slower (not measured).

### KEM combiner

```
pk = pk_X(32) || ek_M(1184)
(ct_M, ss_M) = ML-KEM-768.Encaps(ek_M)             FIPS 203, fresh random m
(ct_X, ss_X) = X25519 ephemeral DH with pk_X       ct_X = the ephemeral public key
ct = ct_X(32) || ct_M(1088)
ss = BLAKE3-derive_key("tarnet kem v2", ss_M || ss_X || ct_X || pk_X)
```

This follows X-Wing (draft-connolly-cfrg-xwing-kem): it binds the X25519
ciphertext and public key, and ML-KEM's own shared secret already binds
`ct_M`. Only tarnet uses this, so the draft's status doesn't matter.
Today's combiner hashes the two secrets alone.

### Rules for every key agreement

1. **Session KEMs are always the combined KEM above**, whatever scheme the
   identity uses. Any node can run an ephemeral ML-KEM, so ECC throwaways
   get PQ confidentiality too.
2. **Algorithm bytes stay on the wire for future versions, but each version
   accepts exactly one value.** Other values are refused (DESTROY, refusal,
   handshake abort). There is no `negotiate`.
3. **Keys come from `KDF(secret, H(transcript))`.** The transcript covers
   the version, every public key, every ciphertext, both nonces and the
   identities. Circuits already do this, and v2 extends it to links,
   rekeys, tunnels and INTRODUCE.
4. **Parse failures are hard errors.** No code path rebuilds a weaker
   identity or key from bytes it couldn't parse.

## Identity v2

### Seed and key derivation

Each identity has a 32-byte master seed `S`. Every key comes from it under
its own label:

```
k(label) = BLAKE3-derive_key("tarnet identity v2 " || label, S)

Ed25519 seed        = k("ed25519")
ML-DSA-44 ξ         = k("ml-dsa-44")                                   FIPS 204 KeyGen_internal
SLH-DSA seeds       = XOF(derive_key("tarnet identity v2 slh-dsa seeds", k("slh-dsa")))[..48]
                                                                       SK.seed, SK.prf, PK.seed
Falcon-512          = random key generation (round-3 Falcon fixes no seeded derivation)

static KEM, generation n:
  kem_seed          = derive_key("tarnet identity v2 kem", S || n(u32))
  X25519            = derive_key("tarnet identity v2 x25519", kem_seed)  no longer the Ed25519 seed
  ML-KEM-768 (d, z) = XOF(derive_key("tarnet identity v2 ml-kem-768", kem_seed))[..64]
```

* **Stored form:**

  ```
  version(2) || scheme || seed(32) || kem_generation(u32) || id_check(32)
    [hybrid] || falcon_sk_len(u16) || falcon_sk || falcon_pk_len(u16) || falcon_pk
             || mldsa44_leaf(32) || slhdsa_leaf(32)
  ```

  * The Falcon key pair is stored because no standard fixes its key
    generation.
  * The backup leaves are derived once, when the identity is created, and
    stored. SLH-DSA key generation is slow on small machines, and the leaves
    are what the identity commits to.
* **On load,** the Ed25519 key and the static KEM key are re-derived from
  the seed and the bundle is rebuilt. If it doesn't hash to `id_check` (the
  PeerId-domain hash), loading fails. A mismatch is a hard error, never a
  fallback.
* **The static KEM key rotates with its generation `n`.** It is published
  in intro records signed by the identity and is not part of the SID.
* **Every identity's static KEM is hybrid,** ECC throwaways included:
  ML-KEM key generation costs microseconds, so INTRODUCE to any identity is
  post-quantum confidential.
* **Disposable record keys** (the outer signer of pool claims) are hybrid,
  so a quantum attacker can't forge a higher-sequence copy that pushes the
  real one out. Their backup leaves are random: a key used once never needs
  them.
* **Wire values:** identity class `0x11` Ed25519 (ECC) and `0x12`
  Ed25519 + Falcon (hybrid); KEM `0x03`. v1 values are rejected.

### Key bundle and identifiers

```
leaf(algo, pk) = BLAKE3-derive_key("tarnet key leaf v2", algo || pk)

bundle = version(u8)=2 || slot_count(u8) || slot*        slots in increasing algo order
slot   = algo(u8) || form(u8) || len(u16) || bytes
           form 0: bytes = the public key
           form 1: bytes = its leaf (32 B), the key itself not revealed

SID     = BLAKE3-derive_key("tarnet sid v2",     version || slot_count || leaf_1 || … || leaf_n)
PeerId  = BLAKE3-derive_key("tarnet peer-id v2", version || slot_count || leaf_1 || … || leaf_n)
```

Algorithm ids: `0x01` Ed25519, `0x02` Falcon-512 (round-3 key encoding),
`0x03` ML-DSA-44, `0x04` SLH-DSA-SHA2-128s. Ids are never reused.

* **Hybrid identity:** commits to `{01, 02, 03, 04}` and reveals 01 and 02.
  A revealed bundle is about 1.0 KB: 36 + 901 + 2 × 36 + header.
* **ECC throwaway:** commits to `{01}` only. It is a different preimage, so
  it can never collide with a hybrid identity's SID.
* **PeerIds must be hybrid.**
* SIDs and PeerIds stay 32-byte hashes, so addresses look the same as today.

### Signatures and verification policy

```
signature = count(u8) || (algo(u8) || len(u16) || sig)*
signed message = the caller's domain-separated message (each use has its own label)
```

A signature is valid for an identity when:

1. the bundle hashes to the identity;
2. the bundle's committed set is one the current policy allows;
3. every algorithm the policy requires is revealed in the bundle and its
   signature verifies.

**Policy 1** (wire v10):

| Committed set | Required signatures |
|---|---|
| `{01, 02, 03, 04}` | Ed25519 **and** Falcon-512 |
| `{01}` (ECC throwaway) | Ed25519 |
| anything else | rejected |

**Changing algorithms later is a software release, not new identities:**

* If FN-DSA ends up with Falcon's key format, it is the same key under a
  new signing algorithm.
* If its key format differs, or Falcon has trouble, a release switches to
  "Ed25519 and ML-DSA-44". Identities then reveal slot 03 and keep their
  SIDs.
* If lattices fail, a release switches to SLH-DSA (slot 04). Its 7.8 KB
  signatures are an emergency cost.

Nothing helps if lattices and hash functions both fail.

## Handshakes

All sizes are for hybrid identities. "Bundle" means a revealed bundle
(about 1.0 KB); "sig" means a policy-1 signature (about 0.73 KB).

### Link

v1 used about 12 KB: an ephemeral X25519 DH, encapsulations to the
responder's static and ephemeral KEM keys, and signatures. Whether a link
got PQ depended on the responder's advertised scheme, and session keys came
from the shared secret alone.

v2 has SIGMA-I shape with a single ephemeral KEM. Message types: 1 is
`HandshakeHello`, 2 and 3 are `HandshakeAuth` (one layout per direction),
4 is `HandshakeConfirm`.

```
1. I → R   Hello:    min(u8) || max(u8) || nonce_i(32) || len(u16) || eph_pk_i
2. R → I   Auth:     version || min || max || nonce_r(32) || len(u16) || ct
                     || len(u16) || seal(hs_r, th1; bundle_r, sig_r)
3. I → R   Auth:     len(u16) || seal(hs_i, th2; bundle_i, sig_i)
4. R → I   Confirm:  derive_key("tarnet link confirm responder", session)

ss      = combined KEM to eph_pk_i
th1     = derive_key("tarnet link v2 th1", len||msg1 payload || len||msg2 up to the sealed part)
hs_r    = derive_key("tarnet link v2 handshake responder", ss || th1)
hs_i    = derive_key("tarnet link v2 handshake initiator", ss || th1)
seal    = XChaCha20-Poly1305, zero nonce (each key used once), AAD = the th
          over len(u16)||bundle||len(u16)||sig
sig_r   over "tarnet link responder v2" || th1 || BLAKE3(bundle_r)
th2     = derive_key("tarnet link v2 th2", th1 || len||bundle_r || len||sig_r)
sig_i   over "tarnet link initiator v2" || th2 || BLAKE3(bundle_i)
th3     = derive_key("tarnet link v2 th3", th2 || len||bundle_i || len||sig_i)
session = derive_key("tarnet link v2 session", ss || th3)
keys    = kdf(session, "tarnet link i2r_enc" / "tarnet link r2i_enc")
```

* **Loss and retransmits:** the lockstep retransmit rules are unchanged (the
  initiator resends on timeout, either side answers a stale message by
  resending). A responder that is already linked answers a repeated message
  3 with its Confirm.

* **Forward secrecy:** comes from the ephemeral KEM alone. The static KEM
  added nothing that the signatures don't already provide.
* **Identities stay hidden:**
  * Both identities travel encrypted, so passive observers learn neither.
  * The initiator reveals its identity only after authenticating the
    responder.
  * The responder's identity is visible to an active attacker, which is
    unavoidable for the side that speaks first.
* **Pinning:** when it knows the PeerId it expects (bootstrap, mainline,
  mDNS, dialling a known peer), the initiator aborts if `bundle_r` doesn't
  hash to it. Today those paths connect with `expected_peer = None`.
* **Size:** about 1.3 + 2.9 + 1.8 ≈ 6 KB, half of v1's. That matters on
  slow radio links.
* **Both sides refuse a peer whose bundle isn't hybrid**: nodes must be.
* The version range goes into `th1`, as today, so the version can't be
  downgraded.

### Link rekey

v1 computed `new = derive_key("tarnet rekey", kem_ss)`. The previous
secret wasn't mixed in, the algorithm was the weaker of the two identities'
schemes, and the signature covered only `algo || pk || ct`.

```
Rekey = epoch(u64) || kem_algo(u8) || len||kem_pubkey || len||kem_ct || len||sig
        request: the key, empty ct; reply: empty key, the ct
sig over "tarnet link rekey v2" || th3 || epoch || kem_algo || len32||pk || len32||ct
binding = derive_key("tarnet link v2 rekey binding",
                     th3 || epoch || len32||pk || len32||ct)
new     = derive_key("tarnet link v2 rekey", chain || kem_ss || binding)
chain   = the session secret, then each rekey's `new`
```

* `epoch` is the key epoch the exchange installs. The responder refuses a
  request for anything but its current epoch + 1.

* Rekeys are always hybrid. `negotiate_rekey` is deleted.
* **Mixing in the previous secret means** an attacker who compromises only
  the rekey's ephemeral key learns nothing.
* **The signatures mean** an attacker who holds only the session keys can't
  take over the rekey and cut the real peer out.

### Circuits

The structure is unchanged ([routing](routing.md), "Onion circuits").

* CREATE's `kem_algo` must be the combined KEM (`0x03`); anything else gets
  DESTROY. In v1 the client used its own identity's KEM for every hop, so a
  classic client built classical circuits.
* CREATED carries the hop's bundle instead of its signing key, and a
  policy-1 signature over the same transcript. The client refuses a CREATED
  from a non-hybrid node.
* Hop keys are unchanged: `KDF(kem_secret, H(transcript))`.
* **Multi-cell relay messages survive loss.** Client authentication made
  STREAM_BEGIN about four cells, and in v1 losing any one piece dropped the
  whole message.
  * Every piece now carries a 4-byte `msg_id` that hashes the message
    (`derive_key("tarnet relay message id v1", command || stream_id ||
    data)`), so retransmissions share it.
  * The receiver keeps pieces by index until the message completes, then
    checks the id against the assembled bytes.
  * Pieces: first is `total_len(u16) || msg_id(4) || bytes`, continuation is
    `index(u8) || msg_id(4) || bytes`.
  * Bounds: 4 partial messages per circuit direction. The last 8
    completed ids are remembered: a whole retransmission of one is delivered
    again (its sender retries because the answer was lost, and every
    multi-cell handler answers a repeat idempotently), but stray late pieces
    of one are evicted first when room is needed.
  * At 50% loss, a four-cell message needs about two retransmissions instead
    of sixteen tries.

### Tunnels

* The KEM is always the combined one.
* Keys come from `KDF(ss, H(offer || response))`. Today they come from `ss`
  alone, and the transcript is bound only through the signatures.
* Tunnels rekey like links (see "Key lifetime"). Today they never rekey.

### Key lifetime

Status: **implemented** for links, tunnels and circuits.

In v1:

* Links rekeyed only after 65536 frames, and were never closed for
  idleness, so a quiet link could keep one key for weeks.
* Tunnels never rekeyed.
* Circuits and end-to-end connections never rekeyed and had no maximum
  age.

v2 has two rules:

1. **No traffic key outlives its epoch: a symmetric ratchet.**

   ```
   epoch       = counter >> 16
   key_{e + 1} = BLAKE3-derive_key("tarnet epoch v2", key_e)
   ```

   * The epoch comes from the counter each message already carries, so loss
     and reordering work unchanged.
   * The receiver keeps the previous epoch's key only while its reorder
     window still covers that epoch, then deletes it.
   * A receiver advances at most 4 epochs for one message. Counters are
     authenticated only after decryption, so a forged huge counter costs no
     hashing.
   * Applies to links, tunnels and every circuit layer where a cell is
     sealed or opened (cell crypto version 2): the end keystream and the tag
     key come from `derive_key("tarnet onion v2 end stream" / "... end
     mac", key_e)`. Only the two ends of a direction see its plain counter.
     The initiator counts per hop, so heavy traffic to one hop never pushes
     a rarely addressed one past the 4-epoch jump.
   * A layer's pass-through keystream and its trailer permutation don't
     ratchet. A relay passing a cell on sees only a transformed trailer, and
     can't count cells itself because cells may be lost. Those keys only
     protect against linking; content is under the end layer.

2. **No session goes more than an hour without a fresh KEM.**
   * **Links:** rekey (always hybrid, previous secret mixed in, signed) after
     65536 frames **or** one hour, whichever comes first. The link
     initiator drives it.
   * **Tunnels:** the side that ran the key exchange runs a fresh one after
     65536 messages or an hour (a 60 s sweep). The new tunnel keeps the old
     one's receive keys, so messages already in flight still decrypt.
   * **Circuits:** the initiator rekeys the innermost layer (the
     destination's hop layer, or the end-to-end layer of a rendezvous) once
     an hour with one KEM exchange inside the current layer, about 1.2 KB
     each way, instead of a KEM per hop:

     ```
     LAYER_REKEY   (relay cell 0x16)  generation(u32) || ephemeral KEM key
     LAYER_REKEYED (relay cell 0x17)  generation(u32) || KEM ciphertext
     transcript_g = derive_key("tarnet layer rekey transcript v2",
                      transcript_{g-1} || g || len || pk || len || ct)
     keys_g       = HopKey(kem_secret, transcript_g)
     ```

     `transcript_0` is the layer's CREATE or rendezvous transcript. The old
     layer authenticates both messages. The initiator retries one
     generation with the same KEM key until it gets an answer (across
     sweeps if need be), and the responder answers a repeat with the same
     ciphertext, so the two chains never diverge. The initiator switches as
     soon as it has the answer and sends a cell under the new keys. The
     responder switches its sending side only when the first cell under the
     new keys arrives, so neither end seals under keys the other can't open
     yet. Both keep the old receive keys for 120 s after the switch, for
     cells already in flight.
   * The hour is measured on each node's own monotonic clock, and nothing is
     compared between nodes.

Not done:

* **A per-message (Double Ratchet style) asymmetric ratchet.** It is built
  for asynchronous messaging, and a PQ step per message is impossible on
  radio links.
* **A maximum circuit age.** It would cut live connections.

The messenger's group key schedule (MLS-style or sender keys, with PQ steps
spread over messages as in Signal's SPQR) belongs to the messenger design,
not the transport.

### Hidden services

* **INTRODUCE:** its AEAD AAD is `"tarnet introduce v2" || service_id ||
  kem_ct` (empty in v1). `ext` is consumed by the intro point and never
  reaches the service, so it can't be bound for the service. INTRODUCE is
  sealed to the identity's current static KEM key (generation `n`).
* **Rendezvous:** the client's ephemeral key is always the combined KEM. In
  v1 a classic client got no PQ forward secrecy.
* IntroRegister, Peer records and intro records carry bundles and policy-1
  signatures.

### Client authentication

The first message to reach the host carries the client's proof:

* direct circuits: `StreamBegin`;
* hidden services: `RendezvousReady`.

```
StreamBegin (relay cell 0x03)
  service_id(32) || mode(u8) || port_len(u16) || port || client_auth
RendezvousReady (relay cell 0x12)
  client_auth                                     (empty in v1)

client_auth = len(u16) || bundle || len(u16) || signature
signed: "tarnet client auth v2" || binding(32) || target_sid(32) || mode(u8)
        || hash_port_name(port)(32)
```

Both messages span several cells, which the loss-tolerant multi-cell
assembly makes affordable (see "Circuits").

* **`binding`:** the destination waypoint's CREATED transcript on direct
  circuits, or the hash the rendezvous end-to-end key is derived from. A
  proof can't be replayed onto another circuit or presented to another host.
* **Mandatory:** a missing or invalid proof gets `StreamRefused`. There is
  no unauthenticated mode, because an opt-in would split every application
  into two code paths.
* **The host gets** `Connection.remote_service_id`, the verified client SID.
  In v1 it held the host's own SID.
* **Which SID:** the node's default identity, unless the caller names one
  (`connect_as`, or a throwaway).
* **Retransmits:** a repeat `StreamBegin` on a circuit that already has a
  stream gets `StreamConnected` again and is not verified twice.
* **Hidden services** hand a connection to the listener only after
  `RendezvousReady` verifies, then answer `StreamConnected` (`StreamRefused`
  on a bad proof). In v1 they handed it over first.
* **Size:** about 1.75 KB hybrid (4 cells) or 100 B ECC, once per connection.
* **Privacy:** the proof is inside the end-to-end layer, so relays and
  rendezvous points never see it.
* **Not deniable, on purpose.** The host holds a signature showing that
  the SID connected. Throwaways are the deniability mechanism. A deniable
  KEM-based option can be added later under a new algorithm id.

## Throwaway identities

A throwaway is a full identity that lives only in daemon memory and belongs
to one IPC client. Like Tor's ephemeral `ADD_ONION` services, it can serve on
a fresh SID until its owner goes away. The CLI front end (`tarnet expose
--ephemeral`) isn't written yet; the API below is.

```rust
let sid = api.create_ephemeral_identity(EphemeralOptions {
    privacy: PrivacyLevel::Hidden { intro_points: 3 },  // the default
    outbound_hops: 3,
    scheme: IdentityScheme::FalconEd25519,              // or Ed25519
}).await?;
api.connect_as(target, mode, port, Some(sid)).await?;
api.listen_hidden(sid, mode, port, 3, options).await?;
api.drop_ephemeral_identity(sid).await?;  // also when the owning client disconnects
```

| | Throwaway |
|---|---|
| Privacy | Hidden (default) or Public |
| `connect_as` | ✓. Hidden: `outbound_hops ≥ 3` enforced. Public: caller's hops, default 1 |
| Listen | ✓ |
| `peer` / `intro` TNS labels | ✓, managed by the system, never persisted |
| TNS labels set by applications | ✗. Names are for things that last; use a pseudonym |
| `dht_put_signed`, pools | ✓, memory only |
| Visible to and usable by | its owning IPC client only |
| Lifetime | until dropped, its owner disconnects, or the daemon restarts |

* **ECC throwaways** (`{01}`, Ed25519) skip Falcon key generation.
  * Their session confidentiality is still PQ (see the key agreement
    rules), and so is INTRODUCE to them: every identity's static KEM is
    hybrid.
  * Only their *authentication* is classical: a quantum attacker could
    impersonate them while a connection is live. That matters little for an
    identity nobody trusts yet.
* **Public is allowed, never the default.** It covers "I just want a fresh
  identity". Its `peer` record (SID → PeerId) outlives the throwaway by up
  to the label TTL (10 min).
* **On drop:**
  * connections and listeners close at once;
  * timers stop (intro and label refresh, pool lease, republish);
  * intro points are torn down;
  * its DHT records stop counting as the node's own;
  * keys are zeroized;
  * later attempts to reach it are refused exactly as for a SID the node
    doesn't host.
* **Already published data runs out its TTL.** The DHT never deletes. No
  tombstone is published on drop, because it would mark the moment of death.
* **Key generation:** the daemon keeps a small in-memory pool of generated
  hybrid key sets (two), refilled in the background, so creation returns
  instantly.
* **Republishing:** the node republishes signed content for its persistent
  Public identities. It doesn't for throwaways or Hidden identities: the
  re-PUTs on link-up would link them to the host. Their owners republish.
* **Creation rules:** persistent identities must be hybrid, and labels
  starting with `~` are reserved for throwaways (`~` followed by the first
  12 characters of the SID). Throwaways can't be updated or deleted, only
  dropped.
* **Not covered:** throwaways created or used together by one node can be
  linked by timing.

## Persistence invariants

Identity-bound state lives in six tables (`identities`, `tns_labels`,
`tns_records`, `tns_tombstones`, `pools`, `dht_records`), and owners
republish their own records. For throwaways and deleted identities alike:

1. **Nothing tied to an ephemeral identity reaches disk.**
   * **Identity-bound writes:** they go through `Node::db_for(&sid)`, which
     gives no database for a throwaway. That is the path in-memory nodes
     already take. The tombstone write uses it; app labels are refused
     outright.
   * **DHT records:** publishing them for an identity goes through
     `note_owned_records(owner, records)`. For a throwaway it marks them
     memory-only in the store, which never mirrors them to SQLite, and
     remembers them for the drop. A TNS lane's signer is a digest, so the
     publish path names the owner instead of the store guessing.
   * **Publication sequences:** a throwaway's are kept in memory. The
     node-wide counter is persisted, so its writes alone would record that
     a throwaway was active. The tests caught exactly that.
   * Throwaways aren't exported or written to `identities`.
2. **Dropping a throwaway and deleting an identity share one teardown
   path** (`remove_identity`). It removes:
   * its hidden service, listeners and zone working set;
   * its cached resolutions;
   * its own DHT records and its sequence counter;
   * its row, labels and tombstones;
   * its keys, erased on drop.

   v1's `delete_identity` removed only the row and the hidden service.
3. **The startup sweep removes orphaned rows** (`StateDb::sweep_orphans`,
   run before the DHT store loads). It deletes:
   * label rows not filed under a live identity's SID (or `""`, the
     default);
   * tombstones of dead SIDs;
   * the node's own SignedContent, ZoneKey and Hello rows whose signer is
     neither the node key nor a live identity.

   The node's own TNS-lane and pool-claim rows have digest or disposable
   signers and expire within minutes; the store drops expired rows at load.
4. **Labels are filed under the identity's base32 SID**, never its name
   (`""` still files the default's). In v1 a new identity reusing a deleted
   one's name inherited and published its labels.
5. **Tests** (`src/node/identity_mgmt.rs`, `lifecycle_tests`):
   * `assert_no_trace` checks the store, listeners, zone working set,
     intros, the node's own DHT records, republish set and every table, for
     a deleted identity, a dropped throwaway, after a restart, and after the
     sweep.
   * A throwaway in use writes no row to any table.
   * A schema registry test fails when a table appears that the sweep and
     `assert_no_trace` don't know.

## Application API

No wire change.

* **Daemon socket.**
  * The socket's directory is 0700 and the socket 0600.
  * On accept, the peer's uid must equal the daemon's (`getpeereid`,
    `SO_PEERCRED`).
  * This separates applications run by one user from each other. It is not
    a boundary against a hostile process running as the same uid.
* **Events reach only the client that asked.**
  * Watches are reference-counted per client; a disconnect releases them.
  * Raw `Data`/`Tunnel` events need `subscribe_raw` (`METHOD_SUBSCRIBE_RAW`;
    the client library sends it from `subscribe_events`).
  * In v1 every client was sent every event, and one client's `dht_unwatch`
    cancelled the watch for all of them.
* **`connect_as` over IPC passes the source identity through**
  (`METHOD_CONNECT_AS`). In v1 it was dropped.
* **Throwaways belong to the client that created them.** Other clients
  don't see them in `list_identities`, and can't connect, listen, sign or
  put as them. They are dropped when their client disconnects.
* **IPC protocol version 6**, which adds methods `0x0030`–`0x0038`.
* **Signing as an identity.**
  * `identity_sign(sid, context, msg)` signs `"tarnet app sig v2" ||
    len(context)(u16) || context || msg` under policy 1.
  * The prefix keeps applications from obtaining signatures that verify as
    daemon messages. **A raw signing call is not allowed.**
  * Verification needs no secret: it's `identity_verify` over IPC, or
    `tarnet::node::verify_app_signature` in-process. It isn't in
    `tarnet-api`, which carries no signature crates.
  * `identity_kem_decap(sid, ct, context)` returns a secret already passed
    through a KDF bound to the context.
* **`dht_put_signed`** signs as the default identity, and
  `dht_put_signed_as` as a chosen one. In v1 it signed with the node's
  PeerId key, which tied every signed put to the host.

## Removed

* `KemAlgo::negotiate_rekey` and every choice of session KEM made from
  an identity's scheme.
* Ed25519-only (`0x01`) persistent identities and PeerIds.
* The v1 seed migration (`crates/tarnetd/src/main.rs:779`), the deprecated
  `Keypair::from_bytes`, and the fallback that builds a classic keypair from
  an identity it failed to parse (`src/node/mod.rs:699`).
* Deriving the static X25519 key from the Ed25519 signing seed.
* The full key derivation for every pool publish. The outer signer stays
  hybrid, so that a quantum attacker can't forge a higher-sequence copy
  that pushes the real one out, but a disposable key skips the backup keys.
* Dead code: the `pubkey_cache` KEM placeholder and the unused X25519
  helpers in `src/identity.rs`.

## Compatibility and rollout

* **Wire version 10, a hard break.** Every SID and PeerId changes. Routing
  tables, directory records, TNS zones, peer records and petnames start
  over, and every node needs the new build, relays included. There is no
  import from v1 identities.
* **DHT record encoding changes.** `signer_algo || pk_len || signer_pubkey`
  and the signature field become `bundle` and a policy signature. Walks,
  placement, admission and the local policy are untouched.
* **TNS:** the blinded envelope stays Ed25519-only by design. A quantum
  attacker could flood a label location but not forge its contents. The
  blinding factor hashes the bundle instead of the raw key. ZoneKey
  descriptors and inner bundles carry bundles.
* People who saved SIDs (TNS delegations, `tns set … zone …`) re-enter them.
* **The daemon refuses to start on v1 identities,** whether in the identity
  file or `state.db`. It explains why rather than converting them, so the
  data directory has to be moved aside.
* **Tests** added with the change:
  * bundle canonical-form and policy tests;
  * identity derivation, storage and refusal tests;
  * KEM combiner tests;
  * v2 handshake tests: an ECC peer refused in both roles, PeerId pinning,
    low-order X25519 refused, loss cases;
  * rekey chaining and age tests;
  * tunnel transcript, overlap and rekey tests;
  * client-auth binding tests;
  * multi-cell gap-filling tests;
  * IPC scoping tests;
  * persistence lifecycle tests;
  * e2e: an ECC node refused, the host seeing the client's SID (direct and
    hidden), a throwaway as client, a Hidden throwaway serving until
    dropped, identity-signed DHT records across nodes.
* **Slow links** (local policy, no wire change). Making the firewall tests
  pass reliably needed changes that also matter on HC-12 and ESP-NOW. The
  slow-link test failed on v1 too.
  * **Background preemption:** a background message (a 2 KB DHT record)
    no longer holds the line for its whole airtime. Foreground messages
    alternate with its fragments, and fragments still queued aren't resent
    on NACK.
  * **Sparse flows:** a flow is sparse by the bytes it sent lately, so a
    window-limited bulk stream no longer counts as interactive whenever its
    queue empties.
  * **Retransmission timeout:** after a timeout, the backed-off RTO holds
    for new packets until a valid sample (RFC 6298 5.5–5.7). Without that, a
    path slower than the initial RTO retransmitted every packet and never
    got a sample.
  * **Timestamp echo (wire):** stream DATA carries the sender's own
    millisecond clock, `seq(u32) || timestamp(u16) || kind || body`, and
    StreamAck may end with `echo(u16)`, the timestamp of the last DATA
    received since the previous ACK. Every echo is a valid RTT sample, even
    for a retransmission. Under heavy random loss most delivered packets
    were retransmitted, so Karn's rule gave no samples and the backed-off
    floor made every new packet wait 8 s (10 messages at 50% loss took up to
    37 s; now 1–8 s). Only the sender's own clock is compared, so this is
    clock-free.
  * **ACKs ride on data (wire):** an ACK owed when a small DATA packet goes
    out travels in the same cell (`StreamDataAck`, relay cell 0x18), and a
    due ACK waits for a DATA packet that is ready to go with room for it. An
    interactive reply then acknowledges what it answers: on a 2 KB/s line,
    bulk next to an interactive session went from about 5 KB to 9–10 KB in
    the test, and the worst keystroke round trip from 0.8 s to 0.68 s.
  * **Frame size kept at 256 B:** frames sized to split a cell evenly
    (three of 207 B) cut an isolated cell's airtime by a fifth but lost
    about 20% of bulk throughput. With 256 B frames the next cell starts in
    the room a cell's last fragment leaves.
  * **CREATED replay:** a node answers a resent CREATE with the cached
    CREATED only once the previous copy has had twice its airtime to arrive.
    The sender times resends by its own link, and on a slow uplink of ours
    the ~3 KB post-quantum CREATED takes seconds: five queued copies held a
    2 KB/s line for 9 s.
  * **ACKs:** an ACK identical to one sent within a round trip is
    suppressed, and the delayed ACK (25 ms) merges the receipt ACK with the
    window update.
  * **Stream setup:** stream setup retries back off to at most 4 s (or 4×
    the message's airtime), with 10 retries, matching the multi-cell setup
    message.

## v1 → v2

| Site | v1 | v2 |
|---|---|---|
| KEM implementation | Kyber768 round 3, labelled ML-KEM | FIPS 203 ML-KEM-768 |
| KEM combiner | `H(ss_X ‖ ss_K)` | X-Wing structure |
| Link handshake | PQ only if the responder is hybrid; keys from `ss` alone; ~12 KB | Always hybrid, SIGMA-I, keys from the transcript, ~6 KB |
| Link rekey | Weaker scheme of the pair; no chaining; volume only | Always hybrid; previous secret mixed in; transcript bound; hourly |
| Circuits | Client's own identity KEM on every hop | Always hybrid; CREATED from hybrid nodes only |
| Multi-cell relay messages | Lost piece drops the message | Retransmissions fill gaps |
| Tunnels | Initiator's KEM; keys from `ss` alone; never rekeyed | Always hybrid; transcript KDF; ratchet; rekeyed |
| INTRODUCE | Empty AAD | AAD binds SID and ciphertext |
| Rendezvous ephemeral | Client's identity KEM | Always hybrid |
| Client identity on connections | None (host saw its own SID) | Mandatory hybrid-signed proof |
| Identity → id | Hash of the full signing key | Hash of committed key leaves |
| Static X25519 | Derived from the Ed25519 seed | Its own seed label |
| Silent classic fallback | Yes | Hard error |
| Bootstrap pinning (mainline addresses) | Not pinned | Pinned |
| Signed DHT puts | Node key | Default or chosen identity |
| TNS label rows | Filed under name or SID | Under SID |
| Daemon socket | Any process that can open it; every event to every client | 0600 socket, same uid only; events scoped per client |
| TNS envelope | Ed25519, by design | Unchanged |

## Alternatives considered

* **Client auth by static-static X25519 MAC (CADET-style).** Deniable and
  needs no round trip, but classical. Rejected: PQ now.
* **Client auth by KEM-based implicit authentication.** Deniable, but about
  4 KB per connection, a third message, and an extra round trip for
  protocols where the server speaks first.
* **Optional client auth.** Rejected: two code paths in every application.
* **ML-DSA-44 as the active PQ signature.** Settled standard, but 3.7×
  Falcon's signature size on every CREATED, record and proof. Kept as the
  committed backup instead.
* **FN-DSA now.** FIPS 206 is not final, and betting on the draft risks a
  second break. Commitments make the bet unnecessary.
* **Storing only the seed.** Falcon key generation isn't fixed by a
  standard, so a library change could alter a re-derived key and the SID.
  The Falcon key is stored instead.
* **GNUnet CADET, for comparison.** It always authenticates the initiating
  *peer*, deniably (triple-DH followed by an Axolotl ratchet). It is never
  anonymous and doesn't authenticate application identities.

## Open

* **Key lifetime on circuits:** the epoch ratchet on every layer's
  sealing and opening, and an hourly end-to-end rekey of long-lived
  connections.
* **`tarnet expose --ephemeral`** and other CLI front ends for throwaways.
* **`slh-dsa` is pinned to a release candidate.** It is only a backup, but
  its key derivation must stay exactly as it is, because SIDs commit to its
  public key. Re-check against FIPS 205 vectors before relying on it.
* **Moving Falcon to FN-DSA** once FIPS 206 is final: same keys if the key
  format holds, otherwise a policy switch to ML-DSA.
* **A deniable client-auth algorithm,** if the messenger needs one.
