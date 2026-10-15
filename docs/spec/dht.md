# DHT protocol (v1)

Status: wire format frozen with this revision. Everything under "Local policy"
may change between releases without a compatibility break.

## Model

tarnet is a routing protocol with a DHT. The DHT follows R5N: each DHT hop is
one overlay link, so it works in graphs that are not fully connected (e.g.
machines joined only through relay boxes) and never pays a multi-link path for
a single DHT hop.

* **DHT neighbours** are the node's direct links. Each neighbour's DHT id is
  `dht_id_from_peer_id(peer)`; distance is XOR against the 64-byte key.
* **Storing vs relay-only nodes.** A node either stores DHT records for others
  (default) or is relay-only (`store = false`, e.g. a Pi Zero). A relay-only
  node forwards DHT messages but never stores, verifies or caches records for
  others. It still keeps its own published records.
* **Placement.** A record lives at the *ends of walks*: a storing node that is
  closer to the key than every one of its neighbours (a local minimum). Nodes on
  the way only forward. This bounds each node's share of the key space.

## Walks

Every PUT, GET and WATCH travels as one or more independent *walks*. A walk has
two phases.

1. **Random phase** (`WALKING` flag set). The originator always sends with
   `WALKING`. Every node receiving a walking message ends the random phase with
   probability *q*; otherwise it forwards to a uniformly random neighbour other
   than the sender, keeping `WALKING`. A node whose only neighbour is the sender
   always ends the random phase. A node that ends the random phase clears
   `WALKING`, sets the greedy budget, and continues in the greedy phase from
   itself.
2. **Greedy phase.** At node *X* with distance *dX* to the key:
   * If `DELIVER` is set: a storing *X* is the end of the walk. A relay-only *X*
     inserts itself into the bloom and forwards (keeping `DELIVER`) to its
     closest neighbour that is believed to store and is not in the bloom, else
     to its closest neighbour not in the bloom, else drops.
   * Otherwise, if some neighbour is strictly closer than *dX*: forward to the
     closest one.
   * Otherwise *X* is a local minimum. A storing *X* is the end of the walk. A
     relay-only *X* inserts itself into the bloom, sets `DELIVER`, and forwards
     to its closest neighbour believed to store (else its closest neighbour).
   * Every greedy forward decrements `greedy_budget`; a message arriving with
     budget 0 ends where it is (stored there if that node stores, else dropped).

Greedy steps strictly decrease distance, so they cannot loop. The bloom is only
needed for the `DELIVER` detour around relay-only nodes, and only those nodes
are ever inserted. No originator, random-walk node, or greedy node appears in it.

## What each message does at the end of a walk

* **PUT**: the end node verifies and stores the record. Nodes on the way do not
  verify, store or deduplicate; each hop forwards to exactly one neighbour.
* **GET**: every node on the walk that holds records for the key answers along
  the reverse path (`query_token` → previous hop, as before). The walk continues
  to its end regardless, also when it passes a node a second time (in its
  random phase, or right after it): that visit is not answered again, and
  responses keep following the first visit's previous hop, so they travel a
  tree rooted at the originator and can't loop. A node forwards at most a few
  visits of one walk. Each walk has its own `query_token`. Every node on the
  walk keeps the key with the token and drops a `DhtGetResponse` whose key
  differs, or that doesn't come from a neighbour the walk was passed to.
  Results go to the lookup that asked; no node stores what it fetched (the
  store holds what PUT walks placed there, and the node's own records).
* **WATCH**: every node on the walk registers `(key, query_token, previous hop,
  expiry)`; a node that already holds the token drops the duplicate visit. When
  such a node stores, publishes or forwards a PUT for the key it sends
  `DhtWatchNotify` to the previous hop, which relays it back hop by hop using its
  own registration for that token. Relays of a notification do not verify it;
  the watcher does. The node that originates a notification verifies the PUT
  first: it notifies each watcher only of news (a record version it hasn't
  told that watcher of), and a forged PUT claiming someone's signer with a
  huge sequence would otherwise mark their real records as already told. A
  record version is identified by its signer and sequence.

## Wire format

All multi-byte integers are big-endian.

Walk header, shared by PUT, GET and WATCH:

```
dht_version(u8) = 1
flags(u8)            bit0 WALKING, bit1 DELIVER; other bits reserved:
                     sent as 0, ignored on receipt
greedy_budget(u8)    meaningful only once WALKING is clear
bloom_salt(u32)      chosen by whoever first inserts into the bloom
bloom(256)           2048-bit filter, k = 4,
                     index_i = u16(H("tarnet dht bloom v1" || salt || peer)[2i..2i+2]) mod 2048
```

Messages:

```
DhtPut         (0x0200)  walk_header || record
DhtGet         (0x0201)  walk_header || key(64) || query_token(32)
DhtGetResponse (0x0202)  query_token(32) || key(64) || count(u16) || records
DhtWatch       (0x0203)  walk_header || key(64) || query_token(32) || expiration_secs(u32)
DhtWatchNotify (0x0204)  query_token(32) || record                               (DhtPut minus the walk header)
DhtNeighbor    (0x0205)  dht_version(u8) || flags(u8)   bit0 STORES; sent on link-up by relay-only nodes
```

`record` is the unchanged signed record encoding: `key(64) || record_type(u8) ||
sequence(u64) || signer(32) || ttl(u32) || value_len(u16) || value ||
sig_len(u16) || signature || signer_algo(u8) || pk_len(u16) || signer_pubkey`.
`ttl` is the lifetime left, in seconds; it is not signed (see below).

Messages with an unknown `dht_version` are dropped. There is no hop counter,
originator-set hop limit, or replication count on the wire: a neighbour cannot
tell from a walking message whether the sender started it.

A neighbour that sends no `DhtNeighbor` message is assumed to store. A false
claim only sends a `DELIVER` detour one hop further.

Unknown record types are signature-checked generically (signer key, algorithm,
signature over `"tarnet dht record v1" || key || type || sequence || value`) and kept newest-per-signer
under the usual per-key and global caps, so future record types pass through
older storing nodes. Only `Content` is unsigned, and it is self-certifying
instead (below).

### Content: content-hash keys

Unsigned content uses content-hash keys, as Freenet's CHKs do. The plaintext
is encrypted under a key derived from it (`enc_key = BLAKE3-derive("tarnet
content v2 encryption key", plaintext)`, with a nonce derived from `enc_key`),
giving a blob that is a pure function of the plaintext. The reader's 64-byte
**handle** is `enc_key(32) || chk(32)`, where `chk = BLAKE3(blob)`, and the DHT
key is `H64("tarnet content key v2" || chk)`.

A storing node sees only the blob, but recomputes its key from it, and drops a
content record stored anywhere else. Exactly one blob is valid per key, so
there are no competing candidates for junk to crowd out, and content needs no
special case anywhere: it is kept, deduplicated and expired like any other
record, one version per (key, signer), its signer being zero. A reader checks
`chk` against the blob, decrypts with `enc_key`, and checks `enc_key` against
the plaintext. The same plaintext always gives the same handle (convergent),
so honest copies from different publishers are identical.

`SignedContent` at a content key wraps the same blob, encrypted under the DHT
key and signed; different signers keep separate records.

Lifetimes are clock-free (see "Clock-free" in the routing spec): every hop
carries the TTL left, clamped to the type's cap, and each node counts it down
on its own monotonic clock. The TTL can't be signed, so the store guards the
lifetime instead:

* A record arriving with the sequence already held (a republish, or anyone
  replaying it) changes nothing: the copy held keeps its deadline. Only a
  higher sequence, which only the owner can sign, brings a new lifetime.
* A record that expired at a node is not stored there again unless its
  sequence is higher. The node remembers this for the TTL cap after the
  latest such expiry, the longest any copy could claim to live, in a table
  bounded like the store. Unsigned content is the exception: it has no
  sequence its owner could raise, so remembering it would refuse its
  republish, and a replay can only bring back the one immutable blob its key
  admits.

A replay can still seed a node that never held the record, for at most the
type's cap. Owners end a record early by publishing a higher sequence.

A node that persists records keeps its database a mirror of the store: the
store writes every change to it itself, in the same step, so a record is
written only while the store holds it, together with who handed it over (this
node, or which link peer), records the caps evict or that expire lose their
rows, and on start-up rows the caps no longer admit are deleted. A node's own
records are never evicted for others' (nothing would put them back), and a
relay-only node drops the replicas it held when it was storing. The store caps
therefore bound the database too, and a restarted node republishes only the
records it published itself, never replicas it held for others. The table is
a cache owners refill: a layout change drops it rather than migrating it.

The byte caps count each record's full wire encoding (signer key and
signature included) plus a fixed bookkeeping overhead, computed once when the
record is stored.

### Admission

Every DHT message pays its sender's budget at one gate before its handler
runs: `DhtGet` and `DhtWatch` (cancellations included) a query, `DhtPut`,
`DhtWatchNotify` and `DhtGetResponse` their records and bytes, `DhtNeighbor`
nothing. A DHT message type without a declared charge is refused.

Reverse-path state (one entry per GET walk passing through or leaving a node,
30 s) is capped at 65,536 entries for relayed and locally launched GETs
alike; the table refuses entries past the cap itself. A lookup launched while
it is full sends only the walks that fit, possibly none.

`DhtNeighbor` is a link message rather than a handshake field so the handshake
transcript is untouched; it travels on the already-authenticated link.

A TNS zone root is one signed record holding every label of the zone, so it
has one lifetime (`ZONE_ROOT_TTL`, 10 min): the node re-signs it, with all its
labels, on one timer per identity (the peer-record refresh for Public
identities, the intro refresh for Hidden ones), never once per label.

A content handle (`ContentHandle`) is a reader's capability, not a DHT
location: its location is derived from it (`content_key`), and its first half
is a secret, so it is never logged.

## Local policy (not part of the wire contract)

| Parameter | Value |
|---|---|
| Random-phase end probability *q* | 1/3 |
| Greedy budget | 32 |
| Walks per PUT and per GET round, ρ | `max(2, ceil(sqrt(3 · N / (d + 1))))`, capped at 32 |
| N (network size) | routing-table destinations + 1 while the table is a complete view, else landmarks × budget (see the routing spec) |
| d | number of direct links |
| GET rounds | a search launches ρ fresh walks every 1.5 s, 3 rounds in total (keys can hold several records); dropping the search stops it |
| Originator walks | spread over distinct random neighbours, cycling if ρ > d |
| Republish | owners republish their own records: hello every 5 min; a zone root (all of a zone's TNS labels) every 4 min for a Public identity, with each intro refresh (every 200–300 s) for a Hidden one; records signed by the node's own key every 30 min. Records signed by any other key are republished only by their owners' timers. Hello + own records republished and watches relaunched 1–3 s after links come or go, at most once per 60 s: changes inside that window are folded into one republish at its end |
| Watches | the watcher relaunches its watch walks every 60 s until the requested expiry, each walk registering for 120 s; unwatch only drops local state, registrations along old walks expire. The app hears of each record version once, and never of one older than it was told |
| Store caps | 4096 records / 16 MB (full encoded size), fair-share eviction by source, TTL caps |
| DHT budget | per link: 256 queries (GET, WATCH) per window, plus the phase 1 ingest budget for records |

ρ follows R5N: with about N/(d+1) local minima per key, ρ PUT walks and ρ GET
walks meet with probability ≈ 1 − e^(−ρ²(d+1)/N). The factor 3 targets ≈ 95%
per round; relaunches make misses independent.

Removed relative to the previous protocol: flooding (fan-out 20), storing at
every hop, the 5-minute replication sweep, the full-store sync on link-up, the
L2NSE estimate from the k-bucket, and `hop_count`/`hop_limit`.

## Privacy notes

* A walking message carries nothing tied to its originator. A neighbour still
  sees timing and volume (ρ walks for one key leaving one node together).
* Each hop knows its predecessor and successor. Hidden identities need DHT
  operations carried over a circuit (planned; no change to this format).
* Only relay-only nodes on a `DELIVER` detour enter the bloom.
