# Routing protocol (v2, draft)

Status: **draft, mostly implemented**. Not yet: per-transport link-death
timing and Hidden-identity lookups over circuits. Replaces the routing part of wire
v4 (`RouteAdvertisement`, `RouteProbe`, `RouteProbeFound`) and changes link
framing, `Data` and circuit `EXTEND`. Ships as wire version 7, a hard break
(`WIRE_VERSION_MIN = WIRE_VERSION_MAX = 7`); after it the wire is frozen or
extensible. Everything under "Local policy" may change between releases
without a compatibility break. Open decisions are collected at the end.

## Goals

1. **Reach any node a physical path exists to**, in one flat address space
   shared by everyone (no private overlays). Reaching your own machines from
   anywhere by running a daemon and loading your SID is the reference use case.
2. **Bounded per-node cost.** Routing state grows like √N. Steady-state routing
   traffic on a link depends on churn, not on network size.
3. **Light enough for the slowest link class**: about 500 B/s to 1 KB/s, lossy,
   half-duplex (HC-12-class radio). Idle background traffic must leave most of
   that free. The radio driver and its framing are a future transport; this
   spec only makes the protocol fit the budget.
4. **Partition tolerance.** An island cut off from the rest of the network keeps
   routing and resolving names internally.
5. **Keep the privacy properties of v4** (listed under "Privacy"), and keep the
   design stances: unauthenticated relays, public by default, privacy opt-in via
   Hidden identities.
6. **Clock-free.** Nothing depends on nodes' clocks agreeing; see below.

## Clock-free

Decision (2026-10): tarnet does not trust clocks. Relays include boards with no
real-time clock on links that may never reach a time server, and serving time
over the overlay was rejected as an extra dependency. So:

* No message carries a wall-clock time that another node checks. The link
  handshake and the tunnel key exchange carry no timestamps; their freshness
  comes from both sides' fresh ephemeral keys and random challenges or nonces,
  bound into what is signed. Keepalive pings carry a random id, not a time
  (which would also fingerprint the sender's clock).
* Lifetimes are relative: a record carries the TTL it has left and each node
  counts it down on its own monotonic clock. Since a TTL can't be signed
  meaningfully, stores never let a copy extend a record they hold, and never
  store again a record that expired with them unless its owner signed a higher
  sequence (DHT records and directory address records alike).
* Sequences are counters persisted by their owner, never times.
* A node's own wall clock is used only locally and fails safe: persisted DHT
  records are dropped at start-up if the clock reads earlier than when they
  were written.

## Use cases the design is checked against

* **Remote access.** A daemon started anywhere on the internet resolves a SID
  (DHT/TNS) to the hosting node, resolves the node to an address, builds a
  circuit and authenticates at the service.
* **School network down, another uplink exists.** Links through the school die;
  the cluster re-routes over the other uplink. A *new* connection attempt made
  after link-death detection must succeed well inside Linux's TCP connect
  timeout (~127 s). Existing connections may die.
* **Island.** The cluster is cut off and you are on it with cables. Routing,
  name resolution and connections work inside the island.

## Layering

```
lookup       landmarks + address directory   node ID → address (landmark, path)
routing      Babel-style distance vector     next hop toward: local area + all landmarks
forwarding   Data / circuit EXTEND           destination known? → furthest known hint
link         frames, coalescing, crypto      fixed frame size per link
transport    TCP / WS / WebRTC / (future serial radio)
```

Routing still moves every packet hop by hop over direct links. Landmarks and
the directory only answer "where is x". The DHT (see `dht.md`) is unchanged
apart from the local-policy changes listed below; it stores records, not routes.

**Small networks run without landmarks.** While every node's table holds every
destination (N ≤ `B_MIN`), no landmark is elected, no address is published and
forwarding behaves like v4. Everything below the routing section only switches
on once the network outgrows `B_MIN`. Tests force it on by lowering `B_MIN`.

## Link framing

The link handshake is unchanged (see "Link handshake" below). The frame
encryption drops its random nonce, and the plaintext inside a frame becomes a
sequence of records instead of one padded wire message.

### Frame encryption

```
v4: nonce(24, random) || AEAD(seq(8) || payload) || tag(16)
v5: seq(u64)          || AEAD(payload)            || tag(16)
    XChaCha20-Poly1305, nonce = 16 zero bytes || seq, AD = seq
```

* Saves 24 B per frame, about 10% of a 256 B slow-link frame.
* Safe because a `(key, seq)` pair is never reused. Each direction has its own
  key, and `seq` restarts at 0 only when a new key is installed by a rekey.
  A sender must never reset `seq` under a key it has already used, including
  when a rekey is abandoned and it keeps the current key.
* Replay detection and the multi-key decryption across a rekey (current,
  pending, previous) are unchanged. They read `seq` from the clear header
  instead of from the plaintext.
* `seq` in clear tells a link observer the frame count since the last rekey,
  which it can count anyway.

### Records

```
frame_plain = record* || zero padding

record:
  kind(u8)
    0x00  END        the rest of the frame is padding
    0x01  MESSAGE    len(u16) || wire_message(len)
    0x02  FRAGMENT   msg_id(u16) || index(u16) || count(u16) || len(u16) || bytes(len)
    0x03  NACK       msg_id(u16) || n(u8) || n × index(u16)   fragments still missing
```

* The receiver parses records until `END` or the end of the frame. Unknown
  `kind` drops the rest of the frame.
* **Fragments.** A wire message larger than one frame is split into fragments
  sharing `msg_id`. Index and count are 16-bit: a maximum-size wire message
  (64 KB) needs about 290 fragments in a 256 B frame. The receiver reassembles per `(link,
  msg_id)`; a partial message is dropped after a timeout or when too many are in
  progress. Without repair, a lost fragment loses the whole message.
* **Fragment repair (NACK).** Best effort, for lossy paths where resending
  a whole message is expensive. It runs on every link, whatever the local
  transport claims: a reliable socket at one end says nothing about the path
  (one end may sit behind a lossy relay or radio). On a path that loses nothing
  it costs only the sender's buffer.
  * The receiver sends `NACK` for a partial message when a later fragment or a
    later `msg_id` arrives past a gap, or when no fragment of it has arrived for
    the stall time `max(200 ms, 2 · tx_time(frame))`. Repeated stall NACKs back
    off: each waits twice as long as the one before, so later NACKs cover
    repairs that were themselves lost or reordered. At most 5 NACKs per message
    in a row without a new fragment arriving. A new fragment resets that count
    and steps the backoff down once, so on a path that delays rather than
    loses, NACKs answered by late fragments don't use up the budget. Each reset
    needs a fragment not seen before, so a message gets at most 5 plus its
    fragment count.
  * The sender keeps the fragments of recently sent messages in a small
    per-link buffer and resends the listed ones at the message's original
    priority. It ignores a NACK for a `msg_id` it no longer holds.
  * If every fragment is lost there is nothing to NACK; the protocols above
    retransmit what matters, as before.
  * Holding fragments is optional. A sender with no buffer ignores every NACK,
    so the record never breaks interoperability.
* **Frame size is sender-local policy per link.** Every frame a node sends on a
  link has the same size, so an observer of that link cannot classify messages
  by frame length. The receiver accepts any frame size up to the existing
  maximum.
* **Coalescing.** The link's send queue packs as many queued messages as fit
  into each frame. On a slow link this batches naturally: while one frame is on
  the air the queue fills, and the next frame carries all of it. Padding is
  wasted only when the link is idle.

### Link handshake

The v4 handshake (~12 KB: both static keys, static-KEM authentication and a
signature) is kept unchanged on every connection. Caching certificates to skip
static keys on reconnect was rejected: it adds a state to get wrong, and a
stale cache becomes a hazard on the bootstrap path. On an HC-12 link the
handshake takes about 25 s. That is acceptable as long as links are not closed
without reason:

* The handshake deadline is link-aware: `max(30 s, 3 · tx_time(12 KB))`, and
  it is extended while handshake bytes keep arriving. It fails on silence, not
  on elapsed time. A hard cap of 10 deadlines stops a peer from trickling
  bytes to hold a handshake open forever.
* A link is closed only when it is dead (silence past the link-death limit),
  when the peer closes it, or on a protocol error. There is no idle close.
  Rekeys happen in place on the live link.
* Reconnects after a link dies use backoff, so a flapping radio link doesn't
  spend all its airtime on handshakes.

## Link-aware timing (local policy, no wire change)

* `Transport` gains a bandwidth hint (bytes/s, or unknown). The link measures
  RTT from keepalive probes and rekey exchanges.
* Every retransmit timer (link handshake, rekey, tunnel key exchange, circuit
  CREATE/EXTEND, ChannelOpen, channel RTO, directory lookups, route search) is
  `max(current floor, SRTT + 4·RTTVAR + k · tx_time(message))` on the link it
  depends on, where `tx_time = size / bandwidth`. Fast links keep today's
  behaviour; slow links stop resending before the first copy has finished
  sending.
* Sending is scheduled per link by priority, and slow links drop rather than
  queue. See "Best-effort sending".
* Link-death detection is set per transport class (table under "Local policy"),
  replacing the single 180 s timeout.
* The firewall test transport gains a bandwidth-limit policy so e2e tests can
  put an HC-12-speed hop into a topology.

## Best-effort sending (local policy, no wire change)

A slow link should carry as much useful data as its rate allows. Queues stay
short and excess traffic is dropped before it is sent, instead of piling up
behind it (today's 4096-frame queue is hours of backlog at HC-12 speed).

### Scheduler

Each link has a sender-side scheduler, paced to the link's bandwidth hint, or to
the measured rate if there is no hint. Messages are classified by wire type:

| Class | Contents | Under pressure |
|---|---|---|
| Control | handshake, keepalives, routing updates and probes, rekey (and NACK records, which go ahead of everything) | never dropped; small and bounded by the protocols that send it |
| Circuit control | CREATE / CREATED / DESTROY, tunnel key exchange, ChannelOpen / Close, and anything sent as critical | never dropped here; bounded by its own timeout |
| Data | circuit cells, channel data and acks, overlay Data | fair-queued per flow, dropped by queueing delay |
| Background | DHT puts, gets, watches, neighbour traffic | dropped first |

* Higher classes are served first, except that background keeps a minimum
  share of the link (10% of sent bytes, with a small banked credit), so DHT
  maintenance still advances on a busy link.
* **Data is fair-queued per flow (fq_codel style).** The flow key is the
  message type plus the circuit id, the channel id or the origin's first
  bytes. A flow that becomes active after being empty (an interactive stream
  sending a keystroke) joins the *new* list and is served before flows with a
  standing backlog; backlogged flows share the rest round robin. No stream is
  labelled interactive or bulk: the behaviour follows from which flows keep a
  queue. (Classifying streams by queue length does not work: the AIMD window
  keeps a bulk flow to a few queued messages, so it looks interactive.)
* Coalescing fills each frame from the scheduler in this order. A message
  starts in whatever room the frame being filled has left; only the remainder
  is fragmented.

### Node-wide I/O budget

The node's configured upload and download rates apply at the shared link I/O
boundary, across every physical transport and peer. Accounting counts transport
message bytes, including encrypted frame headers, tags, padding, handshake
traffic and fragment repairs. TCP/WebSocket/IP framing below the `Transport`
interface is excluded. Failed queue admission is not transmitted traffic, and
relayed cells do not add a second byte charge. Before authentication, handshake
traffic contributes to global totals without attribution to a peer.

The upload token bucket reserves 10% of its burst capacity for frames carrying
link control or repairs. All frames spend the same total bucket: control has no
unlimited bypass. Existing per-link scheduling still selects messages. A frame
already waiting to transmit can delay later control on that link; frames larger
than the bucket are admitted against a full bucket and leave debt, so very low
limits necessarily imply long frame times. Rate reloads wake pending I/O.

Download limiting applies backpressure after receiving a transport message;
it cannot undo bytes already received from the network. Local download waits
are excluded from link silence and receive-stall detection. Successful frame
authentication updates link activity independently of router dispatch. Shared
rate limits also provide an upper-bound bandwidth hint for frame sizing and
link timers; established links keep their chosen frame size across reloads.

### Drops by queueing delay

* CoDel, per data flow and for background: when the time a message has spent
  queued stays above the target for a whole interval, the scheduler drops from
  the head of that queue, more often the longer it persists.
  A queue holding no more than one frame after a message leaves it is not
  standing and is never dropped from (RFC 8289); otherwise one delayed
  message on an idle link arms the timer and a later, lone message is lost.
* Target and interval scale with the link: fast links 5 ms / 100 ms; slow links
  target 2 cell airtimes, interval 5 targets.
* A hard byte cap per link backs this up (fast links 8 MB; slow links 2 s of
  sending at the link's rate, at least 16 KB). Over the cap the scheduler sheds
  background first, then the tail of the largest data flow. Control is never
  dropped.
* Dropping is safe. Channels retransmit, datagrams are best effort, and the
  routing and DHT protocols already tolerate loss.

### Congestion window on reliable channels

* The fixed 32-packet channel window becomes an AIMD window, sender only:
  start at 4, double per RTT until the first loss, then add one per RTT;
  halve on loss (retransmit timeout or duplicate acks), never below 2; cap 32.
* The retransmit timeout covers the path's airtime: `RTO + 2 · queued ·
  airtime(packet)`, where airtime comes from the slowest link the channel is
  known to use. Without it, a 1 s RTO fires before a slow link has even sent
  the packet, and Karn's rule keeps the RTT estimate from ever learning.
* With drops in front of the slow link, each channel converges to its share of
  the link rate. The link carries frames the far end can use, not retransmits
  of data that was queued too long.

### What this does not fix

* The ~25 s handshake on HC-12 (kept on purpose, see "Link handshake").
* Per-hop store-and-forward of a cell, about 0.5 s on HC-12 (see Circuits).

## Routing protocol

A distance-vector protocol after Babel (RFC 8966), over direct links.
Destinations are node `PeerId`s.

### State

For each destination D a node keeps up to 3 feasible routes (next hop, metric,
seqno) for multipath failover, and a **feasibility distance** `FD(D) = (seqno,
metric)` of the last route it advertised for D. Each node originates a route to
itself with its own 16-bit seqno (compared modulo 2^16, as in Babel).

### Feasibility (loop freedom)

An update `(D, s, m)` from neighbour n is **feasible** if `s` is newer than
`FD(D).seqno`, or `s == FD(D).seqno` and `m < FD(D).metric`. Only feasible
routes are selected. If the only remaining routes are infeasible (starvation),
the node sends a `RouteRequest` with `SEQNO` toward D; D answers by incrementing
its seqno and advertising. This removes count-to-infinity without hop limits.
Requests are unacknowledged and can be lost, so a node resends them while D
stays starving: after 12 s, doubling up to 120 s (longer than the 10 s within
which relays drop a repeated request). An FD is forgotten 180 s after it was
last used; the node then reselects, so D becomes reachable again even if every
request was lost.

### Metric

Additive per-link cost, chosen locally per link (a fast link costs 1, a slow
link 16). With several links to one neighbour, the cost is that of the link
currently carrying its traffic, and follows it when that link fails over. `0xFFFF` is a retraction. A route whose metric would reach `0xFFFF`
is unusable.

### Table budget

A node keeps routes to the `B` destinations with the lowest metric (its **local
area**) plus every accepted landmark, and **only advertises what it keeps**.
Dropping a destination retracts it toward the neighbours it was advertised to,
so no route ever points through a node that has forgotten the destination.

`B = max(B_MIN, L)` where L is the number of landmarks the node accepts. A node
may keep more than B, never fewer than `B_MIN`. `B_MIN` is a network-wide
assumption: a relay that kept fewer would cut off destinations behind it on a
chain. Memory is not the constraint on a Pi (1024 routes are a few hundred
KB); the slow-link constraint is handled by sending changes only.

### Updates and digests

* **Changes only.** Updates are sent when something changes, batched for a
  short delay and rate-limited per link. There is no periodic full dump.
  Link additions and removals queue degree updates for every neighbour,
  including an empty-entry update when only the degree changed.
* **Digests.** Each node periodically sends each neighbour a 16-byte digest of
  the route set and degree it has advertised to that neighbour, but only once every
  change for that neighbour has been sent. The neighbour compares it with
  everything it holds from that sender, including the entry for itself (which
  it never selects). A mismatch (lost update) triggers a `RouteRequest` with
  `FULL_DUMP`, answered at most once per 10 s per neighbour.
* **Full dumps** go to a new neighbour on link-up and on request. They are
  bracketed by `FULL_START` and `FULL_END`: the receiver collects the dump and
  replaces everything it held from that sender when the dump ends, so entries
  whose retraction was lost disappear. A dump whose end is lost changes
  nothing until the next digest asks again. Ordinary updates arriving during a
  dump apply to both. A sender sends a dump from the same queue as its
  updates, so no update built after the dump can arrive before its end and be
  undone by it; a receiver applies a neighbour's routing messages one at a
  time, in arrival order. A dump missing a middle part is not detected by
  itself; the next digest finds the mismatch and asks again.
  Ordinary batches and completed snapshots share one capacity admission
  boundary. Interleaved withdrawals remain tombstones until snapshot commit.
  An overflowing batch is not committed; an overflowing assembly is discarded
  and digest comparison continues to request repair until a valid dump completes.
  The first dump still exposes admitted chunks incrementally for slow links.
* Every node sends the same entries to every neighbour (no split horizon); the
  feasibility condition already prevents loops.
* **Link death** retracts every route via that neighbour immediately and sends
  triggered updates.
* **No signatures.** Updates only travel between direct neighbours over the
  authenticated link, which already proves who sent them. (v4 signed every
  advertisement with the advertiser's key, which the receiver checked against
  that same link peer's key.)

## Landmarks

Landmarks exist only once the network outgrows `B_MIN`. A landmark is an
ordinary node that everyone keeps a route to. About √N of them give every node
a route toward any destination's neighbourhood with a √N-size table.

Status: **implemented**, with the election, flag propagation, acceptance
limits and lazy hello verification below.

### Eligibility

Local configuration.

* **Default on** only when the node is reachable (it publishes an address
  record), offers relaying (`RELAY` capability), stores DHT records, and has at
  least one link that is not slow. A node whose links are all slow, such as a
  Pi Zero relay on HC-12 alone, is never eligible by default.
* **Opting out always wins.** Any node may refuse the role regardless of the
  defaults. Forcing the role can't be enforced anyway: a landmark that won't
  serve is indistinguishable from one that can't.
* Opting in on a node that fails the defaults is allowed, with a warning.

A node advertises eligibility in its hello record
(`capabilities` bit `LANDMARK_ELIGIBLE`) and its active status with bit
`LANDMARK`. Both are additions to the existing capability bitflags.

### Election by coverage

No global size estimate is needed.

* **Covered.** A node is covered if some accepted landmark lies within its local
  area (metric no larger than its B-th nearest destination).
* **Promote.** An eligible node whose table is at budget (it is evicting, so the
  network is bigger than `B_MIN`) and that is not covered waits a random delay;
  if still uncovered it becomes a landmark: it sets `LANDMARK` on its own route
  and in its hello.
* **Demote.** A landmark that has held the role for at least the minimum tenure
  is *crowded* when another landmark lies within half its local-area radius.
  One of the two must step down, and both must agree which without asking:
  * If the other was already flagged when this node promoted (it first saw the
    flag before its own promotion), this node is the younger, and the other
    knows it is the older; this node steps down.
  * Otherwise neither may know who came first: after a merge each side finds
    the other already flagged. Both fall back to the same order: the higher
    `BLAKE3("tarnet landmark tie" || peer)` steps down.

  Landmark age is not carried on the wire: a claimed age can't be checked,
  and a node claiming to be oldest would make honest neighbours hand it the
  directory role.
* **Hysteresis.** A landmark steps down only once its reason has held for the
  hysteresis time, twice that when only hash order decided. A brief merge
  (a link that comes back for a minute) therefore moves no landmarks or
  records, and where one side knows it is younger and the other decides by
  hash, the younger goes first and the other is no longer crowded, so both
  never step down at once. After stepping down, a node doesn't promote again
  for the hysteresis time.
* A landmark also steps down, after its tenure and the hysteresis time, when
  its table holds every destination again (the network shrank below its
  budget), and at once when it is no longer eligible (it opted out, or lost
  its last link that isn't slow).
* **Balance.** Since `B = max(B_MIN, L)` and there is about one landmark per
  local area, `L · B ≈ N` settles at `L ≈ B ≈ √N`.
* **Partitions.** An island bigger than `B_MIN` that loses its landmarks becomes
  uncovered and elects its own. A smaller island needs none.
* **Merges.** When islands join, every node's local area shrinks to the
  denser merged graph, so only landmarks that now sit close together are
  crowded; each such pair resolves as above, about twice the hysteresis time
  after the join, and `L` settles back toward `√N`. Records follow: a
  placement change triggers a republish.

### How everyone learns them

The `LANDMARK` flag rides on the landmark's own route in `RouteUpdate`
(`eflags` bit 0). A relay propagates the flag of the route it selected.

There is no separate signed claim flood. The flag's authority is the landmark's
own hello record in the DHT (signed, republished every 5 minutes, and at
once when the role changes). A node verifies a landmark's hello lazily, the
first time it uses that landmark for directory placement, and caches the
result. Verification searches the DHT for the newest hello rather than
trusting a stored copy, which may predate the promotion. A hello without
`LANDMARK` is checked again 60 s later; if it still says no, the landmark is
left out of placement for 10 minutes and the neighbour advertising the flag
earns a governor strike. If no hello is found, the landmark is used and
checked again after 5 minutes. Routing via an unverified flag is allowed;
the damage a lying neighbour can do is bounded by the fair share below, and
it could lie about any route anyway.

### Acceptance limits (sybil defence)

Sybils can't fake topology: many fake identities on one machine share the same
few physical links.

* At most `max(LM_SHARE_MIN, ceil(LM_SHARE_FACTOR · L / d))` landmarks are
  accepted via any one next hop (d = number of links), and at most `LM_MAX` in
  total.
* A destination whose `LANDMARK` flag toggles faster than the rate limit is
  ignored as a landmark and earns a strike.

## Addresses and the directory

### Who publishes

Only nodes that must be reachable publish an address: nodes with Public
identities, listeners, relays and storing nodes. **Client-only daemons publish
nothing** (configuration); replies to them return over the circuits they build.
Your roaming laptop is client-only, so it is never tracked by address. It may
also use a throwaway node key, since your SID is independent of the node key.

### Address record

```
address_record:
  peer(32) || seq(u32) || ttl_secs(u32) || count(u8) ||
  count × ( landmark(32) || path_len(u8) || path(32 × path_len) ) ||
  signer_algo(u8) || pk_len(u16) || signer_pubkey ||
  sig_len(u16) || signature
signature over "tarnet address v2" || peer || seq || count || entries (TTL excluded)
```

* `count ≤ 3`: one entry per nearest landmark, so one failing landmark doesn't
  make the node unreachable.
* `path` lists the nodes after the landmark up to, but excluding, `peer`.
  `path_len ≤ PATH_MAX`. A node farther than that from every landmark is
  reachable only by route search.
* The signer key must hash to `peer`. Directory nodes and resolvers verify.
  Newest `seq` wins. Publishers count `seq` up by one per publish and
  persist it with their other sequences, so a restarted node's record is
  never older than the one it left behind. No clock is involved (see
  "Clock-free").
* A landmark's own record lists itself first, with an empty path.

Status: **implemented**.

### Tracing the path

A node knows only its next hop toward a landmark, so it learns the path by
tracing it:

* `PathTrace` is routed toward the landmark through the routing table, and
  every node appends itself, starting with the publisher. A node already on
  the list, or a list already `PATH_MAX + 2` long, drops it.
* The landmark appends itself and answers `PathTraceResult` with the whole
  list. The result returns along the list: each node passes it to the entry
  before its own, if that is a neighbour and the result came from the entry
  after. Relays keep no state.
* The address path is the list between publisher and landmark, reversed.
  Links are bidirectional, so the reverse of a route is a path. A trace longer
  than `PATH_MAX` relays leaves that landmark out of the address.
* The publisher traces again when its nearest landmarks or its next hop to
  any of them change, and otherwise every 10 minutes, since a change beyond
  its next hop is invisible to it.

### Placement

* For replica `i` in `0..R`, the responsible landmarks are the `SPREAD`
  accepted landmarks closest by XOR between `BLAKE3("tarnet dir v1" || i ||
  peer)` and `BLAKE3("tarnet dir v1" || landmark)`.
* Spreading covers small differences between nodes' landmark sets (caps,
  convergence).
* **Direction diversity.** If all responsible landmarks are reached through the
  same first hop, publisher and resolver also use the closest landmark per
  replica reached through a different first hop. Targeting one victim's entries
  then needs presence in several places, not just many IDs.

### Publishing

* The publisher routes `DirPublish` toward each responsible landmark through the
  routing table.
* It publishes when its address changes (nearest landmarks or paths), after a
  short delay and rate-limited, and otherwise every `DIR_REPUBLISH`.
* A landmark stores bounded, verified records with TTL, newest seq per peer.
  A repeat of the stored record is accepted but keeps the expiry already
  held: `ttl_secs` is relative, so a replayed copy can't be told from a fresh
  one, and only a higher seq brings a new lifetime. A record that expired at
  this landmark is not stored again unless its seq is higher (remembered for
  the 6 h TTL cap). A different record with the same seq is refused. When
  full, the record expiring soonest makes room.
  A node that is not a landmark stores nothing. When the landmark set
  changes, owners republish. There is no handoff between landmarks.
* `DirPublish` is not acknowledged and lossy links lose it, so the publisher
  checks: 5 s after publishing it looks its own record up at each landmark it
  sent it to (a `DirLookup` routed straight there, no walk; it names only the
  publisher), and sends it again where it is missing or older. Checks back
  off, 4 at most, and stop once a newer record is published.
* A path trace that gets no answer is retried after 15 s.

### Lookup (no origin)

* A `DirLookup` carries no originator.
* It starts with a random-walk phase (same rule as DHT walks: end with
  probability q). The node ending the walk computes the responsible landmark and
  routes the lookup toward it.
* The walk-ending node picks one of the responsible landmarks (spread and
  direction diversity included) at random, so a second attempt may reach
  another. With no landmark it answers "not found".
* Every hop keeps `lookup_token → previous hop` for a short time; `DirResult`
  returns along that reverse path. The landmark learns that x was looked up, not
  by whom. A walk that passes a node twice keeps the first entry, which erases
  the loop; a lookup that passes a node twice after the walk is dropped.
* A lookup that passes through x itself on its way is answered by x.
* The resolver looks up every replica at once, each up to twice, and takes
  the first verified answer.
* Relays do not cache results.
* For Hidden identities, lookups go over a circuit (DHT-over-circuits, phase 3).
  Until then a Hidden identity's lookups use the walk prefix, and the residual
  leak is accepted (see "Privacy").

### Endpoint caching

The resolver keeps an address record until its expiry (at most an hour).
When a circuit build using it fails, it stops using the entry it used, so the
next attempt goes by another landmark; when every entry has failed, it drops
the record and looks it up again. Address records that arrive with relay samples are kept the same way.
Cached addresses are never advertised and never installed as routes.

A node looks an address up only when it has no route to the destination and
its table is not a complete view; in a small network nothing changes.

## Forwarding

### The rule

`Data` and circuit `EXTEND` carry the destination plus an optional list of
**hints**: the destination's landmark and path, `[L_x, p1, …, pk]`, in order
toward the destination. A node forwarding toward destination x:

1. if x is a direct link: deliver (for EXTEND: `reached`);
2. else if x is in its routing table: forward toward x;
3. else: forward toward the **last** hint it has a route to (the one closest to
   x);
4. else: no route (EXTEND answers with the empty EXTENDED, as in v4).

Rule 3 makes shortcuts automatic: the packet heads toward x's landmark until it
meets a node that knows x or a later point on x's path. The landmark is on the
path only when nobody earlier knows x.

A node never sends a packet back where it came from; if its best route
leads there, it uses another of its routes to that node.

Status: **implemented** for `Data`, `EncryptedData`, CREATE and EXTEND. The
sender takes the hints from the destination's address. A tunnel keeps the
hints toward its far end for its lifetime; the responder looks up the
initiator's address when it has no route to it.

**Connection attempts persist.** A connection to a destination the node
knew how to reach when it started (a link, a route or an address), or to
any destination while its table is not a complete view, keeps
building for up to 60 s while builds fail, re-planning each round with a
fresh address lookup, 1 s apart doubling to 8 s. After a link dies, routes
reconverge and addresses are republished inside that, so a connection made
then succeeds well inside a TCP connect timeout. A built circuit whose
stream is refused ends the attempt.

### Circuits

* **Cell size is 512 B** (v4: 1,440 B), the same on every circuit: body 480 B,
  tag 16 B, trailer 16 B, so up to 475 B of payload per relay cell (see
  "Cell crypto"). One
  global size, because a size chosen per circuit would tell every relay
  whether the circuit is interactive or bulk. On fast links several cells
  share a frame, so the smaller cell costs little there. On an HC-12 hop a cell
  takes about 0.5 s on air instead of about 1.4 s.
* **Multi-cell relay messages.** A relay message too large for one cell (a
  post-quantum EXTEND is ~1.3 KB, its EXTENDED ~1.1 KB, INTRODUCE likewise)
  spans several cells. The first cell carries the real command, bit 15 of its
  length field set ("more follows"), and `total_len(u16) || bytes`. Each
  further cell is `Continue` with `index(u8) || bytes`, the bit set on all but
  the last. Every cell keeps its own end-to-end tag, so pieces can be lost
  but not forged. The receiving hop reassembles one message per stream id;
  single-cell messages may arrive in between; any gap drops the partial
  message. Messages are capped at 16 KB.
* **Stream message framing.** A stream's channel packet is `kind(u8) ||
  body`: `0` a whole application message, `1` FIN, `2` a fragment
  `msg_id(u16) || index(u16) || count(u16) || bytes` of a message larger than
  one cell. Fragments are reassembled in any order, so unordered and
  unreliable streams keep message boundaries.
* A waypoint is `(peer, hints)`. The initiator includes the segment's hints in
  each EXTEND. Relays only ever see hints for the segment they are extending.
* **Onion layers only at waypoints, and waypoints are authenticated.** See
  "Onion circuits" below.
* **EXTEND step timeout** is link-aware: `max(1.5 s, hops_built · (0.5 s +
  4 · tx_time(step cells on the first link)))`, not a fixed 1.5 s. The first
  hop's CREATE resend interval likewise covers its airtime.
* **Recognising TRUNCATE.** A relay that has extended only forwards cells, so
  after peeling its layer it also checks the cell against its own digest key;
  only `TRUNCATE` is acted on there. On TRUNCATE the hop destroys its
  downstream leg, forgets the pending extend (a late reply is ignored),
  becomes the endpoint again and answers TRUNCATED. A hop with nothing
  downstream just answers, so retries are safe. The initiator tries each step
  3 times.
* **Resume from the prefix.** When a step fails or times out, the initiator
  sends `TRUNCATE` to the last built hop. That hop destroys whatever it started
  downstream, answers `TRUNCATED`, and the initiator retries the step from
  there. A failed step no longer discards the whole circuit.

### Onion circuits

Status: **implemented**. Fixes from the 2026-10 audit: hop
authentication (A1), cell integrity (C2, C3), the visible cell counter (C4),
relay state limits (C5), the signature downgrade (C7) and one-hop hidden
services (A2–A4, B4, B5).

#### Layers only at waypoints

v4 adds an onion layer at every node on the routed path: each EXTEND moves
the circuit one link, so a circuit over L links takes L sequential steps, each
crossing every hop built so far. v5 adds layers only at waypoints.

* A **routed CREATE** carries a destination and hints. A node that is not the
  destination picks the next hop by the forwarding rule, allocates a circuit
  id on that link, installs keyless forwarding entries both ways and passes
  the CREATE on. The destination answers CREATED, which travels back along
  the entries.
* The initiator sends a routed CREATE toward the first waypoint. EXTEND asks
  the current last waypoint to send a routed CREATE toward the next one.
  Building takes one step per waypoint.
* A relay that can't forward (no route, link down, limits) sends DESTROY
  back. A waypoint whose routed CREATE is destroyed answers EXTEND with an
  empty EXTENDED, as in v4. The initiator retries from the built prefix
  (TRUNCATE, as in v4).
* **No hop counter.** A counter visible to relays would tell each one how far
  it is from whoever started the segment, which for the first segment is the
  initiator. Distance-vector forwarding is loop-free. Hint forwarding is
  checked by remembering each CREATE's ephemeral key for 30 s: a node that
  sees the same key again drops the CREATE and sends DESTROY.
* Each relay rewrites the circuit id, so no id is shared by two links.
* Keyless relays drop cells of the wrong size (C2).

#### Waypoint authentication

The node at the end of a routed CREATE proves it is the destination by
signing. The initiator needs no key in advance: a peer id is the hash of the
signing public key, so CREATED carries the key and the initiator checks it
against the waypoint's id.

* CREATED: `kem_ct`, the destination's signing public key, and a signature
  over a hash of the handshake (version, KEM algorithm, destination,
  ephemeral key, `kem_ct`; see the wire format).
* The initiator verifies `peer_id(signing_pk) == waypoint` and the signature.
  A relay on the segment can't answer for the waypoint, and can't swap the
  ephemeral key, which the signature covers. The `reached` flag is gone.
* The hop key is `KDF(kem_secret, H(transcript))`, transcript as signed. The
  ephemeral KEM keeps forward secrecy; the signature only authenticates.
* Cost: 96 B for an Ed25519 identity, about 1.7 KB for Falcon+Ed25519, once
  per waypoint.
* **The algorithm is implied by the key (fixes C7).** `verify` requires the
  exact key and signature lengths of the stated algorithm, so a hybrid key
  can't be checked as Ed25519 alone. Peer ids don't change.
* Relays between waypoints stay unauthenticated by design.

#### Cell crypto (version 1)

```
cell   = region(496) || trailer(16)            512 B, as before
region = body(480) || tag(16)                  encrypted by every layer
body   = command(1) || stream_id(2) || length(2) || payload || zero padding
tag    = MAC(digest_key, counter || body)      16 B keyed BLAKE3
```

* Every layer XORs a XChaCha20 keystream over the whole region (body and
  tag). Its nonce is the 16-byte trailer as it arrives, padded with 8 zero
  bytes.
* **The trailer changes at every layer (fixes C4).** Each layer replaces the
  trailer `t` with `AES-256(p, t)`, `p` a per-hop, per-direction key. The
  receiving end of a direction sees the plain 128-bit counter. The initiator
  computes the forward trailers by inverting the layers. Relays see unrelated
  values, so colluding relays get nothing to match except timing.
* **Integrity is end to end (fixes C3).** Only the node a cell is addressed to
  checks the tag. A relay recognises cells addressed to it (EXTEND, TRUNCATE,
  rendezvous commands) by checking the tag with its own digest key after
  peeling its layer. The tag covers the whole body including padding, so
  flipping any bit kills the cell. A tagging attack makes the circuit fail
  rather than marking it. The tag is under the layers, so relays never see
  the same tag value.
* **Replay.** The end of a direction keeps an ordered window on the counter.
  Relays keep a set of the last 2048 trailers they peeled and drop repeats,
  so a recent replay dies at the first honest relay. Older replays pass the
  relays and die only at the end of the direction (see Privacy).
* **Separate nonce spaces.** The layer that seals or opens a cell uses a
  different keystream nonce from layers it passes through. Otherwise an inner
  hop could choose trailers equal to a waypoint's own future counters and
  force keystream reuse.
* Payload per cell: 475 B (v4: 451 B).
* CREATE carries a cell-crypto version (1). A wide-block construction such as
  Tor's CGO, which would make a tampered cell undecryptable at the next hop,
  can be added later as version 2 without a wire break.

#### Relay limits (local policy, fixes C5)

* Half-open entries (CREATE passed on, no CREATED) are torn down after 30 s,
  with DESTROY both ways. Established relay and endpoint entries that carry
  no cell for 10 min are torn down the same way; a forwarding entry counts as
  used while its reverse entry is. Live circuits send keepalive padding after
  30 s of idleness, so this only catches circuits whose ends vanished without
  a DESTROY.
* CREATE is rate-limited per incoming link: 50 per second, bursts of 200.
  Refused CREATEs get DESTROY.
* The ephemeral-key cache that detects loops holds 16 K keys for 30 s.

#### Hidden services

Every circuit used by a hidden service, on either side, is a normal
multi-waypoint circuit. Its hop count is the identity's `outbound_hops`: the
service's for intro and rendezvous circuits it builds, the client's for its
own. With `outbound_hops = n`, a circuit has `n - 1` random waypoints before
the intro or rendezvous point. Hidden identities should use at least 3.

* **Choosing points.** Intro points (by the service), rendezvous points (by
  the client, preferring one that isn't the intro point) and every waypoint
  are picked at random as in Relay sampling: from the routing table while it
  is a complete view, else from the sampled relay pool. Neither side knows
  the other's host, so either may pick it:
  * The rendezvous point is the service's host: the service builds its
    rendezvous circuit out through at least one waypoint and back to itself,
    so it looks like any other. A waypoint answering EXTEND may route the new
    segment back the way the circuit came (only relays passing a routed
    CREATE on are kept from sending it back).
  * The intro point is the client: the client hands its INTRODUCE to the
    registered service locally, without an intro circuit.
  * A client that gets no join tries up to 3 rendezvous points.
* **IntroRegister is signed (fixes B4):** `service signing_pk || sig` over
  `"tarnet intro register v1" || intro point id || H(transcript of the
  service's handshake with the intro point)`. The intro point checks that the
  key hashes to the service id. The signature is bound to this circuit, so it
  can't be replayed on another one.
* **INTRODUCE:** `service_id || ext_len(u16) || ext || sealed`. `sealed` is
  encrypted to the service's KEM key and contains the rendezvous point, its
  hints, the cookie, mode, port and a fresh client KEM public key. The hints
  are the rendezvous point's address, or failing that its sample hints
  (nodes next to it on the walk that found it, never the client's
  neighbours), so the service's circuit can reach a rendezvous point outside
  its own local area without learning anything about the client's.
* **Reaching the intro point.** Intro records carry no hints: hints from the
  service's walk would describe where the service sampled from. A client
  outside the intro point's local area looks up its address in the directory,
  like any other destination (a Hidden client's lookup leaks only that
  someone looked up this intro point, see "Privacy"). `ext` holds typed
  extensions the intro point and service ignore when unknown, so
  proof-of-work can be added later without a break.
* **At the service (fixes B5):** INTRODUCE is handled off the circuit's message
  queue, at most 8 at a time per node; more are dropped. A replay cache, keyed
  by the hash of `sealed` and kept for twice the descriptor lifetime, drops
  repeats.
* **Service to rendezvous point:** `RendezvousJoin` carries the cookie plus `join =
  kem_ct_to_client_eph || confirm_tag`, which the rendezvous point passes to
  the client in `RendezvousJoined`.
* **End-to-end key, with forward secrecy:** derived from `static_secret ||
  eph_secret` and a hash of `sealed` and the service's ciphertext; the
  client checks the confirm tag before using it. v4 used the static KEM
  secret alone, so a later compromise of the service key exposed past
  sessions.
* **The rendezvous point splices with crypto.** A cell from the client loses
  the rendezvous point's layer of the client circuit and gains its layer of
  the service circuit, and the reverse the other way. Both sides keep every
  hop key and add the end-to-end key as an extra innermost layer. v4 replaced
  all hop keys with the end-to-end key, which is why its hidden-service
  circuits could only be one hop.
* **Direct streams refused (fixes A3).** A Hidden identity answers a direct
  `StreamBegin` exactly as a node that doesn't host it would (StreamRefused).
* **No peer record (fixes A4).** A Hidden identity never publishes the `"peer"`
  record, and switching an identity to Hidden deletes it.
* **No silent downgrade.** Any identity's connection fails if there aren't
  enough distinct relays for its hop count, instead of using fewer hops.
* An intro point without the service's key: v4 fell back to the node key,
  which linked the service to its host. Publishing now fails instead.

### Fallback: bounded route search

When the directory has no record for x, or every address fails, the initiator
runs a deduplicated, expanding-ring flood:

* `RouteSearch` with ttl 4, then 8, then 16. Every node forwards a new nonce
  once to all neighbours except the sender while ttl > 0, and remembers `nonce →
  previous hop` briefly.
* A node with x in its table, or x itself, answers `RouteSearchFound`. The
  answer accumulates the hop list on its way back, and the initiator uses it as
  hints.
* Relays install no routes. Searches are rate-limited per target and per
  neighbour. There is no originator field.

Status: **implemented**.

* Each ring is a new nonce, waited for `ttl / 2` seconds (2, 4 and 8 s). The
  searcher remembers its own nonces, so its flood coming back is dropped.
* Only the first answer for a nonce is passed back at each relay. An answer
  with more than `ROUTE_SEARCH_MAX_TTL + 1` hops is dropped.
* The searcher reverses the hop list and starts it at the last node it can
  reach itself, so the hints skip its own local area. If that is still longer
  than a message may carry (`PATH_MAX + 1`), the answer is unusable.
* A node searches when it has no route to x and no usable address: the
  directory has no record, it knows no landmark, or every entry of x's
  address failed in the last 60 s and the directory has nothing newer. It searches even when its table looks
  complete: a node at the edge of a scoped network holds no more than its
  budget and can't tell its view is partial. In a small network, a connection
  to a node that doesn't exist therefore fails after the rings (about 14 s),
  not at once.
* A search's answer is used for 5 minutes, and dropped when a build from it
  fails.

This replaces v4's `RouteProbe`, which was a set of random walks whose found
routes never expired.

## Relay sampling

`plan_circuit_path` picks waypoints for multi-hop circuits. With a scoped table
the visible population is the local area plus landmarks: nearby nodes (an
adversary near you supplies all hops) or a small self-elected set (a sybil
target). Waypoints must instead be sampled from the whole network.

* **Complete view** (fewer destinations than the budget; at exactly the
  budget a node can't tell, so it counts as scoped): sample uniformly from the routing
  table, as in v4.
Status: **implemented**.

* **Otherwise: Metropolis–Hastings walks.**
  * The node keeps a pool of sampled relays, refreshed in the background. Each
    sample is a `SampleWalk`. If the pool has too few for a request (just
    started, or many excluded), the node walks on demand. It never falls back
    to its local area.
  * At node i with d_i links, pick a neighbour j uniformly and move with
    probability `min(1, d_i / d_j)`, else stay. Either way one step is consumed.
    Degrees come from the `degree` field of `RouteUpdate`.
  * After `steps` steps the end node answers `SampleResult` along the reverse
    path. Each node replaces the token before passing the walk on and keeps
    `new token → (previous hop, old token, next hop)` for 20 s, at most 4096
    walks. Only the next hop may answer. A walk that passes a node twice
    holds two entries there, with different tokens.
  * The walk converges to a uniform node rather than one weighted by degree.
    Sybils behind few attack links are reached with probability bounded by those
    links.
  * The walk carries no originator. Walks are rate-limited per neighbour
    (10/s, bursts of 100).
* **The sample's address.** The end node puts its own address record in the
  result, if it publishes one. The walker verifies and keeps it, and reaches
  the sample by its address like any other destination.
* **Hints in the result.** The walk's path is kept too, for a sample without
  an address (no landmarks yet, or farther than `PATH_MAX` from every one).
  On the way back each node
  adds itself to the result's path, until it holds `PATH_MAX` nodes, and
  erases loops: a node already in the path cuts it back to itself. The path
  is then the walk's last stretch before the sample, which says nothing about
  where the walk began. The walker also drops its own neighbours and anything
  past them. The hints go into CREATE and EXTEND for that waypoint and into
  INTRODUCE for a rendezvous point, when no usable address is known. Relays
  use them as for any hints: they route toward the hint nearest the
  destination they can reach.
* A node that publishes no address (client-only) answers with an empty result
  and is not used as a relay.
* Samples are used only as waypoints, with their address hints. They are never
  routes.

## DHT local-policy changes

These change `dht.md`'s "Local policy" table only; no DHT wire change.

1. **Hidden identities never republish on link events.** Event-triggered
   republish (link-up today, link-down below) covers only node records (hello)
   and records of Public identities. A Hidden identity's records (TNS intro
   records, zone root) republish only on their own independent, jittered timer.
   *This fixes a leak present in v4 today:*
   * Intro records are stored as the host's own records, and
     `dht_republish_own` re-sends them 1–3 s after any link-up.
   * Every node a PUT passes through notifies watchers, even for an unchanged
     record.
   * So a watcher of the service's key can open a link to a suspected host and
     see whether a re-PUT follows. That links the service to its host.
   * Each Hidden identity has its own timer, so identities on the same host
     don't refresh together and can't be linked to each other that way. The
     timer republishes at a random point between a third and half of the
     record TTL, drawn afresh each time, so records never lapse.
   * Fixed in v4 already (no wire change).
2. **Republish on link-down** as well as link-up, with the same rate limit
   (60 s) and random delay. An island then re-places its records within seconds
   of link-death detection instead of up to 30 minutes. *Implemented.*
3. **Watch notifications only for news.** A node relaying a PUT notifies a
   watch token only when `(signer, sequence)` is newer than the last it notified
   for that token. *Implemented*: each watch remembers up to 64 signers; a
   refreshed watch keeps what it was told.
4. **Network-size estimate.** ρ uses `N_est = table size + 1` while the view is
   complete, else `L · B` (never less than the table size + 1). v4's
   `routing_table.len() + 1` would silently shrink ρ once tables are scoped.
   *Implemented*, for DHT walks and sample walk length.

## Privacy

Properties v4 aims for, and how v2 keeps them:

| Property | v2 |
|---|---|
| Link observers can't classify traffic by size | Fixed frame size per link plus coalescing. On slow links a cell spans several frames, so bursts reveal data vs control. Accepted (open decision 2): padding bursts would cost most of the saving. |
| DHT walks and lookups carry no originator | Unchanged for the DHT. Directory lookups, route search and sample walks also carry none. |
| Reaching a known node involves no third party | Unchanged inside the local area. Outside it, a directory landmark learns "x was looked up", not by whom. |
| Hidden identities never expose the host | **Fixed** (v4 used one-hop circuits to direct neighbours). Intro and rendezvous circuits are multi-waypoint on both sides, see Hidden services. Their records leave event-triggered republish (this also fixes the v4 leak). Hidden lookups go over circuits once phase 3 lands. |
| Circuit waypoints random over the whole network | Relay sampling by Metropolis–Hastings walks. |
| No network-wide census | **Improved.** In v4 every node learns every node ID and its distance. In v2 a node learns its local area plus landmarks. |

Accepted residuals:

* **Published addresses reveal topology.** A path lists real neighbours, so
  someone looking up many addresses can map part of the graph near publishing
  nodes, and pick the neighbours to surround in order to cut off a victim.
  Mitigation: only reachable nodes publish; client-only nodes publish nothing.
* **Landmarks concentrate first-contact traffic and directory load.** That makes
  them worth attacking for traffic analysis. Shortcuts, several addresses per
  node and origin-less lookups reduce this, but don't remove it.
* **Directory placement can be targeted.** An attacker who generates IDs close
  to the hashes for a victim's entries can be responsible for them, then
  withhold them. Records are signed, so withholding is all an attacker can do.
  Replication, spread and direction diversity raise the cost but don't make it
  impossible. Accepted without a placement salt (open decision 4): the worst
  case is a slower first contact, because resolution falls back to route
  search. The intended further fallback is to also store address records in
  R5N, whose random-walk replication is not keyed by landmark placement. Not
  yet specified.
* **Interim Hidden-identity lookups** (before phase 3) reveal "someone looked up
  this intro or rendezvous point" to the directory landmark, without the origin.
* **A path trace names its origin.** It is the publisher tracing to its own
  landmark, and the resulting path is published in its address anyway.
* `Data` still carries origin and destination in clear to every relay, as in v4.
  Hints add the destination's address, which is public anyway.
* **Old replays reach the end of a direction.** A relay can't keep an ordered
  replay window without seeing a counter shared with other relays, so it only
  remembers its last 2048 trailers. An attacker who records a cell and
  replays it later makes the honest relays after it forward a duplicate, which
  a colluding relay further on can see. This is an active watermark, like
  delaying cells, which low-latency onion routing doesn't prevent either.
* **Relays between two waypoints see identical cells.** Without a layer of
  their own, colluding relays on one segment can match a circuit by its bytes
  instead of by timing, which already matches them. These relays are chosen
  by routing, not by the client, so their layers never added real
  unlinkability. Bytes still change at every waypoint. They learn the next
  waypoint from the routed CREATE, as they learned it from EXTEND in v4.

## Wire format (version 7)

All multi-byte integers are big-endian. `peer` is 32 bytes. The wire message
header `VER(u8) | TYPE(u16) | LEN(u16)` is unchanged, with `VER = 7`.

Retired: `RouteAdvertisement (0x0100)`, `RouteProbe (0x0101)`,
`RouteProbeFound (0x0102)`.

```
RouteUpdate        (0x0110)
  flags(u8)          bit0 FULL (part of a full dump), bit1 FULL_START (first
                     message of a dump), bit2 FULL_END (last message of a dump);
                     others reserved, sent 0, ignored
  degree(u8)         sender's number of links, saturating at 255
  dump_id(u16)       nonzero generation shared by all chunks of a full dump;
                     zero on ordinary updates
  count(u16)
  count × ( dest(32) || seqno(u16) || metric(u16) || eflags(u8) )
                     metric 0xFFFF = retraction; eflags bit0 LANDMARK, others reserved

RouteDigest        (0x0111)
  digest(16)         first 16 bytes of BLAKE3 derive_key("tarnet route digest degree v1",
                     route_digest(16) || degree(u8)); route_digest is the first
                     16 bytes of BLAKE3 derive_key("tarnet route digest v1",
                     concatenation of advertised entries sorted by dest,
                     encoded as in RouteUpdate). This changes digest semantics;
                     peers using the older entry-only digest cannot synchronize.
  count(u16)         number of entries covered

RouteRequest       (0x0112)
  flags(u8)          bit0 FULL_DUMP, bit1 SEQNO
  [dest(32) || seqno(u16) || hop_count(u8)]      present iff SEQNO

DirPublish         (0x0130)
  landmark(32) || replica(u8) || address_record

DirLookup          (0x0131)
  flags(u8)          bit0 WALKING
  lookup_token(32) || target(32) || replica(u8) ||
  landmark(32)       all zero while WALKING; set by the node that ends the walk

DirResult          (0x0132)
  lookup_token(32) || status(u8)       0 found, 1 not found
  [address_record]                     present iff found

PathTrace          (0x0133)
  token(32) || target(32) || count(u8) || count × peer(32)
                     count ≤ PATH_MAX + 2; the origin first, each node
                     appends itself

PathTraceResult    (0x0134)
  token(32) || count(u8) || count × peer(32)
                     the trace's list, target last; returns along it

RouteSearch        (0x0140)
  nonce(16) || target(32) || ttl(u8)

RouteSearchFound   (0x0141)
  nonce(16) || target(32) || count(u8) || count × peer(32)
                     hop list from the answering node back toward the searcher:
                     the answering node first, each relay appends itself;
                     count ≤ 17

SampleWalk         (0x0150)
  token(32) || steps(u8)

SampleResult       (0x0151)
  token(32) || status(u8)              0 sample, 1 no sample
  [peer(32) || count(u8) ||            present iff sample; count ≤ PATH_MAX
   count × path(32) ||                 path nearest the sample first
   addr_len(u16) || address_record]    addr_len 0: the sample has no address
```

Changed messages:

```
Data / EncryptedData (0x0500 / 0x0501)
  origin(32) || destination(32) || ttl(u8) ||
  hint_count(u8) || hint_count × peer(32) || data

CircuitCreate (0x0700)
  circuit_id(u32) || version(u8) || flags(u8) ||
  kem_algo(u8) || pk_len(u16) || eph_pk ||
  destination(32) || hint_count(u8) || hint_count × peer(32)
                     version: cell crypto, 1 (others are refused with DESTROY);
                     flags: none defined, sent 0, ignored

CircuitCreated (0x0701)
  circuit_id(u32) || kem_ct_len(u16) || kem_ct ||
  signing_pk_len(u16) || signing_pk || sig_len(u16) || sig
                     sig over "tarnet circuit created v1" || transcript, where
                     transcript = BLAKE3 derive_key("tarnet circuit create
                     transcript v1", version || kem_algo || destination ||
                     len(eph_pk)(u32) || eph_pk || len(kem_ct)(u32) || kem_ct)

EXTEND payload (relay cell 0x05)
  the routed CREATE's fields after circuit_id (destination always present)

EXTENDED payload (relay cell 0x06)
  the CREATED's fields after circuit_id; empty = failed

IntroRegister (relay cell 0x0C)
  service_id(32) || signing_pk_len(u16) || signing_pk || sig_len(u16) || sig

Introduce (relay cell 0x07)
  service_id(32) || ext_len(u16) || ext || sealed

RendezvousJoin (relay cell 0x0A)    cookie(32) || join
RendezvousJoined (relay cell 0x0B)  join

Continue  (relay cell 0x13)   index(u8) || bytes      piece of a multi-cell message
TRUNCATE  (relay cell 0x14)   empty payload
TRUNCATED (relay cell 0x15)   empty payload
```

`hint_count ≤ PATH_MAX + 1`; a message with more is rejected. Forwarders carry
hints unchanged. Unknown flag bits are sent as 0 and ignored.
Unknown message types are dropped, so new message types can be added later
without a break. A future hierarchy layer above landmarks would go there.

Hello record: `capabilities` gains bit 2 `LANDMARK_ELIGIBLE` and bit 3
`LANDMARK`.

### Encoding rules

* **Exact decoding.** Every message, record and payload has exactly one
  encoding: a decoder rejects anything left over after the last field
  (keepalive padding excepted, which is defined as the rest of the message),
  and the wire header's `LEN` must match the payload exactly. Several
  mechanisms identify a message by a hash of its bytes (INTRODUCE replay,
  CREATE resend detection); appending junk must not make a copy look new.
* **Lists.** Every peer list (hints, paths, hops) is `count(u8) || count ×
  peer(32)` with a per-list maximum, checked by the one shared reader; a
  sender never builds a longer list.
* **Status bytes** take only their defined values (0 or 1); others are
  rejected. CREATE's flags byte must be 0.
* **Signed bytes** start with a domain label naming the object and version
  (`"tarnet dht record v1"`, `"tarnet link rekey v1"`, `"tarnet address v2"`,
  …), and length-prefix every variable-length field, so no two objects an
  identity signs can share signed bytes.
* **TTLs** on overlay `Data` are clamped to the sender default (64) on
  receipt; DHT TTLs to the type's cap; seqno-request hop budgets to 64.

## Local policy (not part of the wire contract)

### Admission and per-node state

* **One cost per message type.** Every message type has a declared cost
  (free, a budget it charges, or "charged by its handler" for work only the
  handler can tell from a resend, like CREATE and EXTEND), in one exhaustive
  table. A link peer's message pays before any handler runs; a message
  unwrapped from overlay `Data` pays the same as on a link. Budgets are
  per link peer token buckets (circuit creates, DHT queries, DHT records and
  bytes, directory, sampling, route search, seqno requests, key exchanges),
  created and dropped with the peer.
* **Bounded state.** Every table a peer can make a node grow is capped and
  expires by itself (an entry past its lifetime is never returned, and a full
  table refuses rather than grows): reverse paths, watches, tunnels and
  channels (per peer and in total), rendezvous cookies, introduction and
  key-exchange replay sets, pending circuit legs, search, sampling and
  directory state.
* **Replies come from where the request went.** A DHT response, watch
  notification, directory result or route-search answer is taken only from
  the neighbour the request was passed to; watches can be cancelled or
  refreshed only by the neighbour that registered them.
* **One send path.** Every message a node sends chooses its next hop by the
  forwarding rule and is counted against the upload limit (link and routing
  upkeep is counted but not held back), except keepalives, which belong to a
  single physical link.


| Parameter | Value |
|---|---|
| Frame size, fast links | 1449 B (today's `LINK_PAD_SIZE`; fits two 512 B cells) |
| Frame size, slow links (< 100 KB/s hint) | 256 B on the wire (232 B plaintext) |
| Coalescing wait, fast links | 30 ms + jitter for deferred messages; held outside the scheduler, so the wait is not queueing delay |
| Coalescing, slow links | until the frame is full or the link is free |
| Fragment reassembly | timeout `max(5 s, 4 · tx_time(message))`, 8 partial messages per link |
| Fragment repair buffer | sent fragments kept max(5 s, 16 · tx_time(frame)), at most 16 KB per link; NACK at most 5 per message in a row without progress, backing off |
| Link handshake deadline | `max(30 s, 3 · tx_time(12 KB))`, extended while bytes arrive |
| Reconnect backoff | 1 s doubling to 5 min, jittered |
| Scheduler minimum share, bulk + background | 10% |
| Queue delay target / interval | fast 5 ms / 100 ms; slow 2 / 10 frame times |
| Link queue byte cap | 2 s at link rate, at least 16 KB |
| Channel window | AIMD: initial 4, min 2, max 32 |
| Retransmit timers | `max(floor, SRTT + 4·RTTVAR + 2 · tx_time(msg))`; floors are today's constants |
| Jitter | Every retry, resend and backoff timer (fragment NACKs, CREATE and tunnel key-exchange resends) is scaled by a random factor in [0.75, 1.25), so the ends of a link don't fall into lockstep and timing isn't a fixed fingerprint |
| Link death, TCP/WS | transport error immediately; probe after 15 s idle; dead after 45 s silent |
| Link death, slow links | probe after 30 s idle; dead after 120 s silent |
| Triggered update batching | 250 ms, so at most 4 updates/s per link (slow: 1 per 2 s) |
| Link cost | fast 1, slow 16 |
| Feasibility distance kept after last use | 180 s |
| Seqno request hop count, duplicate window | 64, 10 s |
| Digest interval | 30 s fast, 120 s slow |
| Routes kept per destination | 3 |
| `B_MIN` | 1024 (tests: as low as 4) |
| Landmark promotion delay | uniform 0–60 s |
| Landmark minimum tenure | 30 min; demotion hysteresis 10 min (20 min when hash order decides) |
| `LM_SHARE_MIN`, `LM_SHARE_FACTOR`, `LM_MAX` | 32, 2, 8192 |
| Landmark flag rate limit | 1 change per 10 min per destination |
| Directory replicas R, spread | 3, 2 |
| Address record TTL, republish | 3 h, 1 h; on change after 1–5 s, at most once per 30 s |
| Election and address upkeep | every 2 s |
| Path trace timeout, retrace | 20 s; every 10 min, or when the nearest landmarks or the next hop to one change |
| Directory store | 65,536 records per landmark; records kept at most 6 h whatever their TTL |
| Directory messages per neighbour | 20/s, bursts of 200 |
| Lookup attempt timeout | 10 s |
| Resolved address cache | until expiry, at most 1 h; dropped when a build from it fails |
| Landmark hello check | recheck a denial after 60 s, then ignore 10 min; no hello found: retry after 5 min |
| Connection persistence | 60 s, rounds 1 s apart doubling to 8 s; in a complete view only for destinations reachable at the start |
| Publish check | lookup at each landmark 5 s after publishing, backing off, 4 checks; resend where missing |
| Path trace retry | 15 s after one got no answer |
| Configuration | `core.client_only` (default off), `core.landmark` (`auto`, `never`, `always`), `core.route_budget` (`B_MIN`) |
| `PATH_MAX` | 8 |
| Addresses per node | 3 (nearest landmarks) |
| Lookup token lifetime | 30 s; 2 attempts per replica |
| Route search | ttl 4 → 8 → 16, each ring waited `ttl / 2` s; at most 1 search per target per 30 s; relays: 5/s per neighbour, bursts of 20, nonces kept 30 s (8,192 at most); answers used 5 min |
| Relay sample pool | 32 relays, each replaced after 10 min (jittered); topped up every 20 s, 8 walks at once; only while the table is not a complete view |
| Sample walks | 20 s timeout and relay memory; 4096 remembered per relay; 10/s per neighbour, bursts of 100 |
| Sample walk steps | `min(64, 2 · ceil(log2 N_est) + 4)` |
| EXTEND step timeout | sum of link-aware RTOs over built hops, floor 1.5 s |

**Slow-link budget at research-cluster scale** (< 200 nodes, no landmarks):
digests ~1 frame per 2 min, keepalives, triggered updates of tens of bytes, DHT
maintenance at background priority. A full dump happens only on link-up or
after a digest mismatch: 1024 entries × 37 B ≈ 38 KB, about 75 s on an HC-12
link.

## Test plan

* **Barbell e2e.** Two clusters joined by a 5-hop chain, with the chain on a
  bandwidth-limited, lossy firewall policy. `B_MIN` is forced to 4 so landmarks,
  the directory, hints and sampling all run at small N.
  *Implemented* in `tests/directory.rs`: two clusters of 5, the chain at
  16 KB/s with 2% loss, plus a fast path through one gateway. A circuit and a
  tunnel reach a node of the far cluster that the near node has no route to.
* **School down.** Cut the fast path in the barbell. A new circuit to a node on
  the far side succeeds within the recovery budget. *Implemented* (same
  test). The cut resets the gateway's connections, so link death is detected
  at once; per-transport link-death timing is not implemented yet.
* **Island.** Partition the network; resolution (DHT republish on link-down) and
  connections inside the island recover. *Implemented* as
  `island_keeps_resolving_inside`: the island elects its own landmark and
  connects beyond a local area.
* **Split and merge.** Two chains joined through a bridge node that can be cut,
  one landmark-eligible node on each side of the bridge, close enough to crowd
  each other while joined. Joined, they settle on one landmark; split, the
  half without it elects its own; a merge shorter than the hysteresis moves
  nothing; a lasting merge leaves one landmark again (neither saw the other
  promote, so hash order decides) and the far ends connect. *Implemented* as
  `split_halves_elect_and_merged_halves_thin_out`.
* **Scoped chain, client-only, hidden service.** On an 8-node chain with a
  table budget of 3: landmarks get elected and the far end is resolved and
  reached by circuit and tunnel; a client-only node publishes nothing and
  still connects; a hidden service is reached by a one-hop client through
  intro and rendezvous points beyond its local area.
* **Hidden republish.** A watcher sees no re-PUT of a Hidden identity's records
  when a link to the host comes up or goes down.
* **Truncate and resume.** Drop an EXTEND mid-path; the circuit completes from
  the built prefix. *Implemented* as `circuit_extend_recovers_by_truncate`.
* **Best effort on a slow hop.** A bulk transfer and an interactive session
  share an HC-12-speed hop. Goodput stays near the link rate, keystroke
  latency stays bounded, and routing updates still get through.
  *Implemented* as `firewall_slow_link_keeps_interactive_latency_under_bulk`
  (2 KB/s line): worst keystroke RTT 1.7–2.4 s against a 3 s bound while bulk
  moves 10–13 KB. It fails without the scheduler and airtime-aware RTO.
* **Lossy path, reliable local transport.** `firewall_channel_drop_and_delay`
  (50% drop, up to 2 s delay on one side only) sets up a tunnel whose key
  exchange spans several frames. It needs NACK repair on both ends.
* **Slow-link handshake.** A link over an HC-12-speed firewall policy with 10%
  loss completes its handshake and is never closed while traffic flows or
  while idle.
* **Unit tests:** placement (determinism, spread, direction diversity), the
  directory store, address record signing and bounds, landmark acceptance
  caps and flag rate limit, and hints from an address. Also:
  feasibility and seqno requests, digest mismatch recovery,
  fragment reassembly and NACK repair (including NACK for an evicted message),
  frame seq/nonce across rekey (no `(key, seq)` reuse, old-key stragglers
  still decrypt), landmark promote/demote, fair-share caps, the forwarding
  rule, and the Metropolis–Hastings step.
* All existing `firewall_*` tests stay green.

## Alternatives considered

* **Hop-limited DV.** Fails on chains: peers behind a chain longer than the
  limit are invisible, and a longer limit puts the whole table on the chain's
  relays.
* **DHT locate (R5N) for routing.** Key-space walks behave as random walks on
  chains and barely cross bottlenecks.
* **Per-link Bloom summaries with guided search.** Bounded summaries saturate:
  telling apart two ports with millions of peers each needs about one bit per
  peer.
* **Hierarchical DHTs (Canon, Coral), Yggdrasil-style spanning trees.**
  Considered. Landmarks give the same √N-size tables without a root or an
  administrative hierarchy.

## Open decisions

1. ~~**Cell size.**~~ Decided: one global 512 B cell (see Circuits).
2. ~~**Slow-link burst padding.**~~ Decided: accepted, no burst padding (see
   Privacy).
3. ~~**Handshake trim.**~~ Decided: keep the full handshake, no certificate
   caching. Slow links get a link-aware deadline and no idle close (see Link
   handshake).
4. ~~**Directory placement salt.**~~ Decided: no salt. Placement is fixed per
   peer. Publisher and resolver must compute the same slot independently, so
   any salt must be public (it would only rotate placement, at the cost of
   epoch clocks and boundary republishes) or carried in the SID (opt-in, can
   be added later without a wire break). Targeted withholding is accepted as
   a residual (see Privacy). The intended fallback is R5N (not yet specified).
5. **Hidden-identity lookups over circuits.** Depends on phase 3
   (DHT-over-circuits).
6. ~~**Landmark eligibility defaults.**~~ Decided: reachable, relaying,
   storing, with a non-slow link; opting out always wins (see Eligibility).

### Address lifetime correction (wire v6)

Address signatures use the domain `tarnet address v2` and cover the peer,
sequence and entries, excluding the remaining TTL. Stores and caches clamp
TTL, never extend a held version, and replies carry only its remaining
whole seconds. Wire v6 rejects earlier peers because v5 signed the TTL.

Routing receive and outbox bounds derive from the maximum local area plus
accepted landmarks. When feasibility-history capacity is exhausted, new
destinations are refused until garbage collection frees history; live safety
history is never evicted for capacity. Forwarding alternatives are checked
against the feasibility distance after reselection.
