# Routing protocol (v2, draft)

Status: **draft for review, not implemented.** Replaces the routing part of wire
v4 (`RouteAdvertisement`, `RouteProbe`, `RouteProbeFound`) and changes link
framing, `Data` and circuit `EXTEND`. Ships as wire version 5, a hard break
(`WIRE_VERSION_MIN = WIRE_VERSION_MAX = 5`); after it the wire is frozen or
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
    repairs that were themselves lost or reordered. At most 5 NACKs per message.
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

### Metric

Additive per-link cost, chosen locally per link (a fast link costs 1, a slow or
lossy link more). `0xFFFF` is a retraction.

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
* **Digests.** Each node periodically sends each neighbour a 16-byte digest of
  the route set it has advertised to that neighbour. The neighbour compares it
  with what it holds from that sender. A match refreshes all those routes; a
  mismatch (lost update) triggers a `RouteRequest` with `FULL_DUMP`.
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
  steps down when another landmark lies within half its local-area radius.
  The incumbent (the one that has held the role longer, as observed locally)
  stays; ties go to the lower `BLAKE3("tarnet landmark tie" || peer)`. Tenure
  and hysteresis prevent flapping.
* **Balance.** Since `B = max(B_MIN, L)` and there is about one landmark per
  local area, `L · B ≈ N` settles at `L ≈ B ≈ √N`.
* **Partitions.** An island bigger than `B_MIN` that loses its landmarks becomes
  uncovered and elects its own. A smaller island needs none.

### How everyone learns them

The `LANDMARK` flag rides on the landmark's own route in `RouteUpdate`
(`eflags` bit 0). A relay propagates the flag of the route it selected.

There is no separate signed claim flood. The flag's authority is the landmark's
own hello record in the DHT (signed, republished every 5 minutes). A node
verifies a landmark's hello lazily, the first time it uses that landmark for
directory placement, and caches the result. A flag that fails verification
earns the advertising neighbour a governor strike. Routing via an unverified
flag is allowed; the damage a lying neighbour can do is bounded by the fair
share below, and it could lie about any route anyway.

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
signature over "tarnet address v1" || every field before signer_algo
```

* `count ≤ 3`: one entry per nearest landmark, so one failing landmark doesn't
  make the node unreachable.
* `path` lists the nodes after the landmark up to, but excluding, `peer`.
  `path_len ≤ PATH_MAX`. A node farther than that from every landmark is
  reachable only by route search.
* The signer key must hash to `peer`. Directory nodes and resolvers verify.
  Newest `seq` wins.

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
  When the landmark set changes, owners republish. There is no handoff between
  landmarks.

### Lookup (no origin)

* A `DirLookup` carries no originator.
* It starts with a random-walk phase (same rule as DHT walks: end with
  probability q). The node ending the walk computes the responsible landmark and
  routes the lookup toward it.
* Every hop keeps `lookup_token → previous hop` for a short time; `DirResult`
  returns along that reverse path. The landmark learns that x was looked up, not
  by whom.
* Relays do not cache results.
* For Hidden identities, lookups go over a circuit (DHT-over-circuits, phase 3).
  Until then a Hidden identity's lookups use the walk prefix, and the residual
  leak is accepted (see "Privacy").

### Endpoint caching

The resolver keeps an address record until its expiry and drops it the first
time a circuit build from it fails, then looks it up again. Cached addresses are
never advertised and never installed as routes.

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

### Circuits

* **Cell size is 512 B** (v4: 1,440 B), the same on every circuit: body 472 B,
  nonce 24 B, hop MAC 16 B, so up to 451 B of payload per relay cell. One
  global size, because a size chosen per circuit would tell every relay
  whether the circuit is interactive or bulk. On fast links several cells
  share a frame, so the smaller cell costs little there. On an HC-12 hop a cell
  takes about 0.5 s on air instead of about 1.4 s.
* **Multi-cell relay messages.** A relay message too large for one cell (a
  post-quantum EXTEND is ~1.3 KB, its EXTENDED ~1.1 KB, INTRODUCE likewise)
  spans several cells. The first cell carries the real command, bit 15 of its
  length field set ("more follows"), and `total_len(u16) || bytes`. Each
  further cell is `Continue` with `index(u8) || bytes`, the bit set on all but
  the last. Every cell keeps its own end-to-end digest, so pieces can be lost
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

This replaces v4's `RouteProbe`, which was a set of random walks whose found
routes never expired.

## Relay sampling

`plan_circuit_path` picks waypoints for multi-hop circuits. With a scoped table
the visible population is the local area plus landmarks: nearby nodes (an
adversary near you supplies all hops) or a small self-elected set (a sybil
target). Waypoints must instead be sampled from the whole network.

* **Complete view** (table not evicting): sample uniformly from the routing
  table, as in v4.
* **Otherwise: Metropolis–Hastings walks.**
  * The node keeps a pool of sampled relays, refreshed in the background. Each
    sample is a `SampleWalk`.
  * At node i with d_i links, pick a neighbour j uniformly and move with
    probability `min(1, d_i / d_j)`, else stay. Either way one step is consumed.
    Degrees come from the `degree` field of `RouteUpdate`.
  * After `steps` steps the end node answers `SampleResult` with its own address
    record along the reverse path.
  * The walk converges to a uniform node rather than one weighted by degree.
    Sybils behind few attack links are reached with probability bounded by those
    links.
  * The walk carries no originator.
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
   of link-death detection instead of up to 30 minutes.
3. **Watch notifications only for news.** A node relaying a PUT notifies a
   watch token only when `(signer, sequence)` is newer than the last it notified
   for that token.
4. **Network-size estimate.** ρ uses `N_est = table size + 1` while the view is
   complete, else `L · B`. v4's `routing_table.len() + 1` would silently shrink
   ρ once tables are scoped.

## Privacy

Properties v4 aims for, and how v2 keeps them:

| Property | v2 |
|---|---|
| Link observers can't classify traffic by size | Fixed frame size per link plus coalescing. On slow links a cell spans several frames, so bursts reveal data vs control. Accepted (open decision 2): padding bursts would cost most of the saving. |
| DHT walks and lookups carry no originator | Unchanged for the DHT. Directory lookups, route search and sample walks also carry none. |
| Reaching a known node involves no third party | Unchanged inside the local area. Outside it, a directory landmark learns "x was looked up", not by whom. |
| Hidden identities never expose the host | Unchanged. Their records leave event-triggered republish (this also fixes the v4 leak). Hidden lookups go over circuits once phase 3 lands. |
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
* `Data` still carries origin and destination in clear to every relay, as in v4.
  Hints add the destination's address, which is public anyway.

## Wire format (version 5)

All multi-byte integers are big-endian. `peer` is 32 bytes. The wire message
header `VER(u8) | TYPE(u16) | LEN(u16)` is unchanged, with `VER = 5`.

Retired: `RouteAdvertisement (0x0100)`, `RouteProbe (0x0101)`,
`RouteProbeFound (0x0102)`.

```
RouteUpdate        (0x0110)
  flags(u8)          bit0 FULL (this update is a full dump); others reserved, sent 0, ignored
  degree(u8)         sender's number of links, saturating at 255
  count(u16)
  count × ( dest(32) || seqno(u16) || metric(u16) || eflags(u8) )
                     metric 0xFFFF = retraction; eflags bit0 LANDMARK, others reserved

RouteDigest        (0x0111)
  digest(16)         first 16 bytes of BLAKE3 derive_key("tarnet route digest v1",
                     concatenation of the advertised entries, sorted by dest,
                     encoded as in RouteUpdate)
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

RouteSearch        (0x0140)
  nonce(16) || target(32) || ttl(u8)

RouteSearchFound   (0x0141)
  nonce(16) || target(32) || count(u8) || count × peer(32)
                     hop list from the answering node back toward the searcher

SampleWalk         (0x0150)
  token(32) || steps(u8)

SampleResult       (0x0151)
  token(32) || status(u8)              0 sample, 1 no sample
  [address_record]                     present iff sample
```

Changed messages:

```
Data / EncryptedData (0x0500 / 0x0501)
  origin(32) || destination(32) || ttl(u8) ||
  hint_count(u8) || hint_count × peer(32) || data

EXTEND payload (relay cell 0x05)
  kem_algo(u8) || pk_len(u16) || pk || destination(32) ||
  hint_count(u8) || hint_count × peer(32)

Continue  (relay cell 0x13)   index(u8) || bytes      piece of a multi-cell message
TRUNCATE  (relay cell 0x14)   empty payload
TRUNCATED (relay cell 0x15)   empty payload
```

`hint_count ≤ PATH_MAX + 1`; a message with more is rejected. Until forwarding
with hints is implemented, senders send `hint_count = 0` and forwarders carry
hints unchanged. Unknown flag bits are sent as 0 and ignored.
Unknown message types are dropped, so new message types can be added later
without a break. A future hierarchy layer above landmarks would go there.

Hello record: `capabilities` gains bit `LANDMARK_ELIGIBLE` and bit `LANDMARK`.

## Local policy (not part of the wire contract)

| Parameter | Value |
|---|---|
| Frame size, fast links | 1449 B (today's `LINK_PAD_SIZE`; fits two 512 B cells) |
| Frame size, slow links (< 100 KB/s hint) | 256 B on the wire (232 B plaintext) |
| Coalescing wait, fast links | 30 ms + jitter for deferred messages; held outside the scheduler, so the wait is not queueing delay |
| Coalescing, slow links | until the frame is full or the link is free |
| Fragment reassembly | timeout `max(5 s, 4 · tx_time(message))`, 8 partial messages per link |
| Fragment repair buffer | sent fragments kept max(5 s, 16 · tx_time(frame)), at most 16 KB per link; NACK at most 5 per message, backing off |
| Link handshake deadline | `max(30 s, 3 · tx_time(12 KB))`, extended while bytes arrive |
| Reconnect backoff | 1 s doubling to 5 min, jittered |
| Scheduler minimum share, bulk + background | 10% |
| Queue delay target / interval | fast 5 ms / 100 ms; slow 2 / 10 frame times |
| Link queue byte cap | 2 s at link rate, at least 16 KB |
| Channel window | AIMD: initial 4, min 2, max 32 |
| Retransmit timers | `max(floor, SRTT + 4·RTTVAR + 2 · tx_time(msg))`; floors are today's constants |
| Link death, TCP/WS | transport error immediately; probe after 15 s idle; dead after 45 s silent |
| Link death, slow links | probe after 30 s idle; dead after 120 s silent |
| Triggered update batching | 200 ms, at most 4 updates/s per link (slow: 1 per 2 s) |
| Digest interval | 30 s fast, 120 s slow |
| Routes kept per destination | 3 |
| `B_MIN` | 1024 (tests: as low as 4) |
| Landmark promotion delay | uniform 0–60 s |
| Landmark minimum tenure | 30 min; demotion hysteresis 10 min |
| `LM_SHARE_MIN`, `LM_SHARE_FACTOR`, `LM_MAX` | 32, 2, 8192 |
| Landmark flag rate limit | 1 change per 10 min per destination |
| Directory replicas R, spread | 3, 2 |
| Address record TTL, republish | 3 h, 1 h; on change after 1–5 s, at most once per 30 s |
| `PATH_MAX` | 8 |
| Addresses per node | 3 (nearest landmarks) |
| Lookup token lifetime | 30 s; 2 attempts per replica |
| Route search | ttl 4 → 8 → 16; at most 1 search per target per 30 s |
| Relay sample pool | 32 relays, refreshed every 10 min |
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
* **School down.** Cut the fast path in the barbell. A new circuit to a node on
  the far side succeeds within the recovery budget.
* **Island.** Partition the network; resolution (DHT republish on link-down) and
  connections inside the island recover.
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
* **Unit tests:** feasibility and seqno requests, digest mismatch recovery,
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
