# TNS opaque label records

TNS keeps `label.SID`, local petnames, aliases, delegation, and the existing
identity algorithms. Each published label has its own encrypted record sets
at four independent DHT locations. Storage checks a blinded Ed25519 envelope
and a hash puzzle. Readers decrypt and authenticate the complete record set
with the zone's identity signature, including Falcon for hybrid identities.

The zone identity public key and authoritative version are absent from label
envelopes. Knowledge of a SID still permits targeted label guessing. Storage
admission has classical security; reader authentication retains the identity's
full security. Opacity, work, candidate retention, and independent placements
limit attacks on availability without promising post-quantum write exclusion.

## Identity key discovery

A small identity-signed `ZoneKey` descriptor at `zone_key(SID)` bootstraps the
original public key. Its value is a fixed protocol marker, with no label
directory, record values, or label references. The reader verifies the complete
public key against the requested SID and verifies its identity signature.
Validated public keys can be cached independently of mutable label data.

This lookup exposes the SID to its storage nodes. Those nodes can perform the
targeted guessing allowed to any SID holder. Label-storage nodes do not receive
this descriptor as part of a label publication. Traffic analysis, ciphertext
sizes, and collecting descriptors can still link identities and names.

## Label locations and signatures

Labels retain their existing exact UTF-8 interpretation. All variable-length
inputs use explicit big-endian lengths. Domains are distinct from pool records,
identity signatures, content keys, and the previous zone-root protocol.

For each lane `i` in `0..4`, derive a scalar from a 64-byte BLAKE3 XOF over a
domain, the complete identity public key, the label, and the lane. Reduce it
modulo the Ed25519 group order. Multiply the identity's Ed25519 public point by
this scalar to obtain the lane's blinded public key. Including the complete
hybrid key prevents identities sharing an Ed25519 component from sharing a
namespace. Reject zero scalars and invalid, small-order, or non-prime-order
public points.

The DHT location is a domain-separated 64-byte hash of the blinded public key.
The publisher derives the corresponding signing scalar from its expanded
Ed25519 seed. Derived signing uses a private, domain-separated nonce prefix
bound to the blinding factor and message; it never reuses the identity's normal
signing nonce derivation directly. Storage verifies the signature using strict
Ed25519 verification and checks that the location hashes from that exact key.

The four lanes have distinct keys and independently randomized encryption.
Each lane uses `ceil(rho / 2)` originator walks for both PUT and GET, where
`rho` is the ordinary R5N walk count. Across four independent locations this
preserves the aggregate `rho^2` meeting exponent used by the existing model,
with approximately twice the total publication and lookup traffic instead of
four times. This is a probabilistic model, not a delivery guarantee.

Observing one location does not disclose the other three. A SID holder can
derive all four after fetching the original public key.

## Encrypted publications

Each lane encrypts an owner-signed bundle with XChaCha20-Poly1305 and a fresh
24-byte nonce. Key derivation binds the SID, exact label, and lane. Associated
data binds the protocol and lookup location. The identity signature binds the
SID, label, lane, authoritative sequence, and complete serialized record set.
The identity public key and signature remain inside encryption. An empty record
set is an authenticated tombstone.

The outer DHT sequence is always zero. Its signer slot is a domain-separated
digest of the location and encrypted blob, rather than the blinded key's peer
identifier. This identifies immutable candidates for deduplication and permits
several versions to coexist. The trust gate explicitly checks this digest;
ordinary peer-bound signatures retain their existing rules.

Neither an outer sequence nor a newly arriving candidate supersedes an existing
candidate. Only readers interpret authoritative versions, after checking the
complete identity signature and namespace binding. A malformed higher version
cannot invalidate a cached answer or advance its verified version floor.

## Work and storage policy

Every distinct encrypted blob pays a hash puzzle bound to its location and blob
digest. Verification hashes the bounded encrypted blob and one fixed-size work
input.
For encrypted-blob length `n`, require `14 + ceil(log2(ceil(n / 4096)))` leading
zero bits in BLAKE3 over the work domain, lookup address, blob digest, and a
big-endian 64-bit nonce. Values are capped at 60 KiB. Work scales with value size.
The work nonce is excluded from the candidate identifier, so solving a different
puzzle for identical ciphertext does not buy another slot. Ordinary replay does
not renew an existing deadline. Nodes remember expired candidate identifiers
under the bounded replay policy.

Storage uses bounded candidates and byte limits, with fair-share eviction by
forwarding source. Generic signed junk cannot evict label candidates merely by
choosing the same lookup address. Within a label bucket, preserve an incumbent
when capacity permits and rotate the remaining candidates fairly; the incumbent
has no permanent ownership and expires normally. Locally published replacements
replace the previous local candidate rather than accumulating pinned history.

Admission, candidate caps, global capacity, and response-size limits remain
enforced even for valid envelopes. A source can create its own valid addresses;
ECC admission is not a substitute for network and storage budgets. A quantum
attacker able to forge a blinded signature can inject candidates but still
cannot create a reader-valid Falcon publication. Retention and independent
lanes mitigate crowding; they do not make it impossible.

## Publication and resolution

Changing a label republishes its descriptor and that label's four candidates.
Timer refreshes enumerate the owner's local working set and refresh each label;
no zone map is uploaded. Preflight all candidates for one label before admitting
or sending them, so capacity or size rejection does not partially publish an
edit. Refreshes produce fresh ciphertext and a higher signed inner sequence.

Withdrawals publish signed tombstones and retain their intent across restarts.
Petnames that have never been published remain local. Hidden identities refresh
on their existing intro timer; link changes must not expose their publications.

A reader obtains the public key descriptor, derives all four locations, and
searches them within the existing resolution deadline. After the first
acceptable authenticated answer, it allows 150 ms for the other lanes, without
waiting for a missing lane's full timeout. It verifies envelopes,
decrypts matching candidates, and verifies their complete identity signatures.
The greatest authenticated sequence determines the answer, including tombstones.
Cached version floors prevent a known newer answer from being replaced by an
older publication while that bounded state is retained; restart or bounded
eviction can forget it. Fresh readers still cannot prove that a storage node
supplied the latest version.

Absent labels have no signed absence proof and can require the normal lookup
timeout. Delegation and alias processing are unchanged. Private label data has
no fallback to the old SID-encrypted whole-zone root.

## Compatibility

The new admission and immutable-candidate semantics require a wire revision.
Old zone-root publications are rejected and removed from the DHT cache on load;
local identity keys and label configuration are retained for republication.
The deprecated `new_zone_root` constructor emits only a key descriptor and
ignores its old payload; it cannot publish an aggregate label map. Resource
pools retain their separate shared-secret, multi-writer protocol.
No zero-knowledge proof backend enters the production dependency graph.
