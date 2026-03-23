# DHT

Tarnet includes a distributed hash table used for peer discovery and name resolution. You can also use it directly to store and retrieve small values across the network.

Queries use R5N-style hybrid routing: for the first few hops (scaled to the estimated network size), messages are forwarded to random peers, spreading the query widely. After that, routing switches to greedy convergence toward the peers closest to the target key. The random walk phase prevents shadowing - without it, a malicious node positioned close to a target key could intercept all queries and suppress or forge records. By reaching diverse parts of the network first, queries are much harder to eclipse.

## Storing and Retrieving Values

`dht put` stores a value and returns its hash. The value is encrypted before being stored - the DHT key is derived from a double hash, and the encryption key from the content hash. Nodes storing the record cannot read it; you need the content hash to both find and decrypt it.

```plaintext
$ tarnet dht put "hello world"
3f4a1b...  (128-char hex hash)
```

`dht get` retrieves a value by its hash:

```plaintext
$ tarnet dht get 3f4a1b...
hello world
```

Get operations time out after 30 seconds if the value is not found.

## Signed Records

Signed records are tied to a specific identity. Anyone can verify who published them. The value is encrypted with a key derived from the DHT lookup key, so storage nodes can see the signer and enforce replacement policy but cannot read the content. You need to know the lookup key to decrypt.

```plaintext
$ tarnet dht put-signed "my signed value" --identity default
3f4a1b...

$ tarnet dht get-signed 3f4a1b...
```

Signed records have a TTL (default 3600 seconds). Multiple identities can publish different values under the same key; `get-signed` returns all of them.

## Peer Lookups

Each node publishes a signed hello record advertising its transports and capabilities. Like other records, the value is encrypted - you need to know the peer ID to look it up and decrypt it. Storage nodes can see the signer for deduplication but cannot read the contents.

```plaintext
tarnet dht hello <peer-id>
```

This is mostly useful for diagnostics. For example, checking whether a peer is reachable and what transports it supports.
