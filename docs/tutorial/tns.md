# TNS

TNS (Tarnet Name System) is decentralised name resolution for tarnet. It maps human-readable names to ServiceIds. If you know DNS, some concepts carry over - zones, delegation, record types - but the trust model is fundamentally different.

## How It Differs from DNS

DNS has a global root. Anyone can resolve `example.com` because resolution starts at the root servers and follows a shared delegation tree.

TNS has no global root. Resolution always starts from **your own zone**. To resolve the name `alice`, you need a zone record for `alice` in your zone pointing to alice's ServiceId. Without that record, the name means nothing to you. There is no central authority, no registrar, no squatting.

This makes names **subjective** - your `alice` and someone else's `alice` can point to different zones. Names are relationships you choose to create, not globally unique labels.

## Privacy

Both the DHT lookup key and the encryption key for a record are derived from the zone's ServiceId and the label name. This means you can only find and decrypt a record if you already know both the zone and the label you're looking for. An observer watching DHT traffic cannot see what names exist in a zone or what they resolve to.

Queries are also private: the DHT key sent in a lookup is an opaque hash, and reply routing uses ephemeral tokens so intermediary nodes never learn who originated the query. A node relaying your query sees a 64-byte hash but cannot reverse it to learn the zone or label.

The tradeoff: if someone knows your ServiceId and can guess a label (e.g., `@`, `ssh`, `www`), they can look it up and decrypt it, and could correlate DHT queries to specific lookups. The records are private against enumeration, not against targeted guessing.

## Record Types

| Type | Analogous to | Purpose |
|---|---|---|
| `identity` | A/AAAA | Terminal: this name resolves to a ServiceId |
| `zone` | NS | Delegation: subnames are resolved in the target zone |
| `alias` | CNAME | Redirect: resolution restarts with the target name |
| `text` | TXT | Arbitrary text metadata attached to a name |

## Publishing Records in Your Zone

Use `tns set` to add records to your zone. Records are private (local only) by default.

Publish your own identity at the zone apex (`@`) so others who delegate to you can resolve your name:

```plaintext
$ tarnet tns set @ identity K8SGMKEVVV0R4C9SRFKN92RS4RTKWTTCTK146RYSQZEJ0K63AXSG --public
@ [public]
```

`--public` stores the record locally and publishes it to the DHT. Without it, the record stays on your machine only.

## Delegation

To resolve `alice` on your node, add a zone delegation pointing to alice's ServiceId:

```plaintext
tarnet tns set alice zone <alice-service-id>
```

This is a private record in your zone - a petname. You can now resolve `alice` and any names alice has published in her zone:

```plaintext
$ tarnet tns resolve alice
  IDENTITY    <alice-service-id>
```

What happens here: `alice` is looked up in your zone, finds a zone delegation, follows it to alice's zone, then auto-fetches `@` (the apex) - which alice published as an identity record. This mirrors how DNS follows NS delegations to find apex A records.

If alice has published subnames (e.g., `ssh`, `blog`), you can resolve them too:

```plaintext
$ tarnet tns resolve ssh.alice
  IDENTITY    <alice-ssh-service-id>
```

## Aliases

An alias redirects resolution to another name:

```plaintext
tarnet tns set blog alias @
```

Now `blog` in your zone resolves to whatever `@` resolves to.

Alias targets can be a bare label (relative to the current zone) or absolute - pointing into another zone by ending with a raw ServiceId:

```plaintext
tarnet tns set mirror alias www.<alice-service-id>
```

You can publish an alias that points to a private petname - the publisher may have a valid reason for it. But resolvers who encounter the alias will fail to follow it if they don't have the same petname in their own zone. TNS stops resolution rather than silently resolving to something unintended.

## Managing Records

```plaintext
tarnet tns set  <name> <type> <value> [--public] [--identity <label>]
tarnet tns get  <name> [--identity <label>]
tarnet tns rm   <name> [--identity <label>]
tarnet tns list [--identity <label>]
```

`--identity` selects which identity's zone to operate on. Defaults to `default`.

List all records in your zone:

```plaintext
$ tarnet tns list
@ [public]:
  IDENTITY    K8SGMKEV...AXSG
alice [private]:
  ZONE        Y8VQVBC1...RR0G
```

## Resolving

```plaintext
tarnet tns resolve <name> [--identity <label>] [--zone <service-id or identity label>]
```

Without flags, resolution starts from your default identity's zone. `--identity` selects a different identity's zone. `--zone` overrides both and starts from a specific zone — useful for checking what another zone has published.

You can also skip delegation entirely by using a raw ServiceId as a label:

```plaintext
tarnet tns resolve ssh.<alice-service-id>
```

## Export and Import

```plaintext
tarnet tns export backup.json [--identity <label>]
tarnet tns import backup.json [--identity <label>]
tarnet tns clear [--identity <label>]
```

Useful for migrating a zone to a new machine or keeping a backup.
