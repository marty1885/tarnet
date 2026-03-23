# Tarnet Tutorial

Tarnet is a peer-to-peer network you can build from scratch. Any two machines with a link between them form a tarnet. Add more nodes in any topology and the routing handles the rest. Every node gets cryptographic identities, onion-routed circuits, a name system, and a distributed hash table - no central infrastructure required.

This tutorial covers how to use it. Internal workings are explained only where they affect how you use something.

## Contents

1. [Getting Started](geting-started.md) — install, start the daemon, make your first connection
2. [Identity](identity.md) — managing identities, privacy levels, and hop counts
3. [tarnetd](tarnetd.md) — daemon configuration: transports, bootstrap peers, bandwidth limits
4. [Expose](expose.md) — forward local services onto the network
5. [TNS](tns.md) — human-readable names for ServiceIds
6. [Tarify and SOCKS](tarify.md) — route any application through tarnet
7. [Channels](channel.md) — delivery modes for connections
8. [DHT](dht.md) — distributed key-value store and peer lookups
9. [Stats](stats.md) — reading the status output

Start with [Getting Started](geting-started.md) if this is your first time.
