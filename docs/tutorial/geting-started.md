# Getting Started

## Installation

Build from source with Cargo:

```plaintext
cargo build --release
```

This produces three binaries in `target/release/`: `tarnetd`, `tarnet`, and `tarnet-socks`.

## Starting the Daemon

All tarnet functionality requires the daemon to be running:

```plaintext
tarnetd
```

On first run, `tarnetd` generates a machine identity and a default identity, creates its data and config directories, and begins listening for peers. The SOCKS5 proxy starts on `127.0.0.1:1080` by default.

## Your First Identity

The default identity is created automatically. Check it with:

```plaintext
$ tarnet identity list
default
  ServiceId:     K8SGMKEVVV0R4C9SRFKN92RS4RTKWTTCTK146RYSQZEJ0K63AXSG
  Scheme:        falcon_ed25519
  Privacy:       Public
  Outbound hops: 1
```

The ServiceId is your address on the network - share it with peers who want to connect to you.

## Making a Connection

Tarnet connections are between named ports on identities. To test locally, open two terminals.

In the first, start a listener:

```plaintext
tarnet listen default --port hello
```

In the second, connect to it using the ServiceId from `identity list`:

```plaintext
tarnet connect K8SGMKEVVV0R4C9SRFKN92RS4RTKWTTCTK146RYSQZEJ0K63AXSG --port hello
```

Anything you type in either terminal will appear in the other. Press Ctrl-C to close.

## Next Steps

- [Identity](identity.md) - managing multiple identities and privacy settings
- [tarnetd](tarnetd.md) - daemon configuration, bootstrap peers, transports
- [Expose](expose.md) - forwarding local services onto the network
- [TNS](tns.md) - human-readable names for ServiceIds
