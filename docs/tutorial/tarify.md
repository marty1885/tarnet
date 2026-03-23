# Tarify and SOCKS

Tarnet includes a SOCKS5 proxy and `tarify`, a transparent wrapper that routes an application's traffic through it. Together they let unmodified programs connect over tarnet.

## SOCKS Proxy

The daemon runs a SOCKS5 proxy on `127.0.0.1:1080` by default (configurable in `tarnetd.toml` under `[socks]`). Any SOCKS5-capable application can use it directly:

```plaintext
curl --proxy socks5h://127.0.0.1:1080 http://alice/
ssh -o ProxyCommand='nc -x 127.0.0.1:1080 %h %p' alice
```

The proxy supports both TCP (CONNECT) and UDP (UDP ASSOCIATE).

## Name Resolution

The proxy resolves hostnames through TNS first. If TNS returns an identity record, the connection is routed over tarnet circuits to that identity. If TNS resolution fails, behaviour depends on the `allow_clearnet` setting in `tarnetd.toml`:

- `allow_clearnet = false` (default) - the connection is refused. Only tarnet destinations are reachable.
- `allow_clearnet = true` - unresolved names fall through to regular DNS and are connected over the internet.

This means TNS names work as hostnames anywhere the SOCKS proxy is used. If you have a delegation for `alice` in your zone, connecting to `alice` in any SOCKS-aware application reaches alice's tarnet identity.

TNS has no equivalent of DNS's NXDOMAIN. Because records are encrypted, the DHT cannot distinguish between "name does not exist" and "name exists but you don't have the key". Resolution for names that don't exist must wait for the DHT query to time out. If the name is in your local zone and you have no record for it, the proxy rejects immediately as the information is avaliable locally - the timeout only applies once resolution reaches a remote zone.

## Tarify

`tarnet tarify` wraps a command so its network traffic goes through the SOCKS proxy transparently, without the application needing SOCKS support. It uses `LD_PRELOAD` to intercept socket calls:

```plaintext
tarnet tarify curl http://alice/
tarnet tarify ssh alice
```

This is the tarnet equivalent of `torify`. The wrapped application sees normal TCP/UDP sockets - the interception is invisible to it.

Use `--identity` to control which identity you appear as. This selects the TNS zone for name resolution, the circuits used for connections, and the identity the remote side sees you as:

```plaintext
tarnet tarify --identity work curl http://internal-server/
```

## Limitations

- `tarify` relies on `LD_PRELOAD`, so it only works with dynamically linked applications on Linux. Statically linked binaries bypass the interception.
- Applications that resolve DNS themselves (bypassing libc) will not go through TNS.
- Use `socks5h://` (not `socks5://`) when configuring applications manually - the `h` means the proxy handles DNS, which is required for TNS resolution to work.
