# Expose

Expose forwards local TCP or UDP services onto the tarnet network. It runs automatically as part of `tarnetd`, reading service definitions from TOML files and creating a tarnet listener for each one.

## Service Configuration

Service files live in `~/.config/tarnet/services.d/`. Each `.toml` file defines one service:

```toml
local = "127.0.0.1:22"    # local address to forward to
protocol = "tcp"          # "tcp" (default) or "udp"
publish = true            # advertise via TNS (default: false)
subdomain = "ssh"         # TNS subdomain (omit to publish at apex)
identity = "default"      # which identity to publish under
```

The `protocol` field controls both the local connection and the tarnet channel mode. TCP services use reliable-ordered channels; UDP services use unreliable-unordered channels to match UDP's fire-and-forget semantics.

The tarnet port name is derived from the filename (e.g., `ssh.toml` -> port `ssh`).

## Example: Exposing SSH

Create `~/.config/tarnet/services.d/ssh.toml`:

```toml
local = "127.0.0.1:22"
publish = true
subdomain = "ssh"
```

Restart `tarnetd` (or send a reload via `tarnet reload` or `kill -s SIGHUP <pid of tarnetd>`). Peers can now SSH in through tarnet:

```plaintext
tarnet tarify ssh alice
```

Or directly via the SOCKS proxy:

```plaintext
ssh -o ProxyCommand='nc -x 127.0.0.1:1080 %h %p' alice
```

## Daemon Flags

```plaintext
tarnetd --expose-dir <path>   # override service config directory
tarnetd --no-expose           # disable expose entirely
```
