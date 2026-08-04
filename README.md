# Phantun Client for macOS

`phantun-client-mac` is a macOS implementation whose functional contract matches
`vendor/phantun-client-win`: the same configuration file, command-line flags,
UDP listener behavior, fake-TCP forwarding semantics, connection concurrency,
timeouts, logging, and cleanup behavior.

The binary accepts the same options as the Windows client:

```text
phantun-client [--config PATH] [--local IP:PORT] [--remote HOST:PORT]
               [--ipv4-only] [--tun-local IP] [--tun-peer IP]
```

The default configuration file is `phantun-client.json` in the working
directory. Command-line values override values from that file.

See [configuration details](./config.md), including every Windows-compatible
field and its precedence.

Run the built binary with administrator permission, as the Windows client also
requires administrator permission for packet interception. Build and
configuration tests do not change host networking.
