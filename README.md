# mimir-tracker

A lightweight tracker for [Yggdrasil](https://yggdrasil-network.github.io/) overlay network nodes. It allows clients to announce their network addresses and discover peers using Ed25519-signed records over Yggdrasil datagrams and streams.

## Features

- **Announce & Discover** — clients register their addresses via datagrams and look up peers by public key
- **Tracker-to-tracker sync** — multiple tracker instances replicate records over persistent streams with hop-limited forwarding
- **Signed records** — all announcements are Ed25519-signed to prevent spoofing
- **Automatic persistence** — records are periodically saved to disk and restored on restart
- **Adaptive TTL** — announcement TTL doubles on each re-announce (2 → 4 → … → 16 min), reducing traffic for stable nodes

## Usage

```
mimir-tracker -p <peer-uri> [-p <peer-uri> ...] [-s <tracker-pubkey> ...] [-k <hex-key>]
```

### Options

| Flag | Description |
|------|-------------|
| `-p`, `--peer` | Yggdrasil peer URI (required, repeatable) |
| `-s`, `--server` | Public key (hex) of another tracker to sync with (repeatable) |
| `-k`, `--key` | Hex-encoded 32-byte private key seed (optional; auto-generated if omitted) |
| `-h`, `--help` | Print help |

### Example

```bash
mimir-tracker \
  -p tcp://1.2.3.4:5678 \
  -s a1b2c3d4e5f6...
```

## Building

```bash
cargo build --release
```

## License

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/)