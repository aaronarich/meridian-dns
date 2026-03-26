# Meridian

A self-hosted, privacy-focused DNS recursive resolver written in Rust. Designed to run on a Raspberry Pi (aarch64) as a systemd service, handling all DNS resolution for your home network with network-wide ad blocking and a live terminal dashboard.

## Features

- **Recursive resolution** — walks the DNS tree from root servers; no single third party sees your full query history
- **Forwarding mode** — encrypted upstream queries via DoT, DoH, or DoQ for lower latency
- **Network-wide ad blocking** — subscribable hosts-format blocklists with background refresh
- **In-memory cache** — TTL-aware with configurable max entries
- **DNSSEC validation** — signature verification in both modes
- **Metrics endpoint** — HTTP stats (queries, cache hit rate, blocked count, latency, uptime)
- **Live TUI dashboard** — Ratatui-based terminal UI with query log, rate graphs, and blocklist controls
- **Pure Rust TLS** — uses `rustls`, no OpenSSL dependency

## Quick start

### Build from source

```sh
cargo build --release
```

### Run

```sh
# Copy and edit the example config
cp meridian.toml.example meridian.toml

# Validate config
./target/release/meridian check

# Start the resolver
./target/release/meridian --config meridian.toml

# Attach the live dashboard
./target/release/meridian tui
```

### Docker

```sh
docker compose up -d
```

This exposes DNS on port 53 (UDP/TCP) and metrics on port 9053.

## Configuration

See [`meridian.toml.example`](meridian.toml.example) for a complete example. Key settings:

```toml
mode = "recursive"  # or "forwarding"

[cache]
max_entries = 10000

[blocklist]
enabled = true
refresh_interval_hours = 24

[[blocklist.sources]]
name = "stevenblack"
url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

[metrics]
enabled = true
port = 9053

[[upstream.servers]]
name = "quad9"
address = "9.9.9.9"
protocol = "dot"  # dot, doh, or doq
```

## Deployment on Raspberry Pi

Install the binary and systemd service:

```sh
sudo cp target/release/meridian /usr/local/bin/
sudo mkdir -p /etc/meridian
sudo cp meridian.toml /etc/meridian/

# Create a dedicated user
sudo useradd -r -s /usr/sbin/nologin meridian

# Install and enable the service
sudo cp meridian.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now meridian
```

Then point your router's DHCP DNS setting to your Pi's IP address.

## CLI

```
meridian                          # start the resolver
meridian tui                      # attach the live dashboard
meridian check                    # validate config and exit
meridian --config /path/to.toml   # use a custom config path
```

## Project status

This project is under active development. See `CLAUDE.md` for the full build order and architecture details.

## License

MIT
