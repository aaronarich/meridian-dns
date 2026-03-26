# Meridian — Project Brief

## What is this?

Meridian is a self-hosted, privacy-focused DNS recursive resolver written in Rust, designed to run as a systemd service on a Raspberry Pi 4/5 (aarch64). It handles all DNS resolution for a home network, with a live terminal dashboard and network-wide ad blocking.

---

## Goals

- Full DNS resolution with no mandatory dependency on upstream providers
- Maximum privacy -- in recursive mode, no single third party sees your full query history
- Encrypted upstream fallback when needed
- Network-wide ad/tracker blocking via subscribable blocklists
- A live Ratatui TUI dashboard for monitoring
- Clean, well-structured Rust codebase that can be understood and extended

---

## Architecture Overview

### Two operating modes (switchable via config, no recompile)

**Recursive mode** -- Meridian walks the DNS tree itself, starting from root servers. Most private. Slightly higher first-query latency.

**Forwarding mode** -- Meridian sends queries to configured upstream resolvers over encrypted channels. Faster, slightly less private.

In both modes, blocked domains are intercepted before any upstream or recursive lookup happens.

---

### Core components

**DNS listener**
- UDP and TCP on port 53
- Parse and serialize DNS wire format using the `hickory-proto` crate -- do not roll a custom parser

**Recursive resolver**
- Walk the DNS hierarchy from root servers
- Maintain a root hints file (or fetch on startup)
- Follow referrals and CNAME chains

**Forwarding resolver**
- Send queries to configured upstreams
- Support three upstream protocols, selectable per upstream in config:
  - DoT -- DNS over TLS, port 853
  - DoH -- DNS over HTTPS, port 443
  - DoQ -- DNS over QUIC, port 853
- Use `rustls` for TLS (not OpenSSL -- keep it pure Rust)
- Use `reqwest` for DoH
- Use `quinn` for DoQ

**Cache**
- In-memory, TTL-aware
- Shared via `Arc<RwLock<...>>`
- Configurable max entry count

**DNSSEC validation**
- Validate signatures on responses in both modes

**Blocklist engine**
- Load one or more hosts-format blocklists from URLs on startup
- Refresh on a configurable interval in the background without interrupting query handling
- Store in a `HashSet<String>` behind an `Arc<RwLock<...>>`
- If a query matches a blocked domain, return `0.0.0.0` immediately
- Blocked queries are counted in stats

**Metrics HTTP endpoint**
- Simple HTTP server on a configurable port (default 9053)
- Exposes: total queries, cache hit rate, blocked query count, upstream latency, uptime
- Hand-rolled is fine -- no need for a full Prometheus library unless it's clean to add

**Ratatui TUI**
- Invoked with `meridian tui`
- Live dashboard, redraws on a configurable tick rate
- Reads from the same shared stats state as the metrics endpoint
- Panels:
  - Mode and uptime
  - Query rate graph (last 60 seconds)
  - Recent query log (domain, record type, latency, resolution method: cache / recursive / forwarding / blocked)
  - Upstream health and average latency
  - Blocklist status (domain count, last refresh, manual refresh keybind)
- Keybinds: `q` to quit, `r` to trigger blocklist refresh

---

## Crates

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime |
| `hickory-proto` | DNS wire format -- do not reinvent this |
| `rustls` | TLS for DoT |
| `reqwest` | HTTP client for DoH |
| `quinn` | QUIC for DoQ |
| `toml` | Config file parsing |
| `tracing` | Structured logging |
| `ratatui` | Terminal UI |
| `crossterm` | Terminal backend for Ratatui |
| `clap` | CLI argument parsing |

---

## Config file shape

```toml
mode = "recursive" # or "forwarding"

[cache]
max_entries = 10000

[blocklist]
enabled = true
refresh_interval_hours = 24

[[blocklist.sources]]
name = "peter-lowe"
url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0"

[[blocklist.sources]]
name = "stevenblack"
url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

[metrics]
enabled = true
port = 9053

[tui]
tick_rate_ms = 250

# Only used in forwarding mode, or as fallback
[[upstream.servers]]
name = "quad9"
address = "9.9.9.9"
protocol = "dot"

[[upstream.servers]]
name = "cloudflare"
address = "1.1.1.1"
protocol = "doq"
```

---

## CLI interface

```
meridian              # start the resolver (reads meridian.toml)
meridian tui          # attach the live dashboard
meridian --config /path/to/config.toml
meridian check        # validate config and exit
```

---

## Deployment target

- Raspberry Pi 4 or 5, aarch64, running a 64-bit Linux distro (Raspberry Pi OS or Ubuntu)
- Runs as a systemd service
- Include a `meridian.service` systemd unit file in the repo

---

## Repository structure

```
meridian/
  src/
    main.rs
    config.rs
    listener.rs
    resolver/
      mod.rs
      recursive.rs
      forwarding.rs
    cache.rs
    blocklist.rs
    dnssec.rs
    metrics.rs
    tui/
      mod.rs
      dashboard.rs
  meridian.toml.example
  meridian.service
  README.md
```

---

## Build order (do this module by module, not all at once)

1. Project scaffold, config parsing, CLI skeleton
2. UDP/TCP listener with basic query parsing (hickory-proto)
3. In-memory cache
4. Forwarding resolver -- DoT first, then DoH, then DoQ
5. Blocklist engine
6. Recursive resolver
7. DNSSEC validation
8. Metrics HTTP endpoint
9. Ratatui TUI dashboard

Test each module before moving to the next. The forwarding resolver with DoT should be functional and usable before touching recursion.

---

## What this is NOT (don't build these)

- No authoritative DNS serving
- No zone file support
- No GUI
- No Pi-hole-style web dashboard
- No OpenSSL dependency -- rustls only

---

## Development notes for Claude Code

- Work through the build order above -- do not scaffold everything at once
- Each module should compile and have basic tests before moving on
- Prefer explicit error handling with `thiserror` over `unwrap()`
- Keep async boundaries clean -- don't block the Tokio runtime
- The shared stats state (`Arc<RwLock<ResolverStats>>`) is the backbone that connects the resolver, metrics endpoint, and TUI -- design it carefully early on
