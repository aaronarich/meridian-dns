use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ResolverMode {
    Recursive,
    Forwarding,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub mode: ResolverMode,
    #[serde(default = "default_listen_addr")]
    pub listen: SocketAddr,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub blocklist: BlocklistConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub tui: TuiConfig,
    #[serde(default)]
    pub upstream: UpstreamConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CacheConfig {
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    /// Minimum TTL floor in seconds — short upstream TTLs are raised to this value
    #[serde(default = "default_min_ttl")]
    pub min_ttl_secs: u64,
    /// TTL for negative cache entries (NXDOMAIN / SERVFAIL), 0 to disable
    #[serde(default = "default_negative_ttl")]
    pub negative_ttl_secs: u64,
    /// Enable background prefetching of entries nearing expiry
    #[serde(default)]
    pub prefetch: bool,
    /// Prefetch when remaining TTL falls below this fraction of original TTL (0.0–1.0)
    #[serde(default = "default_prefetch_threshold")]
    pub prefetch_threshold: f64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: default_max_entries(),
            min_ttl_secs: default_min_ttl(),
            negative_ttl_secs: default_negative_ttl(),
            prefetch: false,
            prefetch_threshold: default_prefetch_threshold(),
        }
    }
}

fn default_listen_addr() -> SocketAddr {
    "0.0.0.0:53".parse().unwrap()
}

fn default_max_entries() -> usize {
    10_000
}

fn default_min_ttl() -> u64 {
    300 // 5 minutes
}

fn default_negative_ttl() -> u64 {
    300 // 5 minutes
}

fn default_prefetch_threshold() -> f64 {
    0.1 // prefetch when 10% TTL remains
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlocklistConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_hours: u64,
    #[serde(default)]
    pub sources: Vec<BlocklistSource>,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            refresh_interval_hours: default_refresh_interval(),
            sources: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_refresh_interval() -> u64 {
    24
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlocklistSource {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_metrics_port(),
        }
    }
}

fn default_metrics_port() -> u16 {
    9053
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TuiConfig {
    #[serde(default = "default_tick_rate")]
    pub tick_rate_ms: u64,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            tick_rate_ms: default_tick_rate(),
        }
    }
}

fn default_tick_rate() -> u64 {
    250
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UpstreamConfig {
    #[serde(default)]
    pub servers: Vec<UpstreamServer>,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    Dot,
    Doh,
    Doq,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UpstreamServer {
    pub name: String,
    pub address: String,
    pub protocol: UpstreamProtocol,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        std::fs::write(path, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_config() {
        let toml_str = r#"
mode = "recursive"

[cache]
max_entries = 5000
min_ttl_secs = 600
negative_ttl_secs = 120
prefetch = true
prefetch_threshold = 0.2

[blocklist]
enabled = true
refresh_interval_hours = 12

[[blocklist.sources]]
name = "peter-lowe"
url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0"

[metrics]
enabled = true
port = 9053

[tui]
tick_rate_ms = 500

[[upstream.servers]]
name = "quad9"
address = "9.9.9.9"
protocol = "dot"

[[upstream.servers]]
name = "cloudflare"
address = "1.1.1.1"
protocol = "doq"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(matches!(config.mode, ResolverMode::Recursive));
        assert_eq!(config.cache.max_entries, 5000);
        assert_eq!(config.cache.min_ttl_secs, 600);
        assert_eq!(config.cache.negative_ttl_secs, 120);
        assert!(config.cache.prefetch);
        assert!((config.cache.prefetch_threshold - 0.2).abs() < f64::EPSILON);
        assert_eq!(config.blocklist.sources.len(), 1);
        assert_eq!(config.upstream.servers.len(), 2);
    }

    #[test]
    fn parse_minimal_config() {
        let toml_str = r#"mode = "forwarding""#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(matches!(config.mode, ResolverMode::Forwarding));
        assert_eq!(config.cache.max_entries, 10_000);
        assert_eq!(config.cache.min_ttl_secs, 300); // default
        assert_eq!(config.cache.negative_ttl_secs, 300); // default
        assert!(!config.cache.prefetch); // default off
        assert!(config.blocklist.enabled);
    }

    #[test]
    fn invalid_mode_fails() {
        let toml_str = r#"mode = "invalid""#;
        let result = toml::from_str::<Config>(toml_str);
        assert!(result.is_err());
    }
}
