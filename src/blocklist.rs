use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use tracing::{info, warn};

use crate::config::BlocklistConfig;

/// Shared blocklist state
#[derive(Debug)]
pub struct Blocklist {
    domains: HashSet<String>,
    pub domain_count: usize,
    pub last_refresh: Option<Instant>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self {
            domains: HashSet::new(),
            domain_count: 0,
            last_refresh: None,
        }
    }

    /// Check if a domain is blocked. Checks the exact domain and strips trailing dot.
    pub fn is_blocked(&self, domain: &str) -> bool {
        let normalized = domain.trim_end_matches('.').to_lowercase();
        self.domains.contains(&normalized)
    }

    /// Add a single domain to the blocklist
    pub fn add_domain(&mut self, domain: String) {
        let normalized = domain.trim_end_matches('.').to_lowercase();
        self.domains.insert(normalized);
        self.domain_count = self.domains.len();
    }

    /// Replace the blocklist contents with new domains
    fn update(&mut self, domains: HashSet<String>) {
        self.domain_count = domains.len();
        self.domains = domains;
        self.last_refresh = Some(Instant::now());
    }
}

pub type SharedBlocklist = Arc<RwLock<Blocklist>>;

pub fn new_shared_blocklist() -> SharedBlocklist {
    Arc::new(RwLock::new(Blocklist::new()))
}

/// Parse a hosts-format blocklist into a set of domain names.
/// Handles lines like:
///   0.0.0.0 ads.example.com
///   127.0.0.1 tracker.example.com
///   # comments
///   (blank lines)
fn parse_hosts(content: &str) -> HashSet<String> {
    let mut domains = HashSet::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split on whitespace: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
        let mut parts = line.split_whitespace();
        let first = match parts.next() {
            Some(f) => f,
            None => continue,
        };

        // The domain is either the second field (hosts format) or the first (plain domain list)
        let domain = if first == "0.0.0.0" || first == "127.0.0.1" || first == "::1" {
            match parts.next() {
                Some(d) => d,
                None => continue,
            }
        } else {
            // Could be a plain domain list format
            first
        };

        let domain = domain.trim_end_matches('.').to_lowercase();

        // Skip localhost entries
        if domain == "localhost" || domain == "localhost.localdomain" || domain.is_empty() {
            continue;
        }

        domains.insert(domain);
    }

    domains
}

/// Fetch and load all blocklist sources
pub async fn load(config: &BlocklistConfig, blocklist: &SharedBlocklist) {
    if !config.enabled || config.sources.is_empty() {
        info!("blocklist disabled or no sources configured");
        return;
    }

    let mut all_domains = HashSet::new();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    for source in &config.sources {
        info!(name = %source.name, url = %source.url, "fetching blocklist");

        match client.get(&source.url).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    warn!(
                        name = %source.name,
                        status = %resp.status(),
                        "blocklist fetch failed"
                    );
                    continue;
                }

                match resp.text().await {
                    Ok(body) => {
                        let domains = parse_hosts(&body);
                        info!(
                            name = %source.name,
                            count = domains.len(),
                            "loaded blocklist"
                        );
                        all_domains.extend(domains);
                    }
                    Err(e) => {
                        warn!(name = %source.name, error = %e, "failed to read blocklist body");
                    }
                }
            }
            Err(e) => {
                warn!(name = %source.name, error = %e, "failed to fetch blocklist");
            }
        }
    }

    let total = all_domains.len();
    if let Ok(mut bl) = blocklist.write() {
        bl.update(all_domains);
    }
    info!(total_domains = total, "blocklist loaded");
}

/// Spawn a background task that refreshes the blocklist on the configured interval
pub fn spawn_refresh_task(config: BlocklistConfig, blocklist: SharedBlocklist) {
    if !config.enabled || config.refresh_interval_hours == 0 {
        return;
    }

    let interval = std::time::Duration::from_secs(config.refresh_interval_hours * 3600);

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            info!("refreshing blocklist");
            load(&config, &blocklist).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hosts_format() {
        let content = r#"
# This is a comment
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
0.0.0.0 localhost
# Another comment
0.0.0.0 double.click.net

"#;
        let domains = parse_hosts(content);
        assert!(domains.contains("ads.example.com"));
        assert!(domains.contains("tracker.example.com"));
        assert!(domains.contains("double.click.net"));
        assert!(!domains.contains("localhost"));
        assert_eq!(domains.len(), 3);
    }

    #[test]
    fn parse_plain_domain_list() {
        let content = "ads.example.com\ntracker.example.com\n";
        let domains = parse_hosts(content);
        assert!(domains.contains("ads.example.com"));
        assert!(domains.contains("tracker.example.com"));
        assert_eq!(domains.len(), 2);
    }

    #[test]
    fn parse_with_trailing_dots() {
        let content = "0.0.0.0 ads.example.com.\n";
        let domains = parse_hosts(content);
        assert!(domains.contains("ads.example.com"));
    }

    #[test]
    fn blocklist_is_blocked() {
        let mut bl = Blocklist::new();
        let mut domains = HashSet::new();
        domains.insert("ads.example.com".to_string());
        domains.insert("tracker.example.com".to_string());
        bl.update(domains);

        assert!(bl.is_blocked("ads.example.com"));
        assert!(bl.is_blocked("ads.example.com."));
        assert!(bl.is_blocked("ADS.EXAMPLE.COM"));
        assert!(!bl.is_blocked("safe.example.com"));
        assert_eq!(bl.domain_count, 2);
    }

    #[test]
    fn shared_blocklist() {
        let bl = new_shared_blocklist();
        {
            let mut b = bl.write().unwrap();
            let mut domains = HashSet::new();
            domains.insert("blocked.com".to_string());
            b.update(domains);
        }
        {
            let b = bl.read().unwrap();
            assert!(b.is_blocked("blocked.com"));
            assert_eq!(b.domain_count, 1);
        }
    }
}
