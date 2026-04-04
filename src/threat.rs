use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use tracing::{debug, info, warn};

use crate::config::ThreatConfig;

/// A domain flagged by heuristics, pending LLM classification
#[derive(Debug, Clone)]
pub struct GraylistEntry {
    pub domain: String,
    pub first_seen: Instant,
    pub query_count: u64,
    pub entropy: f64,
    pub flags: Vec<ThreatFlag>,
    pub classification: Option<LlmClassification>,
}

/// Why a domain was flagged
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatFlag {
    HighEntropy,
    SuspectedDga,
    DnsTunnel,
    HighFrequencyUnknown,
}

impl std::fmt::Display for ThreatFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatFlag::HighEntropy => write!(f, "high-entropy"),
            ThreatFlag::SuspectedDga => write!(f, "suspected-dga"),
            ThreatFlag::DnsTunnel => write!(f, "dns-tunnel"),
            ThreatFlag::HighFrequencyUnknown => write!(f, "high-freq-unknown"),
        }
    }
}

/// Result from ollama classification
#[derive(Debug, Clone)]
pub struct LlmClassification {
    pub category: String,
    pub confidence: f64,
    pub explanation: String,
    pub timestamp: Instant,
}

/// Shared graylist state
#[derive(Debug)]
pub struct ThreatIntel {
    /// Domains on the graylist: domain -> entry
    pub graylist: HashMap<String, GraylistEntry>,
    /// Domains the user has explicitly approved (won't be graylisted again)
    pub approved: std::collections::HashSet<String>,
    /// How many domains have been graylisted total (including removed)
    pub total_flagged: u64,
    /// How many LLM classifications have been performed
    pub total_classifications: u64,
    /// Track query frequency for domains not on any blocklist: domain -> (count, first_seen)
    frequency_tracker: HashMap<String, (u64, Instant)>,
}

const MAX_GRAYLIST_SIZE: usize = 500;
const MAX_FREQUENCY_TRACKER: usize = 5000;

impl ThreatIntel {
    pub fn new() -> Self {
        Self {
            graylist: HashMap::new(),
            approved: std::collections::HashSet::new(),
            total_flagged: 0,
            total_classifications: 0,
            frequency_tracker: HashMap::new(),
        }
    }

    /// Record a query and return threat flags if suspicious.
    /// This is the fast-path check that runs on every non-blocked query.
    pub fn analyze_domain(&mut self, domain: &str, config: &ThreatConfig) -> Vec<ThreatFlag> {
        let normalized = domain.trim_end_matches('.').to_lowercase();

        // Skip approved domains
        if self.approved.contains(&normalized) {
            return Vec::new();
        }

        // Skip very short domains (e.g., "com.", "net.")
        if normalized.len() < 4 || !normalized.contains('.') {
            return Vec::new();
        }

        // Skip well-known TLDs / infrastructure domains
        if is_infrastructure_domain(&normalized) {
            return Vec::new();
        }

        let mut flags = Vec::new();

        // 1. Entropy check on the subdomain portion
        let entropy = domain_entropy(&normalized);
        if entropy > config.entropy_threshold {
            flags.push(ThreatFlag::HighEntropy);
        }

        // 2. DGA detection: high entropy + unusual character patterns
        if is_suspected_dga(&normalized, config.entropy_threshold) {
            flags.push(ThreatFlag::SuspectedDga);
        }

        // 3. DNS tunnel detection: very long labels or excessive subdomains
        if is_dns_tunnel(&normalized) {
            flags.push(ThreatFlag::DnsTunnel);
        }

        // 4. Frequency tracking for unknown domains
        let freq_entry = self
            .frequency_tracker
            .entry(normalized.clone())
            .or_insert_with(|| (0, Instant::now()));
        freq_entry.0 += 1;

        let elapsed = freq_entry.1.elapsed().as_secs().max(1);
        let rate = freq_entry.0 as f64 / elapsed as f64;
        if freq_entry.0 >= config.frequency_min_queries && rate > config.frequency_rate_threshold {
            flags.push(ThreatFlag::HighFrequencyUnknown);
        }

        // Evict old frequency tracker entries to prevent unbounded growth
        if self.frequency_tracker.len() > MAX_FREQUENCY_TRACKER {
            let cutoff = Instant::now() - std::time::Duration::from_secs(3600);
            self.frequency_tracker.retain(|_, (_, first)| *first > cutoff);
        }

        // If flagged, add to graylist
        if !flags.is_empty() && !self.graylist.contains_key(&normalized) {
            if self.graylist.len() >= MAX_GRAYLIST_SIZE {
                // Evict oldest entry
                if let Some(oldest_key) = self
                    .graylist
                    .iter()
                    .min_by_key(|(_, e)| e.first_seen)
                    .map(|(k, _)| k.clone())
                {
                    self.graylist.remove(&oldest_key);
                }
            }

            self.total_flagged += 1;
            self.graylist.insert(
                normalized.clone(),
                GraylistEntry {
                    domain: normalized,
                    first_seen: Instant::now(),
                    query_count: 1,
                    entropy,
                    flags: flags.clone(),
                    classification: None,
                },
            );

            debug!(domain = %domain, ?flags, entropy, "domain added to graylist");
        } else if let Some(entry) = self.graylist.get_mut(&normalized) {
            entry.query_count += 1;
            // Add new flags we haven't seen before
            for flag in &flags {
                if !entry.flags.contains(flag) {
                    entry.flags.push(flag.clone());
                }
            }
        }

        flags
    }

    /// Get domains that need LLM classification (no classification yet, sorted by query count)
    pub fn pending_classification(&self, limit: usize) -> Vec<GraylistEntry> {
        let mut pending: Vec<_> = self
            .graylist
            .values()
            .filter(|e| e.classification.is_none())
            .cloned()
            .collect();
        pending.sort_by(|a, b| b.query_count.cmp(&a.query_count));
        pending.truncate(limit);
        pending
    }

    /// Store an LLM classification result
    pub fn set_classification(&mut self, domain: &str, classification: LlmClassification) {
        let normalized = domain.trim_end_matches('.').to_lowercase();
        if let Some(entry) = self.graylist.get_mut(&normalized) {
            entry.classification = Some(classification);
            self.total_classifications += 1;
        }
    }

    /// Approve a domain (remove from graylist, prevent future flagging)
    pub fn approve_domain(&mut self, domain: &str) {
        let normalized = domain.trim_end_matches('.').to_lowercase();
        self.graylist.remove(&normalized);
        self.approved.insert(normalized);
    }

    /// Check if a domain is graylisted
    pub fn is_graylisted(&self, domain: &str) -> bool {
        let normalized = domain.trim_end_matches('.').to_lowercase();
        self.graylist.contains_key(&normalized)
    }
}

pub type SharedThreatIntel = Arc<RwLock<ThreatIntel>>;

pub fn new_shared_threat_intel() -> SharedThreatIntel {
    Arc::new(RwLock::new(ThreatIntel::new()))
}

// ── Heuristic functions ──

/// Calculate Shannon entropy of the subdomain labels (excludes the registered domain).
/// Higher entropy = more random-looking = more suspicious.
pub fn domain_entropy(domain: &str) -> f64 {
    // Extract subdomain portion: for "abc.xyz.example.com", analyze "abc.xyz"
    let parts: Vec<&str> = domain.split('.').collect();
    let label = if parts.len() > 2 {
        // Join all labels except the last two (registered domain + TLD)
        parts[..parts.len() - 2].join(".")
    } else {
        // For domains like "example.com", analyze the domain label itself
        parts[0].to_string()
    };

    if label.is_empty() {
        return 0.0;
    }

    shannon_entropy(&label)
}

fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let mut freq = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0u64) += 1;
    }

    freq.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

/// Check if a domain looks like it was generated by a DGA.
/// Looks for: high entropy + mostly consonants + numeric-heavy patterns.
fn is_suspected_dga(domain: &str, entropy_threshold: f64) -> bool {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return false;
    }

    // Analyze the leftmost label (most likely to be DGA-generated)
    let label = parts[0];
    if label.len() < 6 {
        return false;
    }

    let entropy = shannon_entropy(label);
    if entropy < entropy_threshold * 0.85 {
        return false;
    }

    let chars: Vec<char> = label.chars().collect();
    let digit_ratio = chars.iter().filter(|c| c.is_ascii_digit()).count() as f64 / chars.len() as f64;
    let vowel_count = chars
        .iter()
        .filter(|c| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u'))
        .count();
    let vowel_ratio = vowel_count as f64 / chars.len() as f64;

    // DGA domains often have: high digit ratio OR very low vowel ratio
    // Normal English words have ~35-45% vowels
    (digit_ratio > 0.3 && entropy > entropy_threshold * 0.9)
        || (vowel_ratio < 0.15 && label.len() > 8 && entropy > entropy_threshold * 0.85)
        || (digit_ratio > 0.5)
}

/// Detect potential DNS tunneling: unusually long subdomain labels or many subdomains.
fn is_dns_tunnel(domain: &str) -> bool {
    let parts: Vec<&str> = domain.split('.').collect();

    // Many subdomain levels (normal is 3-4 max for most domains)
    if parts.len() > 6 {
        return true;
    }

    // Any single label longer than 40 chars is suspicious (base64 encoded data)
    if parts.iter().any(|p| p.len() > 40) {
        return true;
    }

    // Total domain length over 100 is very suspicious
    if domain.len() > 100 {
        return true;
    }

    // Check for base64-like patterns in subdomain labels
    if parts.len() > 2 {
        let subdomain_part = &parts[..parts.len() - 2];
        let total_subdomain_len: usize = subdomain_part.iter().map(|p| p.len()).sum();
        if total_subdomain_len > 60 {
            return true;
        }
    }

    false
}

/// Check if a domain is a well-known infrastructure domain that shouldn't be flagged.
fn is_infrastructure_domain(domain: &str) -> bool {
    let infra_suffixes = [
        "in-addr.arpa",
        "ip6.arpa",
        "local",
        "localhost",
        "_tcp.",
        "_udp.",
        "_tls.",
    ];

    for suffix in &infra_suffixes {
        if domain.ends_with(suffix) || domain == *suffix {
            return true;
        }
    }

    false
}

// ── Ollama integration ──

/// Spawn background task that periodically classifies graylisted domains via ollama.
pub fn spawn_classification_task(
    config: ThreatConfig,
    threat_intel: SharedThreatIntel,
) {
    if !config.enabled || !config.ollama_enabled {
        return;
    }

    let interval = std::time::Duration::from_secs(config.classification_interval_secs);

    tokio::spawn(async move {
        // Wait a bit before first classification to let queries accumulate
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        loop {
            classify_pending(&config, &threat_intel).await;
            tokio::time::sleep(interval).await;
        }
    });
}

async fn classify_pending(config: &ThreatConfig, threat_intel: &SharedThreatIntel) {
    let pending = {
        let ti = match threat_intel.read() {
            Ok(ti) => ti,
            Err(_) => return,
        };
        ti.pending_classification(config.classification_batch_size)
    };

    if pending.is_empty() {
        return;
    }

    info!(
        count = pending.len(),
        "classifying graylisted domains via ollama"
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    for entry in &pending {
        let prompt = build_classification_prompt(entry);

        let body = serde_json::json!({
            "model": config.ollama_model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "temperature": 0.1,
                "num_predict": 200,
            }
        });

        let url = format!("{}/api/generate", config.ollama_url);
        match client.post(&url).json(&body).send().await {
            Ok(resp) => {
                if let Ok(text) = resp.text().await {
                    if let Some(classification) = parse_ollama_response(&text) {
                        debug!(
                            domain = %entry.domain,
                            category = %classification.category,
                            confidence = classification.confidence,
                            "classified domain"
                        );
                        if let Ok(mut ti) = threat_intel.write() {
                            ti.set_classification(&entry.domain, classification);
                        }
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "ollama classification request failed");
                // Don't spam on connection errors — break and retry next cycle
                break;
            }
        }

        // Small delay between requests to not overwhelm the Pi
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

fn build_classification_prompt(entry: &GraylistEntry) -> String {
    let flags: Vec<String> = entry.flags.iter().map(|f| f.to_string()).collect();
    format!(
        "You are a DNS security analyst. Classify this domain name into exactly one category.\n\
         \n\
         Domain: {}\n\
         Query count: {}\n\
         Shannon entropy: {:.2}\n\
         Heuristic flags: {}\n\
         \n\
         Categories:\n\
         - ad-tracker: Advertising or tracking domain\n\
         - malware-c2: Malware command-and-control\n\
         - dga: Domain generation algorithm\n\
         - data-exfil: DNS tunneling / data exfiltration\n\
         - analytics: Analytics or telemetry service\n\
         - cdn: Content delivery network (benign)\n\
         - legitimate: Normal, legitimate domain\n\
         - unknown: Cannot determine\n\
         \n\
         Respond in exactly this format (3 lines, no extra text):\n\
         CATEGORY: <category>\n\
         CONFIDENCE: <0.0-1.0>\n\
         REASON: <one sentence explanation>",
        entry.domain,
        entry.query_count,
        entry.entropy,
        flags.join(", "),
    )
}

fn parse_ollama_response(response_json: &str) -> Option<LlmClassification> {
    let v: serde_json::Value = serde_json::from_str(response_json).ok()?;
    let text = v["response"].as_str()?;

    let mut category = String::new();
    let mut confidence: f64 = 0.5;
    let mut explanation = String::new();

    for line in text.lines() {
        let line = line.trim();
        if let Some(cat) = line.strip_prefix("CATEGORY:") {
            category = cat.trim().to_lowercase();
        } else if let Some(conf) = line.strip_prefix("CONFIDENCE:") {
            confidence = conf.trim().parse().unwrap_or(0.5);
        } else if let Some(reason) = line.strip_prefix("REASON:") {
            explanation = reason.trim().to_string();
        }
    }

    if category.is_empty() {
        // Try to extract something useful even if format wasn't followed
        category = "unknown".to_string();
        explanation = text.chars().take(150).collect();
    }

    Some(LlmClassification {
        category,
        confidence: confidence.clamp(0.0, 1.0),
        explanation,
        timestamp: Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_normal_domains() {
        // Normal domains should have moderate entropy
        let e = domain_entropy("google.com");
        assert!(e < 3.5, "google.com entropy {e} should be < 3.5");

        let e = domain_entropy("www.example.com");
        assert!(e < 3.5, "www.example.com entropy {e} should be < 3.5");
    }

    #[test]
    fn entropy_random_domains() {
        // Random/DGA domains should have high entropy
        let e = domain_entropy("xk4jf9a2b7c.evil.com");
        assert!(e > 3.0, "random domain entropy {e} should be > 3.0");
    }

    #[test]
    fn dns_tunnel_detection() {
        // Normal domain
        assert!(!is_dns_tunnel("google.com"));
        assert!(!is_dns_tunnel("www.example.com"));

        // Tunnel-like: very long subdomain
        assert!(is_dns_tunnel(
            "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3QgbWVzc2FnZQ.evil.com"
        ));

        // Tunnel-like: many subdomains
        assert!(is_dns_tunnel("a.b.c.d.e.f.g.evil.com"));

        // Tunnel-like: very long total
        let long = format!("{}.{}.evil.com", "a".repeat(50), "b".repeat(50));
        assert!(is_dns_tunnel(&long));
    }

    #[test]
    fn dga_detection() {
        // Normal domains should not be flagged
        assert!(!is_suspected_dga("google.com", 3.5));
        assert!(!is_suspected_dga("facebook.com", 3.5));

        // DGA-like domains
        assert!(is_suspected_dga("xk4jf92b7c3.evil.com", 3.5));
        assert!(is_suspected_dga("a8b3c9d2e1f.malware.net", 3.5));
    }

    #[test]
    fn infrastructure_domains_skipped() {
        assert!(is_infrastructure_domain("1.168.192.in-addr.arpa"));
        assert!(is_infrastructure_domain("localhost"));
        assert!(!is_infrastructure_domain("google.com"));
    }

    #[test]
    fn graylist_basic_flow() {
        let config = ThreatConfig::default();
        let mut ti = ThreatIntel::new();

        // A suspicious domain should get flagged
        let flags = ti.analyze_domain(
            "xk4jf92b7c3d5e.evil.com",
            &config,
        );
        assert!(!flags.is_empty(), "random-looking domain should be flagged");
        assert!(ti.is_graylisted("xk4jf92b7c3d5e.evil.com"));

        // Normal domain should not
        let flags = ti.analyze_domain("google.com", &config);
        assert!(flags.is_empty(), "google.com should not be flagged");
        assert!(!ti.is_graylisted("google.com"));
    }

    #[test]
    fn approve_removes_from_graylist() {
        let config = ThreatConfig::default();
        let mut ti = ThreatIntel::new();

        ti.analyze_domain("xk4jf92b7c3d5e.evil.com", &config);
        assert!(ti.is_graylisted("xk4jf92b7c3d5e.evil.com"));

        ti.approve_domain("xk4jf92b7c3d5e.evil.com");
        assert!(!ti.is_graylisted("xk4jf92b7c3d5e.evil.com"));

        // Should not be flagged again
        let flags = ti.analyze_domain("xk4jf92b7c3d5e.evil.com", &config);
        assert!(flags.is_empty());
    }

    #[test]
    fn parse_ollama_response_valid() {
        let json = r#"{"response": "CATEGORY: ad-tracker\nCONFIDENCE: 0.85\nREASON: This domain matches known ad tracking patterns."}"#;
        let c = parse_ollama_response(json).unwrap();
        assert_eq!(c.category, "ad-tracker");
        assert!((c.confidence - 0.85).abs() < f64::EPSILON);
        assert!(c.explanation.contains("ad tracking"));
    }

    #[test]
    fn shannon_entropy_uniform() {
        // All same character = 0 entropy
        let e = shannon_entropy("aaaa");
        assert!((e - 0.0).abs() < f64::EPSILON);

        // Two equally distributed chars = 1.0
        let e = shannon_entropy("abab");
        assert!((e - 1.0).abs() < 0.01);
    }
}
