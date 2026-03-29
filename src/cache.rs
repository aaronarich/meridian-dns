use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};

/// Cache key: lowercased domain name + record type
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct CacheKey {
    pub name: String,
    pub record_type: RecordType,
}

/// A cached DNS response with TTL tracking
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The full serialized DNS response (without the original query ID)
    response: Vec<u8>,
    /// When this entry was inserted
    inserted_at: Instant,
    /// How long the entry is valid (after applying min TTL floor)
    ttl: Duration,
    /// Original TTL from the DNS response (before min TTL floor)
    original_ttl: Duration,
    /// Whether this is a negative cache entry (NXDOMAIN / SERVFAIL)
    is_negative: bool,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() >= self.ttl
    }

    fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.inserted_at.elapsed())
    }

    /// Returns true if this entry's remaining TTL is below the prefetch threshold
    fn needs_prefetch(&self, threshold: f64) -> bool {
        if self.is_negative || self.original_ttl.is_zero() {
            return false;
        }
        let remaining = self.remaining_ttl().as_secs_f64();
        let original = self.original_ttl.as_secs_f64();
        remaining / original < threshold
    }
}

/// Result of a cache lookup
pub struct CacheLookup {
    pub bytes: Vec<u8>,
    pub remaining_ttl: Duration,
    /// Indicates the caller should trigger a background re-resolve
    pub needs_prefetch: bool,
}

/// TTL-aware in-memory DNS cache
#[derive(Debug)]
pub struct DnsCache {
    entries: HashMap<CacheKey, CacheEntry>,
    max_entries: usize,
    /// Minimum TTL floor applied to positive entries
    min_ttl: Duration,
    /// TTL for negative cache entries
    negative_ttl: Duration,
    /// Prefetch threshold (fraction of original TTL)
    prefetch_threshold: f64,
    /// Whether prefetching is enabled
    prefetch_enabled: bool,
}

impl DnsCache {
    pub fn new(
        max_entries: usize,
        min_ttl_secs: u64,
        negative_ttl_secs: u64,
        prefetch: bool,
        prefetch_threshold: f64,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            min_ttl: Duration::from_secs(min_ttl_secs),
            negative_ttl: Duration::from_secs(negative_ttl_secs),
            prefetch_threshold,
            prefetch_enabled: prefetch,
        }
    }

    /// Store a DNS response in the cache.
    /// Extracts TTL from answer records, or from SOA in the authority section
    /// for negative responses (NXDOMAIN/NODATA). Skips caching if TTL is 0.
    pub fn insert(&mut self, key: CacheKey, response: &Message) {
        // Find the minimum TTL from answer records (or authority if no answers)
        let min_record_ttl = response
            .answers()
            .iter()
            .chain(response.name_servers().iter())
            .map(|r| r.ttl())
            .min()
            .or_else(|| {
                // For negative responses, use the SOA minimum TTL from the authority section
                response
                    .name_servers()
                    .iter()
                    .filter_map(|r| {
                        if let RData::SOA(soa) = r.data() {
                            // RFC 2308: use the minimum of the SOA TTL and the SOA MINIMUM field
                            Some(r.ttl().min(soa.minimum()))
                        } else {
                            None
                        }
                    })
                    .min()
            })
            .unwrap_or(0);

        if min_record_ttl == 0 {
            return; // Don't cache zero-TTL responses
        }

        let original_ttl = Duration::from_secs(min_record_ttl as u64);
        // Apply minimum TTL floor
        let effective_ttl = original_ttl.max(self.min_ttl);

        let serialized = match response.to_vec() {
            Ok(v) => v,
            Err(_) => return,
        };

        self.make_room();

        self.entries.insert(
            key,
            CacheEntry {
                response: serialized,
                inserted_at: Instant::now(),
                ttl: effective_ttl,
                original_ttl,
                is_negative: false,
            },
        );
    }

    /// Cache a negative response (NXDOMAIN or SERVFAIL).
    /// Uses the configured negative_ttl_secs.
    pub fn insert_negative(&mut self, key: CacheKey, response: &Message) {
        if self.negative_ttl.is_zero() {
            return; // Negative caching disabled
        }

        let serialized = match response.to_vec() {
            Ok(v) => v,
            Err(_) => return,
        };

        self.make_room();

        self.entries.insert(
            key,
            CacheEntry {
                response: serialized,
                inserted_at: Instant::now(),
                ttl: self.negative_ttl,
                original_ttl: self.negative_ttl,
                is_negative: true,
            },
        );
    }

    /// Look up a cached response. Returns None if not found or expired.
    pub fn lookup(&mut self, key: &CacheKey) -> Option<CacheLookup> {
        let entry = self.entries.get(key)?;

        if entry.is_expired() {
            self.entries.remove(key);
            return None;
        }

        let remaining = entry.remaining_ttl();
        let needs_prefetch =
            self.prefetch_enabled && entry.needs_prefetch(self.prefetch_threshold);

        Some(CacheLookup {
            bytes: entry.response.clone(),
            remaining_ttl: remaining,
            needs_prefetch,
        })
    }

    /// Number of entries currently in the cache
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Evict to make room if at capacity
    fn make_room(&mut self) {
        if self.entries.len() >= self.max_entries {
            self.evict_expired();
        }
        if self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }
    }

    /// Remove all expired entries
    fn evict_expired(&mut self) {
        self.entries.retain(|_, entry| !entry.is_expired());
    }

    /// Remove the entry with the least remaining TTL
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.remaining_ttl())
            .map(|(k, _)| k.clone())
        {
            self.entries.remove(&oldest_key);
        }
    }
}

pub type SharedCache = Arc<RwLock<DnsCache>>;

pub fn new_shared_cache(
    max_entries: usize,
    min_ttl_secs: u64,
    negative_ttl_secs: u64,
    prefetch: bool,
    prefetch_threshold: f64,
) -> SharedCache {
    Arc::new(RwLock::new(DnsCache::new(
        max_entries,
        min_ttl_secs,
        negative_ttl_secs,
        prefetch,
        prefetch_threshold,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, ResponseCode};
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn make_response(domain: &str, ip: Ipv4Addr, ttl: u32) -> Message {
        let mut msg = Message::new();
        msg.set_id(1000);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::NoError);

        let name = Name::from_str(domain).unwrap();
        let record = Record::from_rdata(name, ttl, RData::A(ip.into()));
        msg.add_answer(record);
        msg
    }

    fn make_nxdomain_response(domain: &str) -> Message {
        let mut msg = Message::new();
        msg.set_id(1000);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::NXDomain);
        msg
    }

    fn key(domain: &str) -> CacheKey {
        CacheKey {
            name: domain.to_lowercase(),
            record_type: RecordType::A,
        }
    }

    fn default_cache(max: usize) -> DnsCache {
        DnsCache::new(max, 0, 300, false, 0.1)
    }

    #[test]
    fn insert_and_lookup() {
        let mut cache = default_cache(100);
        let response = make_response("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300);
        let k = key("example.com.");

        cache.insert(k.clone(), &response);
        assert_eq!(cache.len(), 1);

        let result = cache.lookup(&k);
        assert!(result.is_some());

        let lookup = result.unwrap();
        assert!(!lookup.bytes.is_empty());
        assert!(lookup.remaining_ttl.as_secs() > 0);
        assert!(!lookup.needs_prefetch);
    }

    #[test]
    fn zero_ttl_not_cached() {
        let mut cache = default_cache(100);
        let response = make_response("example.com.", Ipv4Addr::new(1, 2, 3, 4), 0);
        cache.insert(key("example.com."), &response);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn miss_returns_none() {
        let mut cache = default_cache(100);
        assert!(cache.lookup(&key("nonexistent.com.")).is_none());
    }

    #[test]
    fn eviction_at_capacity() {
        let mut cache = default_cache(2);

        let r1 = make_response("one.com.", Ipv4Addr::new(1, 1, 1, 1), 100);
        let r2 = make_response("two.com.", Ipv4Addr::new(2, 2, 2, 2), 200);
        let r3 = make_response("three.com.", Ipv4Addr::new(3, 3, 3, 3), 300);

        cache.insert(key("one.com."), &r1);
        cache.insert(key("two.com."), &r2);
        assert_eq!(cache.len(), 2);

        // This should evict the entry with the lowest remaining TTL (one.com, 100s)
        cache.insert(key("three.com."), &r3);
        assert_eq!(cache.len(), 2);
        assert!(cache.lookup(&key("one.com.")).is_none());
        assert!(cache.lookup(&key("three.com.")).is_some());
    }

    #[test]
    fn shared_cache_across_threads() {
        let cache = new_shared_cache(100, 0, 300, false, 0.1);

        let response = make_response("test.com.", Ipv4Addr::new(1, 2, 3, 4), 60);
        {
            let mut c = cache.write().unwrap();
            c.insert(key("test.com."), &response);
        }
        {
            let mut c = cache.write().unwrap();
            assert!(c.lookup(&key("test.com.")).is_some());
        }
    }

    #[test]
    fn min_ttl_floor_applied() {
        // min_ttl = 300s, response TTL = 60s → effective TTL should be 300s
        let mut cache = DnsCache::new(100, 300, 300, false, 0.1);
        let response = make_response("short-ttl.com.", Ipv4Addr::new(1, 2, 3, 4), 60);
        cache.insert(key("short-ttl.com."), &response);

        let lookup = cache.lookup(&key("short-ttl.com.")).unwrap();
        // remaining TTL should be close to 300s, not 60s
        assert!(lookup.remaining_ttl.as_secs() >= 290);
    }

    #[test]
    fn negative_caching() {
        let mut cache = DnsCache::new(100, 0, 300, false, 0.1);
        let response = make_nxdomain_response("doesnotexist.com.");
        let k = key("doesnotexist.com.");

        cache.insert_negative(k.clone(), &response);
        assert_eq!(cache.len(), 1);

        let lookup = cache.lookup(&k).unwrap();
        assert!(!lookup.bytes.is_empty());
        assert!(lookup.remaining_ttl.as_secs() >= 290);
    }

    #[test]
    fn negative_caching_disabled_when_zero() {
        let mut cache = DnsCache::new(100, 0, 0, false, 0.1);
        let response = make_nxdomain_response("doesnotexist.com.");

        cache.insert_negative(key("doesnotexist.com."), &response);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn prefetch_flag_set_near_expiry() {
        // Create cache with prefetch enabled, threshold 0.5 (50%)
        let mut cache = DnsCache::new(100, 0, 300, true, 0.5);
        // TTL of 1 second so it'll be below threshold almost immediately
        let response = make_response("prefetch.com.", Ipv4Addr::new(1, 2, 3, 4), 1);
        cache.insert(key("prefetch.com."), &response);

        // Sleep briefly so remaining TTL drops below 50%
        std::thread::sleep(std::time::Duration::from_millis(600));

        let lookup = cache.lookup(&key("prefetch.com."));
        assert!(lookup.is_some());
        assert!(lookup.unwrap().needs_prefetch);
    }

    #[test]
    fn prefetch_not_set_for_negative_entries() {
        let mut cache = DnsCache::new(100, 0, 1, true, 0.9);
        let response = make_nxdomain_response("neg.com.");
        cache.insert_negative(key("neg.com."), &response);

        let lookup = cache.lookup(&key("neg.com.")).unwrap();
        assert!(!lookup.needs_prefetch);
    }
}
