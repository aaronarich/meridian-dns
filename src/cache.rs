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
    /// How long the entry is valid
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() >= self.ttl
    }

    fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.inserted_at.elapsed())
    }
}

/// TTL-aware in-memory DNS cache
#[derive(Debug)]
pub struct DnsCache {
    entries: HashMap<CacheKey, CacheEntry>,
    max_entries: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Store a DNS response in the cache.
    /// Extracts TTL from answer records, or from SOA in the authority section
    /// for negative responses (NXDOMAIN/NODATA). Skips caching if TTL is 0.
    pub fn insert(&mut self, key: CacheKey, response: &Message, min_ttl_floor: u32) {
        // Find the minimum TTL from answer records
        let min_ttl = response
            .answers()
            .iter()
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

        if min_ttl == 0 {
            return; // Don't cache zero-TTL responses
        }

        let effective_ttl = min_ttl.max(min_ttl_floor);

        // Evict expired entries if we're at capacity
        if self.entries.len() >= self.max_entries {
            self.evict_expired();
        }

        // If still at capacity, evict the entry closest to expiry
        if self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }

        let serialized = match response.to_vec() {
            Ok(v) => v,
            Err(_) => return,
        };

        self.entries.insert(
            key,
            CacheEntry {
                response: serialized,
                inserted_at: Instant::now(),
                ttl: Duration::from_secs(effective_ttl as u64),
            },
        );
    }

    /// Look up a cached response. Returns None if not found or expired.
    /// The returned bytes are the serialized DNS message (caller should fix the ID).
    pub fn lookup(&mut self, key: &CacheKey) -> Option<(Vec<u8>, Duration)> {
        let entry = self.entries.get(key)?;

        if entry.is_expired() {
            self.entries.remove(key);
            return None;
        }

        let remaining = entry.remaining_ttl();
        Some((entry.response.clone(), remaining))
    }

    /// Number of entries currently in the cache (including possibly expired ones)
    pub fn len(&self) -> usize {
        self.entries.len()
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

pub fn new_shared_cache(max_entries: usize) -> SharedCache {
    Arc::new(RwLock::new(DnsCache::new(max_entries)))
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

    fn key(domain: &str) -> CacheKey {
        CacheKey {
            name: domain.to_lowercase(),
            record_type: RecordType::A,
        }
    }

    #[test]
    fn insert_and_lookup() {
        let mut cache = DnsCache::new(100);
        let response = make_response("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300);
        let k = key("example.com.");

        cache.insert(k.clone(), &response, 0);
        assert_eq!(cache.len(), 1);

        let result = cache.lookup(&k);
        assert!(result.is_some());

        let (bytes, remaining) = result.unwrap();
        assert!(!bytes.is_empty());
        assert!(remaining.as_secs() > 0);
    }

    #[test]
    fn zero_ttl_not_cached() {
        let mut cache = DnsCache::new(100);
        let response = make_response("example.com.", Ipv4Addr::new(1, 2, 3, 4), 0);
        cache.insert(key("example.com."), &response, 0);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn miss_returns_none() {
        let mut cache = DnsCache::new(100);
        assert!(cache.lookup(&key("nonexistent.com.")).is_none());
    }

    #[test]
    fn eviction_at_capacity() {
        let mut cache = DnsCache::new(2);

        let r1 = make_response("one.com.", Ipv4Addr::new(1, 1, 1, 1), 100);
        let r2 = make_response("two.com.", Ipv4Addr::new(2, 2, 2, 2), 200);
        let r3 = make_response("three.com.", Ipv4Addr::new(3, 3, 3, 3), 300);

        cache.insert(key("one.com."), &r1, 0);
        cache.insert(key("two.com."), &r2, 0);
        assert_eq!(cache.len(), 2);

        // This should evict the entry with the lowest remaining TTL (one.com, 100s)
        cache.insert(key("three.com."), &r3, 0);
        assert_eq!(cache.len(), 2);
        assert!(cache.lookup(&key("one.com.")).is_none());
        assert!(cache.lookup(&key("three.com.")).is_some());
    }

    #[test]
    fn shared_cache_across_threads() {
        let cache = new_shared_cache(100);

        let response = make_response("test.com.", Ipv4Addr::new(1, 2, 3, 4), 60);
        {
            let mut c = cache.write().unwrap();
            c.insert(key("test.com."), &response, 0);
        }
        {
            let mut c = cache.write().unwrap();
            assert!(c.lookup(&key("test.com.")).is_some());
        }
    }
}
