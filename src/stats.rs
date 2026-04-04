use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// How a query was resolved
#[derive(Debug, Clone)]
pub enum ResolutionMethod {
    Cache,
    Recursive,
    Forwarding,
    Blocked,
    Graylisted,
}

impl std::fmt::Display for ResolutionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolutionMethod::Cache => write!(f, "cache"),
            ResolutionMethod::Recursive => write!(f, "recursive"),
            ResolutionMethod::Forwarding => write!(f, "forwarding"),
            ResolutionMethod::Blocked => write!(f, "blocked"),
            ResolutionMethod::Graylisted => write!(f, "graylisted"),
        }
    }
}

/// A single logged query
#[derive(Debug, Clone)]
pub struct QueryLogEntry {
    pub domain: String,
    pub record_type: String,
    pub latency_ms: f64,
    pub method: ResolutionMethod,
    pub dnssec: DnssecStatus,
    pub timestamp: Instant,
}

/// DNSSEC validation status for a query
#[derive(Debug, Clone)]
pub enum DnssecStatus {
    Secure,
    Insecure,
    Bogus,
    Skipped,
}

impl std::fmt::Display for DnssecStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnssecStatus::Secure => write!(f, "secure"),
            DnssecStatus::Insecure => write!(f, "insecure"),
            DnssecStatus::Bogus => write!(f, "bogus"),
            DnssecStatus::Skipped => write!(f, "skipped"),
        }
    }
}

/// Shared resolver statistics
#[derive(Debug)]
pub struct ResolverStats {
    pub start_time: Instant,
    pub total_queries: u64,
    pub cache_hits: u64,
    pub blocked_queries: u64,
    pub forwarded_queries: u64,
    pub recursive_queries: u64,
    pub graylisted_queries: u64,
    pub recent_queries: VecDeque<QueryLogEntry>,
    pub queries_per_second: VecDeque<(Instant, u64)>,
    /// Rolling 24-hour query history in 10-minute buckets
    pub query_history: VecDeque<QueryBucket>,
}

const MAX_RECENT_QUERIES: usize = 100;
const MAX_QPS_SAMPLES: usize = 60;
const BUCKET_DURATION_SECS: u64 = 600; // 10 minutes
const MAX_BUCKETS: usize = 144; // 24 hours at 10-minute intervals

/// A time bucket tracking query counts by resolution method
#[derive(Debug, Clone)]
pub struct QueryBucket {
    pub window_start: Instant,
    pub cache: u64,
    pub recursive: u64,
    pub forwarded: u64,
    pub blocked: u64,
    pub graylisted: u64,
}

impl QueryBucket {
    fn new(window_start: Instant) -> Self {
        Self {
            window_start,
            cache: 0,
            recursive: 0,
            forwarded: 0,
            blocked: 0,
            graylisted: 0,
        }
    }

    pub fn total(&self) -> u64 {
        self.cache + self.recursive + self.forwarded + self.blocked + self.graylisted
    }

    fn record(&mut self, method: &ResolutionMethod) {
        match method {
            ResolutionMethod::Cache => self.cache += 1,
            ResolutionMethod::Recursive => self.recursive += 1,
            ResolutionMethod::Forwarding => self.forwarded += 1,
            ResolutionMethod::Blocked => self.blocked += 1,
            ResolutionMethod::Graylisted => self.graylisted += 1,
        }
    }

    fn is_current(&self) -> bool {
        self.window_start.elapsed() < Duration::from_secs(BUCKET_DURATION_SECS)
    }
}

impl ResolverStats {
    pub fn new() -> Self {
        let now = Instant::now();
        let mut query_history = VecDeque::with_capacity(MAX_BUCKETS);
        query_history.push_back(QueryBucket::new(now));

        Self {
            start_time: now,
            total_queries: 0,
            cache_hits: 0,
            blocked_queries: 0,
            forwarded_queries: 0,
            recursive_queries: 0,
            graylisted_queries: 0,
            recent_queries: VecDeque::with_capacity(MAX_RECENT_QUERIES),
            queries_per_second: VecDeque::with_capacity(MAX_QPS_SAMPLES),
            query_history,
        }
    }

    pub fn record_query(&mut self, entry: QueryLogEntry) {
        self.total_queries += 1;
        match entry.method {
            ResolutionMethod::Cache => self.cache_hits += 1,
            ResolutionMethod::Blocked => self.blocked_queries += 1,
            ResolutionMethod::Forwarding => self.forwarded_queries += 1,
            ResolutionMethod::Recursive => self.recursive_queries += 1,
            ResolutionMethod::Graylisted => self.graylisted_queries += 1,
        }

        // Update query history bucket
        self.ensure_current_bucket();
        if let Some(bucket) = self.query_history.back_mut() {
            bucket.record(&entry.method);
        }

        if self.recent_queries.len() >= MAX_RECENT_QUERIES {
            self.recent_queries.pop_front();
        }
        self.recent_queries.push_back(entry);
    }

    /// Ensure the most recent bucket is current; rotate if needed
    fn ensure_current_bucket(&mut self) {
        let needs_new = self
            .query_history
            .back()
            .map(|b| !b.is_current())
            .unwrap_or(true);

        if needs_new {
            let now = Instant::now();
            self.query_history.push_back(QueryBucket::new(now));
            // Trim to 24 hours
            while self.query_history.len() > MAX_BUCKETS {
                self.query_history.pop_front();
            }
        }
    }

    pub fn cache_hit_rate(&self) -> f64 {
        if self.total_queries == 0 {
            return 0.0;
        }
        self.cache_hits as f64 / self.total_queries as f64 * 100.0
    }
}

pub type SharedStats = Arc<RwLock<ResolverStats>>;

pub fn new_shared_stats() -> SharedStats {
    Arc::new(RwLock::new(ResolverStats::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_count() {
        let stats = new_shared_stats();
        {
            let mut s = stats.write().unwrap();
            s.record_query(QueryLogEntry {
                domain: "example.com".to_string(),
                record_type: "A".to_string(),
                latency_ms: 12.5,
                method: ResolutionMethod::Forwarding,
                dnssec: DnssecStatus::Skipped,
                timestamp: Instant::now(),
            });
            s.record_query(QueryLogEntry {
                domain: "blocked.com".to_string(),
                record_type: "A".to_string(),
                latency_ms: 0.1,
                method: ResolutionMethod::Blocked,
                dnssec: DnssecStatus::Skipped,
                timestamp: Instant::now(),
            });
            s.record_query(QueryLogEntry {
                domain: "example.com".to_string(),
                record_type: "A".to_string(),
                latency_ms: 0.2,
                method: ResolutionMethod::Cache,
                dnssec: DnssecStatus::Skipped,
                timestamp: Instant::now(),
            });
        }
        let s = stats.read().unwrap();
        assert_eq!(s.total_queries, 3);
        assert_eq!(s.cache_hits, 1);
        assert_eq!(s.blocked_queries, 1);
        assert_eq!(s.forwarded_queries, 1);
        assert_eq!(s.recent_queries.len(), 3);
        assert!((s.cache_hit_rate() - 33.33).abs() < 0.5);
    }

    #[test]
    fn query_history_bucketing() {
        let stats = new_shared_stats();
        {
            let mut s = stats.write().unwrap();
            // Record several queries of different types
            for _ in 0..5 {
                s.record_query(QueryLogEntry {
                    domain: "example.com".to_string(),
                    record_type: "A".to_string(),
                    latency_ms: 1.0,
                    method: ResolutionMethod::Cache,
                    dnssec: DnssecStatus::Skipped,
                    timestamp: Instant::now(),
                });
            }
            for _ in 0..3 {
                s.record_query(QueryLogEntry {
                    domain: "blocked.com".to_string(),
                    record_type: "A".to_string(),
                    latency_ms: 0.1,
                    method: ResolutionMethod::Blocked,
                    dnssec: DnssecStatus::Skipped,
                    timestamp: Instant::now(),
                });
            }
        }
        let s = stats.read().unwrap();
        assert_eq!(s.query_history.len(), 1); // all in same bucket
        let bucket = s.query_history.back().unwrap();
        assert_eq!(bucket.cache, 5);
        assert_eq!(bucket.blocked, 3);
        assert_eq!(bucket.total(), 8);
    }

    #[test]
    fn empty_stats() {
        let stats = new_shared_stats();
        let s = stats.read().unwrap();
        assert_eq!(s.total_queries, 0);
        assert_eq!(s.cache_hit_rate(), 0.0);
    }
}
