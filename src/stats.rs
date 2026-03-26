use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// How a query was resolved
#[derive(Debug, Clone)]
pub enum ResolutionMethod {
    Cache,
    Recursive,
    Forwarding,
    Blocked,
}

impl std::fmt::Display for ResolutionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolutionMethod::Cache => write!(f, "cache"),
            ResolutionMethod::Recursive => write!(f, "recursive"),
            ResolutionMethod::Forwarding => write!(f, "forwarding"),
            ResolutionMethod::Blocked => write!(f, "blocked"),
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
    pub timestamp: Instant,
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
    pub recent_queries: VecDeque<QueryLogEntry>,
    pub queries_per_second: VecDeque<(Instant, u64)>,
}

const MAX_RECENT_QUERIES: usize = 100;
const MAX_QPS_SAMPLES: usize = 60;

impl ResolverStats {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_queries: 0,
            cache_hits: 0,
            blocked_queries: 0,
            forwarded_queries: 0,
            recursive_queries: 0,
            recent_queries: VecDeque::with_capacity(MAX_RECENT_QUERIES),
            queries_per_second: VecDeque::with_capacity(MAX_QPS_SAMPLES),
        }
    }

    pub fn record_query(&mut self, entry: QueryLogEntry) {
        self.total_queries += 1;
        match entry.method {
            ResolutionMethod::Cache => self.cache_hits += 1,
            ResolutionMethod::Blocked => self.blocked_queries += 1,
            ResolutionMethod::Forwarding => self.forwarded_queries += 1,
            ResolutionMethod::Recursive => self.recursive_queries += 1,
        }
        if self.recent_queries.len() >= MAX_RECENT_QUERIES {
            self.recent_queries.pop_front();
        }
        self.recent_queries.push_back(entry);
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
                timestamp: Instant::now(),
            });
            s.record_query(QueryLogEntry {
                domain: "blocked.com".to_string(),
                record_type: "A".to_string(),
                latency_ms: 0.1,
                method: ResolutionMethod::Blocked,
                timestamp: Instant::now(),
            });
            s.record_query(QueryLogEntry {
                domain: "example.com".to_string(),
                record_type: "A".to_string(),
                latency_ms: 0.2,
                method: ResolutionMethod::Cache,
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
    fn empty_stats() {
        let stats = new_shared_stats();
        let s = stats.read().unwrap();
        assert_eq!(s.total_queries, 0);
        assert_eq!(s.cache_hit_rate(), 0.0);
    }
}
