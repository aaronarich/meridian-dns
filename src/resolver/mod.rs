pub mod forwarding;
pub mod recursive;

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use crate::blocklist::SharedBlocklist;
use crate::cache::{CacheKey, SharedCache};
use crate::config::{CacheConfig, Config, ResolverMode, UpstreamServer};
use crate::dnssec;
use crate::stats::{DnssecStatus, ResolutionMethod};

/// Result of resolving a query
pub struct ResolveResult {
    pub response: Message,
    pub method: ResolutionMethod,
    pub dnssec: DnssecStatus,
}

/// Try to resolve a query: check blocklist, then cache, then forward/recurse
pub async fn resolve(
    request: &Message,
    config: &Config,
    cache: &SharedCache,
    blocklist: &SharedBlocklist,
) -> Result<ResolveResult, Box<dyn std::error::Error + Send + Sync>> {
    let query = match request.queries().first() {
        Some(q) => q,
        None => {
            return Err("no question in query".into());
        }
    };

    let domain = query.name().to_string();

    // Check blocklist first
    if config.blocklist.enabled {
        if let Ok(bl) = blocklist.read() {
            if bl.is_blocked(&domain) {
                return Ok(ResolveResult {
                    response: build_blocked_response(request),
                    method: ResolutionMethod::Blocked,
                    dnssec: DnssecStatus::Skipped,
                });
            }
        }
    }

    let cache_key = CacheKey {
        name: domain.to_lowercase(),
        record_type: query.query_type(),
    };

    // Check cache
    if let Some((cached_bytes, _remaining_ttl)) = cache.write().unwrap().lookup(&cache_key) {
        if let Ok(mut cached_msg) = Message::from_bytes(&cached_bytes) {
            cached_msg.set_id(request.id());
            return Ok(ResolveResult {
                response: cached_msg,
                method: ResolutionMethod::Cache,
                dnssec: DnssecStatus::Skipped,
            });
        }
    }

    // Resolve based on mode
    let (response, method) = match config.mode {
        ResolverMode::Forwarding => {
            let resp = forward_query(request, &config.upstream.servers).await?;
            (resp, ResolutionMethod::Forwarding)
        }
        ResolverMode::Recursive => {
            match recursive::resolve(request, cache, &config.cache).await {
                Ok(resp) => (resp, ResolutionMethod::Recursive),
                Err(e) => {
                    tracing::warn!(error = %e, domain = %domain, "recursive resolution failed");
                    return Err(e.into());
                }
            }
        }
    };

    // Run DNSSEC validation (non-blocking, best-effort)
    let dnssec_result = dnssec::validate(&response, None).await;
    let dnssec_status = match &dnssec_result {
        dnssec::ValidationResult::Secure => {
            tracing::debug!(domain = %domain, "DNSSEC: secure");
            DnssecStatus::Secure
        }
        dnssec::ValidationResult::Insecure => DnssecStatus::Insecure,
        dnssec::ValidationResult::Bogus(reason) => {
            tracing::warn!(domain = %domain, reason = %reason, "DNSSEC: bogus response");
            DnssecStatus::Bogus
        }
    };

    // Cache the response if it has answers or authority records
    if !response.answers().is_empty() || !response.name_servers().is_empty() {
        cache.write().unwrap().insert(cache_key, &response, config.cache.min_ttl);
    }

    Ok(ResolveResult {
        response,
        method,
        dnssec: dnssec_status,
    })
}

/// Build a response that returns 0.0.0.0 for blocked domains
fn build_blocked_response(request: &Message) -> Message {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(ResponseCode::NoError);
    response.set_recursion_available(true);
    response.set_recursion_desired(request.recursion_desired());

    for query in request.queries() {
        response.add_query(query.clone());

        if query.query_type() == RecordType::A {
            let record = Record::from_rdata(
                query.name().clone(),
                0,
                RData::A(Ipv4Addr::new(0, 0, 0, 0).into()),
            );
            response.add_answer(record);
        }
    }

    response
}

async fn forward_query(
    request: &Message,
    upstreams: &[UpstreamServer],
) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
    let mut response = forwarding::forward(request, upstreams).await?;
    response.set_id(request.id());
    Ok(response)
}
