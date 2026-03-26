pub mod forwarding;
pub mod recursive;

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use crate::blocklist::SharedBlocklist;
use crate::cache::{CacheKey, SharedCache};
use crate::config::{Config, ResolverMode, UpstreamServer};
use crate::stats::ResolutionMethod;

/// Result of resolving a query
pub struct ResolveResult {
    pub response: Message,
    pub method: ResolutionMethod,
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
            });
        }
    }

    // Resolve based on mode
    let response = match config.mode {
        ResolverMode::Forwarding => {
            forward_query(request, &config.upstream.servers).await?
        }
        ResolverMode::Recursive => {
            // Fall back to forwarding for now (recursive not yet implemented)
            forward_query(request, &config.upstream.servers).await?
        }
    };

    let method = match config.mode {
        ResolverMode::Forwarding => ResolutionMethod::Forwarding,
        ResolverMode::Recursive => ResolutionMethod::Recursive,
    };

    // Cache the response if it has answers
    if !response.answers().is_empty() {
        cache.write().unwrap().insert(cache_key, &response);
    }

    Ok(ResolveResult { response, method })
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

        // Return 0.0.0.0 for A queries, empty for others
        if query.query_type() == RecordType::A {
            let record = Record::from_rdata(
                query.name().clone(),
                0, // TTL 0 so it's never cached
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
