pub mod forwarding;
pub mod recursive;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;

use crate::cache::{CacheKey, SharedCache};
use crate::config::{Config, ResolverMode, UpstreamServer};
use crate::stats::ResolutionMethod;

/// Result of resolving a query
pub struct ResolveResult {
    pub response: Message,
    pub method: ResolutionMethod,
}

/// Try to resolve a query: check cache first, then forward/recurse
pub async fn resolve(
    request: &Message,
    config: &Config,
    cache: &SharedCache,
) -> Result<ResolveResult, Box<dyn std::error::Error + Send + Sync>> {
    let query = match request.queries().first() {
        Some(q) => q,
        None => {
            return Err("no question in query".into());
        }
    };

    let cache_key = CacheKey {
        name: query.name().to_string().to_lowercase(),
        record_type: query.query_type(),
    };

    // Check cache
    if let Some((cached_bytes, _remaining_ttl)) = cache.write().unwrap().lookup(&cache_key) {
        if let Ok(mut cached_msg) = Message::from_bytes(&cached_bytes) {
            // Fix the ID to match the incoming request
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

async fn forward_query(
    request: &Message,
    upstreams: &[UpstreamServer],
) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
    let mut response = forwarding::forward(request, upstreams).await?;
    // Ensure the response ID matches the request
    response.set_id(request.id());
    Ok(response)
}
