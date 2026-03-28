use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::cache::{CacheKey, SharedCache};
use crate::config::CacheConfig;

const MAX_RECURSION_DEPTH: usize = 20;
const MAX_CNAME_CHAIN: usize = 10;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Root hints — hardcoded root server addresses
/// These are the IANA root name servers
const ROOT_SERVERS: &[(char, Ipv4Addr)] = &[
    ('a', Ipv4Addr::new(198, 41, 0, 4)),
    ('b', Ipv4Addr::new(170, 247, 170, 2)),
    ('c', Ipv4Addr::new(192, 33, 4, 12)),
    ('d', Ipv4Addr::new(199, 7, 91, 13)),
    ('e', Ipv4Addr::new(192, 203, 230, 10)),
    ('f', Ipv4Addr::new(192, 5, 5, 241)),
    ('g', Ipv4Addr::new(192, 112, 36, 4)),
    ('h', Ipv4Addr::new(198, 97, 190, 53)),
    ('i', Ipv4Addr::new(192, 36, 148, 17)),
    ('j', Ipv4Addr::new(192, 58, 128, 30)),
    ('k', Ipv4Addr::new(193, 0, 14, 129)),
    ('l', Ipv4Addr::new(199, 7, 83, 42)),
    ('m', Ipv4Addr::new(202, 12, 27, 33)),
];

#[derive(Debug, thiserror::Error)]
pub enum RecursiveError {
    #[error("max recursion depth exceeded")]
    MaxDepth,
    #[error("max CNAME chain exceeded")]
    MaxCnameChain,
    #[error("no nameservers available")]
    NoNameservers,
    #[error("all nameservers failed for {zone}")]
    AllNameserversFailed { zone: String },
    #[error("network error: {0}")]
    Network(String),
}

/// Recursively resolve a DNS query starting from root servers
pub async fn resolve(
    request: &Message,
    cache: &SharedCache,
    cache_config: &CacheConfig,
) -> Result<Message, RecursiveError> {
    let query = request
        .queries()
        .first()
        .ok_or(RecursiveError::NoNameservers)?;

    let name = query.name().clone();
    let record_type = query.query_type();

    // Follow CNAME chains
    let mut current_name = name;
    let mut cname_count = 0;
    let mut accumulated_cnames: Vec<hickory_proto::rr::Record> = Vec::new();

    loop {
        let result = resolve_name(&current_name, record_type, cache, cache_config).await?;

        // Check if we got actual answers for the requested type
        let has_target_answers = result
            .answers()
            .iter()
            .any(|r| r.record_type() == record_type);

        if has_target_answers {
            // Build final response with any CNAME chain + final answers
            let mut response = Message::new();
            response.set_id(request.id());
            response.set_message_type(MessageType::Response);
            response.set_op_code(OpCode::Query);
            response.set_response_code(result.response_code());
            response.set_recursion_available(true);
            response.set_recursion_desired(request.recursion_desired());

            for q in request.queries() {
                response.add_query(q.clone());
            }

            // Add CNAME chain first
            for cname_record in &accumulated_cnames {
                response.add_answer(cname_record.clone());
            }

            // Add actual answers
            for answer in result.answers() {
                response.add_answer(answer.clone());
            }

            return Ok(response);
        }

        // Check for CNAME redirect
        let cname_target = result
            .answers()
            .iter()
            .find(|r| r.record_type() == RecordType::CNAME)
            .and_then(|r| {
                if let RData::CNAME(cname) = r.data() {
                    Some(cname.0.clone())
                } else {
                    None
                }
            });

        if let Some(target) = cname_target {
            cname_count += 1;
            if cname_count > MAX_CNAME_CHAIN {
                return Err(RecursiveError::MaxCnameChain);
            }

            // Save the CNAME record
            for r in result.answers() {
                if r.record_type() == RecordType::CNAME {
                    accumulated_cnames.push(r.clone());
                }
            }

            debug!(from = %current_name, to = %target, "following CNAME");
            current_name = target;
            continue;
        }

        // No answers and no CNAME — return the response as-is (NXDOMAIN, etc.)
        let mut response = Message::new();
        response.set_id(request.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_response_code(result.response_code());
        response.set_recursion_available(true);
        response.set_recursion_desired(request.recursion_desired());

        for q in request.queries() {
            response.add_query(q.clone());
        }
        for ns in result.name_servers() {
            response.add_name_server(ns.clone());
        }

        return Ok(response);
    }
}

/// Try to look up a record from the shared cache.
/// Returns the deserialized Message if found and not expired.
fn cache_lookup(cache: &SharedCache, name: &Name, record_type: RecordType) -> Option<Message> {
    let key = CacheKey {
        name: name.to_string().to_lowercase(),
        record_type,
    };
    let (bytes, _remaining) = cache.write().ok()?.lookup(&key)?;
    Message::from_bytes(&bytes).ok()
}

/// Store a response in the shared cache, keyed by name + record type.
fn cache_store(cache: &SharedCache, name: &Name, record_type: RecordType, response: &Message, min_ttl: u32) {
    let key = CacheKey {
        name: name.to_string().to_lowercase(),
        record_type,
    };
    if let Ok(mut c) = cache.write() {
        c.insert(key, response, min_ttl);
    }
}

/// Cache all useful records from a referral response (NS records, glue A/AAAA records)
fn cache_referral(cache: &SharedCache, response: &Message, min_ttl: u32) {
    // Cache glue A records from the additional section
    for additional in response.additionals() {
        let rtype = additional.record_type();
        if rtype == RecordType::A || rtype == RecordType::AAAA {
            // Build a minimal response message for this glue record
            let mut glue_msg = Message::new();
            glue_msg.set_message_type(MessageType::Response);
            glue_msg.set_response_code(ResponseCode::NoError);
            glue_msg.add_answer(additional.clone());

            let key = CacheKey {
                name: additional.name().to_string().to_lowercase(),
                record_type: rtype,
            };
            if let Ok(mut c) = cache.write() {
                c.insert(key, &glue_msg, min_ttl);
            }
        }
    }
}

/// Resolve a specific name by walking from root servers down, using the cache
/// for intermediate NS/glue lookups.
async fn resolve_name(
    name: &Name,
    record_type: RecordType,
    cache: &SharedCache,
    cache_config: &CacheConfig,
) -> Result<Message, RecursiveError> {
    let min_ttl = cache_config.min_ttl;

    // Check if we already have the final answer cached
    if let Some(cached) = cache_lookup(cache, name, record_type) {
        if !cached.answers().is_empty() || cached.response_code() == ResponseCode::NXDomain {
            debug!(name = %name, rtype = ?record_type, "recursive: cache hit for final answer");
            return Ok(cached);
        }
    }

    // Start with root servers
    let mut nameservers: Vec<SocketAddr> = ROOT_SERVERS
        .iter()
        .map(|(_, ip)| SocketAddr::new((*ip).into(), 53))
        .collect();

    let mut depth = 0;

    loop {
        depth += 1;
        if depth > MAX_RECURSION_DEPTH {
            return Err(RecursiveError::MaxDepth);
        }

        let response = query_nameservers(name, record_type, &nameservers).await?;

        // If we got an authoritative answer or a definitive response, cache and return it
        if response.header().authoritative()
            || !response.answers().is_empty()
            || response.response_code() == ResponseCode::NXDomain
        {
            // Cache the final answer
            cache_store(cache, name, record_type, &response, min_ttl);
            return Ok(response);
        }

        // If we got a NOERROR with no answers and no referrals, return it
        if response.name_servers().is_empty() && response.additionals().is_empty() {
            return Ok(response);
        }

        // Cache all glue/NS records from the referral
        cache_referral(cache, &response, min_ttl);

        // Extract NS referral — get IP addresses from the additional section
        let mut next_nameservers: Vec<SocketAddr> = Vec::new();

        // First, try to find glue records (A records in additional section)
        for additional in response.additionals() {
            if let RData::A(addr) = additional.data() {
                next_nameservers.push(SocketAddr::new(addr.0.into(), 53));
            }
        }

        // If we got referral nameservers with glue, use them
        if !next_nameservers.is_empty() {
            debug!(
                name = %name,
                depth = depth,
                ns_count = next_nameservers.len(),
                "following referral"
            );
            nameservers = next_nameservers;
            continue;
        }

        // If we have NS records but no glue, we need to resolve the NS names
        let ns_names: Vec<Name> = response
            .name_servers()
            .iter()
            .filter_map(|r| {
                if let RData::NS(ns) = r.data() {
                    Some(ns.0.clone())
                } else {
                    None
                }
            })
            .collect();

        if ns_names.is_empty() {
            // No more referrals, return what we have
            return Ok(response);
        }

        // Resolve the NS names — check cache first, then query
        let mut resolved_any = false;
        for ns_name in ns_names.iter().take(3) {
            // Check cache for the NS address first
            if let Some(cached_ns) = cache_lookup(cache, ns_name, RecordType::A) {
                for answer in cached_ns.answers() {
                    if let RData::A(addr) = answer.data() {
                        next_nameservers.push(SocketAddr::new(addr.0.into(), 53));
                        resolved_any = true;
                    }
                }
                if resolved_any {
                    debug!(ns = %ns_name, "resolved NS address from cache");
                    break;
                }
            }

            // Fall back to querying current nameservers
            debug!(ns = %ns_name, "resolving nameserver address via network");
            if let Ok(ns_response) =
                query_nameservers(ns_name, RecordType::A, &nameservers).await
            {
                // Cache the NS address for future use
                cache_store(cache, ns_name, RecordType::A, &ns_response, min_ttl);

                for answer in ns_response.answers() {
                    if let RData::A(addr) = answer.data() {
                        next_nameservers.push(SocketAddr::new(addr.0.into(), 53));
                        resolved_any = true;
                    }
                }
            }
            if resolved_any {
                break;
            }
        }

        if next_nameservers.is_empty() {
            return Err(RecursiveError::AllNameserversFailed {
                zone: name.to_string(),
            });
        }

        nameservers = next_nameservers;
    }
}

/// Send a query to a list of nameservers, returning the first successful response
async fn query_nameservers(
    name: &Name,
    record_type: RecordType,
    nameservers: &[SocketAddr],
) -> Result<Message, RecursiveError> {
    if nameservers.is_empty() {
        return Err(RecursiveError::NoNameservers);
    }

    let query_msg = build_query(name, record_type);
    let query_bytes = query_msg
        .to_vec()
        .map_err(|e| RecursiveError::Network(e.to_string()))?;

    // Try each nameserver
    for &ns_addr in nameservers.iter().take(4) {
        match send_udp_query(&query_bytes, ns_addr).await {
            Ok(response) => {
                if response.response_code() == ResponseCode::ServFail {
                    continue; // Try next NS
                }
                return Ok(response);
            }
            Err(e) => {
                debug!(ns = %ns_addr, error = %e, "nameserver query failed");
                continue;
            }
        }
    }

    Err(RecursiveError::AllNameserversFailed {
        zone: name.to_string(),
    })
}

/// Send a raw UDP DNS query and wait for a response
async fn send_udp_query(
    query_bytes: &[u8],
    server: SocketAddr,
) -> Result<Message, RecursiveError> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| RecursiveError::Network(format!("bind: {e}")))?;

    socket
        .send_to(query_bytes, server)
        .await
        .map_err(|e| RecursiveError::Network(format!("send to {server}: {e}")))?;

    let mut buf = vec![0u8; 4096];

    let len = tokio::time::timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
        .await
        .map_err(|_| RecursiveError::Network(format!("timeout from {server}")))?
        .map_err(|e| RecursiveError::Network(format!("recv from {server}: {e}")))?;

    Message::from_bytes(&buf[..len])
        .map_err(|e| RecursiveError::Network(format!("parse response from {server}: {e}")))
}

/// Build a simple DNS query message
fn build_query(name: &Name, record_type: RecordType) -> Message {
    let mut msg = Message::new();
    msg.set_id(rand_id());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false); // We're doing the recursion ourselves

    let query = Query::query(name.clone(), record_type);
    msg.add_query(query);

    msg
}

fn rand_id() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u8(0);
    h.finish() as u16
}
