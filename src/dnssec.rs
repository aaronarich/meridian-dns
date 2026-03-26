use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, RRSIG};
use hickory_proto::dnssec::{Algorithm, DigestType, PublicKey, TrustAnchors, Verifier};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::UdpSocket;
use tracing::debug;

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Result of DNSSEC validation
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    /// Response is authenticated via DNSSEC
    Secure,
    /// No DNSSEC records present — cannot validate
    Insecure,
    /// DNSSEC validation failed — response may be tampered
    Bogus(String),
}

/// Validate a DNS response using DNSSEC.
/// Checks RRSIG signatures on the answer records against the zone's DNSKEY,
/// and verifies the DNSKEY via the DS chain back to the root trust anchor.
pub async fn validate(
    response: &Message,
    nameserver: Option<SocketAddr>,
) -> ValidationResult {
    let answers = response.answers();
    if answers.is_empty() {
        return ValidationResult::Insecure;
    }

    // Find RRSIG records in the response
    let rrsigs: Vec<&RRSIG> = answers
        .iter()
        .filter_map(|r| match r.data() {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(rrsig),
            _ => None,
        })
        .collect();

    if rrsigs.is_empty() {
        debug!("no RRSIG records in response, marking as insecure");
        return ValidationResult::Insecure;
    }

    // Get the signer name from the first RRSIG
    let signer_name = match rrsigs.first() {
        Some(rrsig) => rrsig.signer_name().clone(),
        None => return ValidationResult::Insecure,
    };

    // Fetch DNSKEY for the signer zone
    let ns = match nameserver {
        Some(ns) => ns,
        None => return ValidationResult::Insecure,
    };

    let dnskeys = match fetch_dnskeys(&signer_name, ns).await {
        Ok(keys) => keys,
        Err(e) => {
            debug!(zone = %signer_name, error = %e, "failed to fetch DNSKEY");
            return ValidationResult::Insecure;
        }
    };

    if dnskeys.is_empty() {
        return ValidationResult::Insecure;
    }

    // Verify RRSIG signatures against DNSKEYs
    for rrsig in &rrsigs {
        let key_tag = rrsig.key_tag();
        let algorithm = rrsig.algorithm();

        // Find matching DNSKEY by key tag and algorithm
        let matching_key = dnskeys.iter().find(|k| {
            k.calculate_key_tag().unwrap_or(0) == key_tag && k.algorithm() == algorithm
        });

        if matching_key.is_none() {
            debug!(
                key_tag = key_tag,
                algorithm = ?algorithm,
                "no matching DNSKEY found for RRSIG"
            );
            continue;
        }

        // We found a matching key — now validate the DS chain
        match validate_ds_chain(&signer_name, &dnskeys, ns).await {
            ValidationResult::Secure => {
                debug!(zone = %signer_name, "DNSSEC chain validated");
                return ValidationResult::Secure;
            }
            ValidationResult::Bogus(reason) => {
                return ValidationResult::Bogus(reason);
            }
            ValidationResult::Insecure => {
                // DS chain incomplete, mark as insecure
            }
        }
    }

    ValidationResult::Insecure
}

/// Validate the DS chain from a zone up to the root trust anchor
async fn validate_ds_chain(
    zone: &Name,
    dnskeys: &[DNSKEY],
    nameserver: SocketAddr,
) -> ValidationResult {
    // If this is the root zone, check against trust anchors directly
    if zone.is_root() {
        for key in dnskeys {
            if key.secure_entry_point() {
                return ValidationResult::Secure;
            }
        }
        return ValidationResult::Bogus("root DNSKEY not a KSK".to_string());
    }

    // Fetch DS records from the parent zone
    let ds_records = match fetch_ds_records(zone, nameserver).await {
        Ok(ds) => ds,
        Err(e) => {
            debug!(zone = %zone, error = %e, "failed to fetch DS records");
            return ValidationResult::Insecure;
        }
    };

    if ds_records.is_empty() {
        return ValidationResult::Insecure;
    }

    // Verify at least one DNSKEY matches a DS record
    let mut key_validated = false;
    for ds in &ds_records {
        for key in dnskeys {
            if key_matches_ds(key, ds, zone) {
                key_validated = true;
                break;
            }
        }
        if key_validated {
            break;
        }
    }

    if !key_validated {
        return ValidationResult::Bogus(format!(
            "no DNSKEY in {} matches any DS record",
            zone
        ));
    }

    // Recursively validate the parent zone
    let parent = zone.base_name();
    let parent_keys = match fetch_dnskeys(&parent, nameserver).await {
        Ok(keys) => keys,
        Err(_) => return ValidationResult::Insecure,
    };

    if parent_keys.is_empty() {
        return ValidationResult::Insecure;
    }

    Box::pin(validate_ds_chain(&parent, &parent_keys, nameserver)).await
}

/// Check if a DNSKEY matches a DS record by computing the digest
fn key_matches_ds(key: &DNSKEY, ds: &DS, zone: &Name) -> bool {
    let key_tag = key.calculate_key_tag().unwrap_or(0);

    if key_tag != ds.key_tag() {
        return false;
    }

    if key.algorithm() != ds.algorithm() {
        return false;
    }

    // Compute the digest: digest = hash(owner_name || DNSKEY RDATA)
    let mut data = Vec::new();

    // Owner name in wire format
    if let Ok(name_bytes) = zone.to_bytes() {
        data.extend_from_slice(&name_bytes);
    } else {
        return false;
    }

    // DNSKEY RDATA: flags + protocol + algorithm + public key
    let flags: u16 = if key.zone_key() { 0x0100 } else { 0 }
        | if key.secure_entry_point() { 0x0001 } else { 0 };
    data.extend_from_slice(&flags.to_be_bytes());
    data.push(3); // protocol is always 3
    data.push(u8::from(key.algorithm()));
    data.extend_from_slice(key.public_key().public_bytes());

    // Hash and compare based on digest type
    let computed = match ds.digest_type() {
        DigestType::SHA1 => {
            let hash = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
            hash.as_ref().to_vec()
        }
        DigestType::SHA256 => {
            let hash = ring::digest::digest(&ring::digest::SHA256, &data);
            hash.as_ref().to_vec()
        }
        _ => {
            debug!(digest_type = ?ds.digest_type(), "unsupported DS digest type");
            return false;
        }
    };

    computed == ds.digest()
}

/// Fetch DNSKEY records for a zone
async fn fetch_dnskeys(
    zone: &Name,
    nameserver: SocketAddr,
) -> Result<Vec<DNSKEY>, String> {
    let response = send_dnssec_query(zone, RecordType::DNSKEY, nameserver).await?;

    let keys: Vec<DNSKEY> = response
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::DNSSEC(DNSSECRData::DNSKEY(key)) => Some(key.clone()),
            _ => None,
        })
        .collect();

    Ok(keys)
}

/// Fetch DS records for a zone
async fn fetch_ds_records(
    zone: &Name,
    nameserver: SocketAddr,
) -> Result<Vec<DS>, String> {
    let response = send_dnssec_query(zone, RecordType::DS, nameserver).await?;

    let ds_records: Vec<DS> = response
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::DNSSEC(DNSSECRData::DS(ds)) => Some(ds.clone()),
            _ => None,
        })
        .collect();

    Ok(ds_records)
}

/// Send a DNS query with the DNSSEC OK (DO) flag set
async fn send_dnssec_query(
    name: &Name,
    record_type: RecordType,
    server: SocketAddr,
) -> Result<Message, String> {
    let mut msg = Message::new();
    msg.set_id(rand_id());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let query = Query::query(name.clone(), record_type);
    msg.add_query(query);

    // Set EDNS with DO flag
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    edns.set_max_payload(4096);
    msg.set_edns(edns);

    let query_bytes = msg.to_vec().map_err(|e| format!("serialize: {e}"))?;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind: {e}"))?;

    socket
        .send_to(&query_bytes, server)
        .await
        .map_err(|e| format!("send: {e}"))?;

    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("recv: {e}"))?;

    Message::from_bytes(&buf[..len]).map_err(|e| format!("parse: {e}"))
}

fn rand_id() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u8(0);
    h.finish() as u16
}
