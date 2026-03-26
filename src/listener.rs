use std::net::SocketAddr;
use std::time::Instant;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::stats::{QueryLogEntry, ResolutionMethod, SharedStats};

/// Start both UDP and TCP listeners
pub async fn start(addr: SocketAddr, stats: SharedStats) -> Result<(), Box<dyn std::error::Error>> {
    let udp_stats = stats.clone();
    let tcp_stats = stats;

    let udp_handle = tokio::spawn(listen_udp(addr, udp_stats));
    let tcp_handle = tokio::spawn(listen_tcp(addr, tcp_stats));

    tokio::select! {
        res = udp_handle => {
            error!("UDP listener exited: {:?}", res);
        }
        res = tcp_handle => {
            error!("TCP listener exited: {:?}", res);
        }
    }

    Ok(())
}

async fn listen_udp(addr: SocketAddr, stats: SharedStats) {
    let socket = match UdpSocket::bind(addr).await {
        Ok(s) => {
            info!("UDP listener bound to {addr}");
            s
        }
        Err(e) => {
            error!("failed to bind UDP socket to {addr}: {e}");
            return;
        }
    };

    let mut buf = vec![0u8; 4096];
    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!("UDP recv error: {e}");
                continue;
            }
        };

        let query_start = Instant::now();
        let response = handle_query(&buf[..len], &stats, query_start);

        if let Err(e) = socket.send_to(&response, src).await {
            warn!("UDP send error to {src}: {e}");
        }
    }
}

async fn listen_tcp(addr: SocketAddr, stats: SharedStats) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            info!("TCP listener bound to {addr}");
            l
        }
        Err(e) => {
            error!("failed to bind TCP socket to {addr}: {e}");
            return;
        }
    };

    loop {
        let (stream, src) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => {
                warn!("TCP accept error: {e}");
                continue;
            }
        };

        let stats = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(stream, src, stats).await {
                debug!("TCP connection from {src} ended: {e}");
            }
        });
    }
}

async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    src: SocketAddr,
    stats: SharedStats,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // DNS over TCP: 2-byte length prefix followed by the message
    loop {
        let len = match stream.read_u16().await {
            Ok(l) => l as usize,
            Err(_) => return Ok(()), // connection closed
        };

        if len == 0 || len > 65535 {
            return Ok(());
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        let query_start = Instant::now();
        let response = handle_query(&buf, &stats, query_start);

        let resp_len = (response.len() as u16).to_be_bytes();
        stream.write_all(&resp_len).await?;
        stream.write_all(&response).await?;

        debug!("TCP response sent to {src}, {} bytes", response.len());
    }
}

/// Parse a DNS query, log it to stats, and return a response.
/// For now, returns SERVFAIL since we have no resolver yet.
fn handle_query(buf: &[u8], stats: &SharedStats, query_start: Instant) -> Vec<u8> {
    let request = match Message::from_bytes(buf) {
        Ok(msg) => msg,
        Err(e) => {
            warn!("failed to parse DNS message: {e}");
            return build_formerr(0);
        }
    };

    let id = request.id();

    // Extract query info for logging
    let (domain, record_type) = if let Some(query) = request.queries().first() {
        (query.name().to_string(), query.query_type().to_string())
    } else {
        ("(empty)".to_string(), "?".to_string())
    };

    debug!(domain = %domain, rtype = %record_type, "received query");

    // Build SERVFAIL response (no resolver yet)
    let response_bytes = build_servfail(id, &request);

    let latency_ms = query_start.elapsed().as_secs_f64() * 1000.0;

    // Log to stats
    if let Ok(mut s) = stats.write() {
        s.record_query(QueryLogEntry {
            domain,
            record_type,
            latency_ms,
            method: ResolutionMethod::Forwarding, // placeholder
            timestamp: query_start,
        });
    }

    response_bytes
}

fn build_servfail(id: u16, request: &Message) -> Vec<u8> {
    let mut response = Message::new();
    response.set_id(id);
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(ResponseCode::ServFail);
    response.set_recursion_available(true);
    response.set_recursion_desired(request.recursion_desired());

    // Echo back the question section
    for query in request.queries() {
        response.add_query(query.clone());
    }

    response.to_vec().unwrap_or_default()
}

fn build_formerr(id: u16) -> Vec<u8> {
    let mut response = Message::new();
    response.set_id(id);
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(ResponseCode::FormErr);
    response.to_vec().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::new_shared_stats;
    use hickory_proto::op::{Query, MessageType};
    use hickory_proto::rr::{Name, RecordType};

    fn build_test_query(domain: &str) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(1234);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);

        let name = Name::from_ascii(domain).unwrap();
        let query = Query::query(name, RecordType::A);
        msg.add_query(query);

        msg.to_vec().unwrap()
    }

    #[test]
    fn handle_valid_query_returns_servfail() {
        let stats = new_shared_stats();
        let query_bytes = build_test_query("example.com.");
        let response_bytes = handle_query(&query_bytes, &stats, Instant::now());

        let response = Message::from_bytes(&response_bytes).unwrap();
        assert_eq!(response.id(), 1234);
        assert_eq!(response.response_code(), ResponseCode::ServFail);
        assert!(response.header().recursion_available());
        assert_eq!(response.queries().len(), 1);

        let s = stats.read().unwrap();
        assert_eq!(s.total_queries, 1);
    }

    #[test]
    fn handle_garbage_returns_formerr() {
        let stats = new_shared_stats();
        let response_bytes = handle_query(&[0xFF, 0x00], &stats, Instant::now());

        let response = Message::from_bytes(&response_bytes).unwrap();
        assert_eq!(response.response_code(), ResponseCode::FormErr);

        // Garbage should not be recorded as a query
        let s = stats.read().unwrap();
        assert_eq!(s.total_queries, 0);
    }

    #[test]
    fn response_echoes_question_section() {
        let stats = new_shared_stats();
        let query_bytes = build_test_query("test.org.");
        let response_bytes = handle_query(&query_bytes, &stats, Instant::now());

        let response = Message::from_bytes(&response_bytes).unwrap();
        assert_eq!(response.queries().first().unwrap().name().to_string(), "test.org.");
    }
}
