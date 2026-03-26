use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::{UpstreamProtocol, UpstreamServer};

/// Errors from forwarding resolution
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("no upstream servers configured")]
    NoUpstreams,
    #[error("all upstreams failed")]
    AllFailed,
    #[error("DoT error: {0}")]
    Dot(String),
    #[error("DoH error: {0}")]
    Doh(String),
    #[error("DoQ error: {0}")]
    Doq(String),
    #[error("invalid response from upstream")]
    InvalidResponse,
}

/// Forward a DNS query to the configured upstream servers.
/// Tries each server in order until one succeeds.
pub async fn forward(
    query: &Message,
    upstreams: &[UpstreamServer],
) -> Result<Message, ForwardError> {
    if upstreams.is_empty() {
        return Err(ForwardError::NoUpstreams);
    }

    let query_bytes = query.to_vec().map_err(|e| ForwardError::Dot(e.to_string()))?;

    for upstream in upstreams {
        debug!(name = %upstream.name, protocol = ?upstream.protocol, "trying upstream");

        let result = match upstream.protocol {
            UpstreamProtocol::Dot => forward_dot(&query_bytes, &upstream.address).await,
            UpstreamProtocol::Doh => forward_doh(&query_bytes, &upstream.address).await,
            UpstreamProtocol::Doq => forward_doq(&query_bytes, &upstream.address).await,
        };

        match result {
            Ok(response) => {
                debug!(name = %upstream.name, "upstream responded successfully");
                return Ok(response);
            }
            Err(e) => {
                warn!(name = %upstream.name, error = %e, "upstream failed, trying next");
                continue;
            }
        }
    }

    Err(ForwardError::AllFailed)
}

/// DNS over TLS (port 853)
async fn forward_dot(query_bytes: &[u8], address: &str) -> Result<Message, ForwardError> {
    let addr: SocketAddr = format!("{address}:853")
        .parse()
        .map_err(|e: std::net::AddrParseError| ForwardError::Dot(e.to_string()))?;

    // Set up TLS with rustls
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    // Connect TCP
    let tcp_stream = TcpStream::connect(addr)
        .await
        .map_err(|e| ForwardError::Dot(format!("TCP connect: {e}")))?;

    // DNS name for TLS SNI — use the IP directly via ServerName
    let ip_addr: rustls::pki_types::IpAddr = match addr.ip() {
        std::net::IpAddr::V4(v4) => rustls::pki_types::IpAddr::from(v4),
        std::net::IpAddr::V6(v6) => rustls::pki_types::IpAddr::from(v6),
    };
    let server_name = rustls::pki_types::ServerName::IpAddress(ip_addr);

    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| ForwardError::Dot(format!("TLS handshake: {e}")))?;

    // DNS over TCP: 2-byte length prefix
    let len = (query_bytes.len() as u16).to_be_bytes();
    tls_stream
        .write_all(&len)
        .await
        .map_err(|e| ForwardError::Dot(format!("write: {e}")))?;
    tls_stream
        .write_all(query_bytes)
        .await
        .map_err(|e| ForwardError::Dot(format!("write: {e}")))?;

    // Read response length
    let resp_len = tls_stream
        .read_u16()
        .await
        .map_err(|e| ForwardError::Dot(format!("read length: {e}")))? as usize;

    // Read response
    let mut resp_buf = vec![0u8; resp_len];
    tls_stream
        .read_exact(&mut resp_buf)
        .await
        .map_err(|e| ForwardError::Dot(format!("read response: {e}")))?;

    Message::from_bytes(&resp_buf).map_err(|_| ForwardError::InvalidResponse)
}

/// DNS over HTTPS (port 443)
async fn forward_doh(query_bytes: &[u8], address: &str) -> Result<Message, ForwardError> {
    let url = format!("https://{address}/dns-query");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| ForwardError::Doh(format!("client build: {e}")))?;

    let response = client
        .post(&url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query_bytes.to_vec())
        .send()
        .await
        .map_err(|e| ForwardError::Doh(format!("request: {e}")))?;

    if !response.status().is_success() {
        return Err(ForwardError::Doh(format!(
            "HTTP {}",
            response.status()
        )));
    }

    let resp_bytes = response
        .bytes()
        .await
        .map_err(|e| ForwardError::Doh(format!("read body: {e}")))?;

    Message::from_bytes(&resp_bytes).map_err(|_| ForwardError::InvalidResponse)
}

/// DNS over QUIC (port 853)
async fn forward_doq(query_bytes: &[u8], address: &str) -> Result<Message, ForwardError> {
    let addr: SocketAddr = format!("{address}:853")
        .parse()
        .map_err(|e: std::net::AddrParseError| ForwardError::Doq(e.to_string()))?;

    // Set up QUIC with rustls
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"doq".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| ForwardError::Doq(format!("QUIC config: {e}")))?,
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| ForwardError::Doq(format!("endpoint: {e}")))?;
    endpoint.set_default_client_config(client_config);

    let ip_addr: rustls::pki_types::IpAddr = match addr.ip() {
        std::net::IpAddr::V4(v4) => rustls::pki_types::IpAddr::from(v4),
        std::net::IpAddr::V6(v6) => rustls::pki_types::IpAddr::from(v6),
    };
    let _server_name = rustls::pki_types::ServerName::IpAddress(ip_addr);

    let server_name_str = addr.ip().to_string();

    let connection = endpoint
        .connect(addr, &server_name_str)
        .map_err(|e| ForwardError::Doq(format!("connect: {e}")))?
        .await
        .map_err(|e| ForwardError::Doq(format!("connection: {e}")))?;

    // DoQ: open a bidirectional stream, send length-prefixed query
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| ForwardError::Doq(format!("open stream: {e}")))?;

    // DoQ uses 2-byte length prefix like DNS over TCP
    let len = (query_bytes.len() as u16).to_be_bytes();
    send.write_all(&len)
        .await
        .map_err(|e| ForwardError::Doq(format!("write: {e}")))?;
    send.write_all(query_bytes)
        .await
        .map_err(|e| ForwardError::Doq(format!("write: {e}")))?;
    send.finish()
        .map_err(|e| ForwardError::Doq(format!("finish: {e}")))?;

    // Read response
    let resp_bytes = recv
        .read_to_end(65535)
        .await
        .map_err(|e| ForwardError::Doq(format!("read: {e}")))?;

    // DoQ response may or may not have length prefix depending on implementation
    // Try parsing directly first, then with length prefix stripped
    if let Ok(msg) = Message::from_bytes(&resp_bytes) {
        connection.close(0u32.into(), b"done");
        return Ok(msg);
    }

    if resp_bytes.len() > 2 {
        let len = u16::from_be_bytes([resp_bytes[0], resp_bytes[1]]) as usize;
        if resp_bytes.len() >= 2 + len {
            if let Ok(msg) = Message::from_bytes(&resp_bytes[2..2 + len]) {
                connection.close(0u32.into(), b"done");
                return Ok(msg);
            }
        }
    }

    connection.close(0u32.into(), b"done");
    Err(ForwardError::InvalidResponse)
}
