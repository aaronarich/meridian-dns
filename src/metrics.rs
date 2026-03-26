use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{error, info, debug};

use crate::blocklist::SharedBlocklist;
use crate::stats::SharedStats;

/// Start the metrics HTTP server
pub async fn start(
    port: u16,
    stats: SharedStats,
    blocklist: SharedBlocklist,
) {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            info!("metrics HTTP server listening on {addr}");
            l
        }
        Err(e) => {
            error!("failed to bind metrics server to {addr}: {e}");
            return;
        }
    };

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => {
                debug!("metrics accept error: {e}");
                continue;
            }
        };

        let stats = stats.clone();
        let blocklist = blocklist.clone();

        tokio::spawn(async move {
            // Read the HTTP request (we don't really need to parse it)
            let mut buf = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

            let body = build_metrics_json(&stats, &blocklist);

            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Access-Control-Allow-Origin: *\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            );

            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

fn build_metrics_json(stats: &SharedStats, blocklist: &SharedBlocklist) -> String {
    let s = stats.read().unwrap();
    let uptime_secs = s.start_time.elapsed().as_secs();

    let blocklist_count = blocklist
        .read()
        .map(|b| b.domain_count)
        .unwrap_or(0);

    let blocklist_last_refresh = blocklist
        .read()
        .ok()
        .and_then(|b| b.last_refresh)
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);

    let recent: Vec<String> = s
        .recent_queries
        .iter()
        .rev()
        .take(20)
        .map(|q| {
            format!(
                r#"{{"domain":"{}","type":"{}","latency_ms":{:.2},"method":"{}"}}"#,
                escape_json(&q.domain),
                escape_json(&q.record_type),
                q.latency_ms,
                q.method,
            )
        })
        .collect();

    format!(
        r#"{{"uptime_secs":{},"total_queries":{},"cache_hits":{},"cache_hit_rate":{:.1},"blocked_queries":{},"forwarded_queries":{},"recursive_queries":{},"blocklist_domains":{},"blocklist_last_refresh_secs_ago":{},"recent_queries":[{}]}}"#,
        uptime_secs,
        s.total_queries,
        s.cache_hits,
        s.cache_hit_rate(),
        s.blocked_queries,
        s.forwarded_queries,
        s.recursive_queries,
        blocklist_count,
        blocklist_last_refresh,
        recent.join(","),
    )
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocklist::new_shared_blocklist;
    use crate::stats::{new_shared_stats, QueryLogEntry, ResolutionMethod};
    use std::time::Instant;

    #[test]
    fn metrics_json_empty() {
        let stats = new_shared_stats();
        let blocklist = new_shared_blocklist();
        let json = build_metrics_json(&stats, &blocklist);

        assert!(json.contains("\"total_queries\":0"));
        assert!(json.contains("\"cache_hit_rate\":0.0"));
        assert!(json.contains("\"recent_queries\":[]"));
    }

    #[test]
    fn metrics_json_with_queries() {
        let stats = new_shared_stats();
        let blocklist = new_shared_blocklist();

        {
            let mut s = stats.write().unwrap();
            s.record_query(QueryLogEntry {
                domain: "example.com".to_string(),
                record_type: "A".to_string(),
                latency_ms: 42.5,
                method: ResolutionMethod::Forwarding,
                timestamp: Instant::now(),
            });
        }

        let json = build_metrics_json(&stats, &blocklist);
        assert!(json.contains("\"total_queries\":1"));
        assert!(json.contains("\"forwarded_queries\":1"));
        assert!(json.contains("example.com"));
    }
}
