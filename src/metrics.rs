use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::blocklist::{self, SharedBlocklist};
use crate::config::{BlocklistSource, Config};
use crate::stats::SharedStats;
use crate::threat::SharedThreatIntel;

/// Start the metrics HTTP server
pub async fn start(
    port: u16,
    stats: SharedStats,
    blocklist: SharedBlocklist,
    threat_intel: Option<SharedThreatIntel>,
    config: Arc<Config>,
    config_path: PathBuf,
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
        let threat_intel = threat_intel.clone();
        let config = config.clone();
        let config_path = config_path.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };

            let (method, path, body) = parse_http_request(&buf[..n]);

            let response = match (method.as_str(), path.as_str()) {
                ("GET", "/") | ("GET", "") => {
                    let json = build_metrics_json(&stats, &blocklist, &threat_intel, &config);
                    http_response(200, "application/json", &json)
                }
                ("GET", "/threat/graylist") => {
                    let json = build_graylist_json(&threat_intel);
                    http_response(200, "application/json", &json)
                }
                ("POST", "/threat/approve") => {
                    handle_threat_approve(&body, &threat_intel)
                }
                ("POST", "/blocklist/refresh") => {
                    handle_blocklist_refresh(&blocklist, &config_path).await
                }
                ("POST", "/blocklist/add") => {
                    handle_blocklist_add(&body, &blocklist, &config_path).await
                }
                ("POST", "/blocklist/remove") => {
                    handle_blocklist_remove(&body, &blocklist, &config_path).await
                }
                _ => http_response(404, "application/json", r#"{"error":"not found"}"#),
            };

            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

fn parse_http_request(buf: &[u8]) -> (String, String, String) {
    let request = String::from_utf8_lossy(buf);
    let mut lines = request.lines();
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    // Find body after \r\n\r\n
    let body = request
        .find("\r\n\r\n")
        .map(|i| request[i + 4..].trim_end_matches('\0').to_string())
        .unwrap_or_default();

    (method, path, body)
}

fn http_response(status: u16, content_type: &str, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )
}

async fn handle_blocklist_refresh(
    blocklist: &SharedBlocklist,
    config_path: &PathBuf,
) -> String {
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to load config for blocklist refresh");
            return http_response(500, "application/json", &format!(r#"{{"error":"{}"}}"#, e));
        }
    };

    blocklist::load(&config.blocklist, blocklist).await;
    info!("blocklist refreshed via API");
    http_response(200, "application/json", r#"{"status":"ok","action":"refresh"}"#)
}

async fn handle_blocklist_add(
    body: &str,
    blocklist: &SharedBlocklist,
    config_path: &PathBuf,
) -> String {
    // Parse JSON body: {"name": "...", "url": "..."}
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return http_response(400, "application/json", &format!(r#"{{"error":"invalid JSON: {}"}}"#, e));
        }
    };

    let name = match v["name"].as_str() {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return http_response(400, "application/json", r#"{"error":"missing 'name' field"}"#),
    };

    let url = match v["url"].as_str() {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => return http_response(400, "application/json", r#"{"error":"missing 'url' field"}"#),
    };

    // Load config from disk, modify, save back
    let mut config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            return http_response(500, "application/json", &format!(r#"{{"error":"{}"}}"#, e));
        }
    };

    // Check for duplicate name
    if config.blocklist.sources.iter().any(|s| s.name == name) {
        return http_response(400, "application/json", r#"{"error":"source with that name already exists"}"#);
    }

    config.blocklist.sources.push(BlocklistSource {
        name: name.clone(),
        url: url.clone(),
    });

    if let Err(e) = config.save(config_path) {
        warn!(error = %e, "failed to save config after adding blocklist source");
        return http_response(500, "application/json", &format!(r#"{{"error":"{}"}}"#, e));
    }

    // Reload blocklist with updated config
    blocklist::load(&config.blocklist, blocklist).await;
    info!(name = %name, url = %url, "blocklist source added via API");
    http_response(200, "application/json", r#"{"status":"ok","action":"add"}"#)
}

async fn handle_blocklist_remove(
    body: &str,
    blocklist: &SharedBlocklist,
    config_path: &PathBuf,
) -> String {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return http_response(400, "application/json", &format!(r#"{{"error":"invalid JSON: {}"}}"#, e));
        }
    };

    let name = match v["name"].as_str() {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return http_response(400, "application/json", r#"{"error":"missing 'name' field"}"#),
    };

    let mut config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            return http_response(500, "application/json", &format!(r#"{{"error":"{}"}}"#, e));
        }
    };

    let before_len = config.blocklist.sources.len();
    config.blocklist.sources.retain(|s| s.name != name);

    if config.blocklist.sources.len() == before_len {
        return http_response(404, "application/json", r#"{"error":"source not found"}"#);
    }

    if let Err(e) = config.save(config_path) {
        warn!(error = %e, "failed to save config after removing blocklist source");
        return http_response(500, "application/json", &format!(r#"{{"error":"{}"}}"#, e));
    }

    // Reload blocklist with updated config
    blocklist::load(&config.blocklist, blocklist).await;
    info!(name = %name, "blocklist source removed via API");
    http_response(200, "application/json", r#"{"status":"ok","action":"remove"}"#)
}

fn handle_threat_approve(body: &str, threat_intel: &Option<SharedThreatIntel>) -> String {
    let ti = match threat_intel {
        Some(ti) => ti,
        None => return http_response(400, "application/json", r#"{"error":"threat detection not enabled"}"#),
    };

    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return http_response(400, "application/json", &format!(r#"{{"error":"invalid JSON: {}"}}"#, e));
        }
    };

    let domain = match v["domain"].as_str() {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => return http_response(400, "application/json", r#"{"error":"missing 'domain' field"}"#),
    };

    if let Ok(mut intel) = ti.write() {
        intel.approve_domain(&domain);
        info!(domain = %domain, "domain approved via API, removed from graylist");
        http_response(200, "application/json", r#"{"status":"ok","action":"approve"}"#)
    } else {
        http_response(500, "application/json", r#"{"error":"lock error"}"#)
    }
}

fn build_graylist_json(threat_intel: &Option<SharedThreatIntel>) -> String {
    let ti = match threat_intel {
        Some(ti) => ti,
        None => return r#"{"graylist":[],"enabled":false}"#.to_string(),
    };

    let intel = match ti.read() {
        Ok(i) => i,
        Err(_) => return r#"{"graylist":[],"error":"lock"}"#.to_string(),
    };

    let mut entries: Vec<&crate::threat::GraylistEntry> = intel.graylist.values().collect();
    entries.sort_by(|a, b| b.query_count.cmp(&a.query_count));

    let items: Vec<String> = entries
        .iter()
        .take(50)
        .map(|e| {
            let flags: Vec<String> = e.flags.iter().map(|f| format!("\"{}\"", f)).collect();
            let classification = match &e.classification {
                Some(c) => format!(
                    r#"{{"category":"{}","confidence":{:.2},"explanation":"{}"}}"#,
                    escape_json(&c.category),
                    c.confidence,
                    escape_json(&c.explanation),
                ),
                None => "null".to_string(),
            };
            format!(
                r#"{{"domain":"{}","query_count":{},"entropy":{:.2},"flags":[{}],"classification":{},"age_secs":{}}}"#,
                escape_json(&e.domain),
                e.query_count,
                e.entropy,
                flags.join(","),
                classification,
                e.first_seen.elapsed().as_secs(),
            )
        })
        .collect();

    format!(
        r#"{{"graylist":[{}],"total_flagged":{},"total_classifications":{},"approved_count":{}}}"#,
        items.join(","),
        intel.total_flagged,
        intel.total_classifications,
        intel.approved.len(),
    )
}

fn build_metrics_json(
    stats: &SharedStats,
    blocklist: &SharedBlocklist,
    threat_intel: &Option<SharedThreatIntel>,
    config: &Config,
) -> String {
    let s = stats.read().unwrap();
    let uptime_secs = s.start_time.elapsed().as_secs();

    let blocklist_count = blocklist.read().map(|b| b.domain_count).unwrap_or(0);

    let blocklist_last_refresh = blocklist
        .read()
        .ok()
        .and_then(|b| b.last_refresh)
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);

    // Build query history (24h in 10-minute buckets)
    let history: Vec<String> = s
        .query_history
        .iter()
        .map(|b| {
            let mins_ago = b.window_start.elapsed().as_secs() / 60;
            format!(
                r#"{{"mins_ago":{},"cache":{},"recursive":{},"forwarded":{},"blocked":{}}}"#,
                mins_ago, b.cache, b.recursive, b.forwarded, b.blocked,
            )
        })
        .collect();

    let recent: Vec<String> = s
        .recent_queries
        .iter()
        .rev()
        .take(20)
        .map(|q| {
            format!(
                r#"{{"domain":"{}","type":"{}","latency_ms":{:.2},"method":"{}","dnssec":"{}"}}"#,
                escape_json(&q.domain),
                escape_json(&q.record_type),
                q.latency_ms,
                q.method,
                q.dnssec,
            )
        })
        .collect();

    // Build config section
    let mode = match config.mode {
        crate::config::ResolverMode::Recursive => "recursive",
        crate::config::ResolverMode::Forwarding => "forwarding",
    };

    let upstreams: Vec<String> = config
        .upstream
        .servers
        .iter()
        .map(|s| {
            let protocol = match s.protocol {
                crate::config::UpstreamProtocol::Dot => "dot",
                crate::config::UpstreamProtocol::Doh => "doh",
                crate::config::UpstreamProtocol::Doq => "doq",
            };
            format!(
                r#"{{"name":"{}","address":"{}","protocol":"{}"}}"#,
                escape_json(&s.name),
                escape_json(&s.address),
                protocol,
            )
        })
        .collect();

    let blocklist_sources: Vec<String> = config
        .blocklist
        .sources
        .iter()
        .map(|s| {
            format!(
                r#"{{"name":"{}","url":"{}"}}"#,
                escape_json(&s.name),
                escape_json(&s.url),
            )
        })
        .collect();

    // Threat intel summary
    let (graylist_count, threat_total_flagged, threat_classifications, threat_enabled) =
        match threat_intel {
            Some(ti) => match ti.read() {
                Ok(intel) => (
                    intel.graylist.len(),
                    intel.total_flagged,
                    intel.total_classifications,
                    true,
                ),
                Err(_) => (0, 0, 0, true),
            },
            None => (0, 0, 0, false),
        };

    // Build top graylisted entries for the main dashboard
    let graylist_top: Vec<String> = match threat_intel {
        Some(ti) => match ti.read() {
            Ok(intel) => {
                let mut entries: Vec<_> = intel.graylist.values().collect();
                entries.sort_by(|a, b| b.query_count.cmp(&a.query_count));
                entries
                    .iter()
                    .take(10)
                    .map(|e| {
                        let flags: Vec<String> = e.flags.iter().map(|f| format!("\"{}\"", f)).collect();
                        let classification = match &e.classification {
                            Some(c) => format!(
                                r#"{{"category":"{}","confidence":{:.2},"explanation":"{}"}}"#,
                                escape_json(&c.category),
                                c.confidence,
                                escape_json(&c.explanation),
                            ),
                            None => "null".to_string(),
                        };
                        format!(
                            r#"{{"domain":"{}","query_count":{},"entropy":{:.2},"flags":[{}],"classification":{}}}"#,
                            escape_json(&e.domain),
                            e.query_count,
                            e.entropy,
                            flags.join(","),
                            classification,
                        )
                    })
                    .collect()
            }
            Err(_) => Vec::new(),
        },
        None => Vec::new(),
    };

    format!(
        r#"{{"uptime_secs":{},"total_queries":{},"cache_hits":{},"cache_hit_rate":{:.1},"blocked_queries":{},"forwarded_queries":{},"recursive_queries":{},"graylisted_queries":{},"blocklist_domains":{},"blocklist_last_refresh_secs_ago":{},"threat":{{"enabled":{},"graylist_count":{},"total_flagged":{},"total_classifications":{},"top_graylisted":[{}]}},"query_history":[{}],"recent_queries":[{}],"config":{{"mode":"{}","listen":"{}","cache_max_entries":{},"blocklist_enabled":{},"blocklist_refresh_hours":{},"blocklist_sources":[{}],"upstreams":[{}]}}}}"#,
        uptime_secs,
        s.total_queries,
        s.cache_hits,
        s.cache_hit_rate(),
        s.blocked_queries,
        s.forwarded_queries,
        s.recursive_queries,
        s.graylisted_queries,
        blocklist_count,
        blocklist_last_refresh,
        threat_enabled,
        graylist_count,
        threat_total_flagged,
        threat_classifications,
        graylist_top.join(","),
        history.join(","),
        recent.join(","),
        mode,
        config.listen,
        config.cache.max_entries,
        config.blocklist.enabled,
        config.blocklist.refresh_interval_hours,
        blocklist_sources.join(","),
        upstreams.join(","),
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
    use crate::stats::{new_shared_stats, DnssecStatus, QueryLogEntry, ResolutionMethod};
    use std::time::Instant;

    fn test_config() -> Arc<Config> {
        let config: Config = toml::from_str(
            r#"
mode = "recursive"
[[upstream.servers]]
name = "quad9"
address = "9.9.9.9"
protocol = "dot"
"#,
        )
        .unwrap();
        Arc::new(config)
    }

    #[test]
    fn metrics_json_empty() {
        let stats = new_shared_stats();
        let blocklist = new_shared_blocklist();
        let config = test_config();
        let json = build_metrics_json(&stats, &blocklist, &None, &config);

        assert!(json.contains("\"total_queries\":0"));
        assert!(json.contains("\"cache_hit_rate\":0.0"));
        assert!(json.contains("\"recent_queries\":[]"));
        assert!(json.contains("\"mode\":\"recursive\""));
        assert!(json.contains("\"quad9\""));
        assert!(json.contains("\"graylisted_queries\":0"));
    }

    #[test]
    fn metrics_json_with_queries() {
        let stats = new_shared_stats();
        let blocklist = new_shared_blocklist();
        let config = test_config();

        {
            let mut s = stats.write().unwrap();
            s.record_query(QueryLogEntry {
                domain: "example.com".to_string(),
                record_type: "A".to_string(),
                latency_ms: 42.5,
                method: ResolutionMethod::Forwarding,
                dnssec: DnssecStatus::Insecure,
                timestamp: Instant::now(),
            });
        }

        let json = build_metrics_json(&stats, &blocklist, &None, &config);
        assert!(json.contains("\"total_queries\":1"));
        assert!(json.contains("\"forwarded_queries\":1"));
        assert!(json.contains("example.com"));
    }

    #[test]
    fn parse_get_request() {
        let raw = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (method, path, body) = parse_http_request(raw);
        assert_eq!(method, "GET");
        assert_eq!(path, "/");
        assert!(body.is_empty());
    }

    #[test]
    fn parse_post_request_with_body() {
        let raw = b"POST /blocklist/add HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\",\"url\":\"https://example.com\"}";
        let (method, path, body) = parse_http_request(raw);
        assert_eq!(method, "POST");
        assert_eq!(path, "/blocklist/add");
        assert!(body.contains("test"));
        assert!(body.contains("https://example.com"));
    }
}
