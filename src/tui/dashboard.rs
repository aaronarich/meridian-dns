use std::time::{Duration, Instant};

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Line as CanvasLine};
use ratatui::widgets::{
    Block, Borders, Cell, Paragraph, Row, Table, Wrap,
};
use ratatui::Frame;

use crate::config::ResolverMode;
use crate::stats::SharedStats;

/// Snapshot of data needed to render a single frame
pub struct DashboardState {
    pub mode: ResolverMode,
    pub uptime: Duration,
    pub total_queries: u64,
    pub cache_hits: u64,
    pub cache_hit_rate: f64,
    pub blocked_queries: u64,
    pub forwarded_queries: u64,
    pub recursive_queries: u64,
    pub recent_queries: Vec<RecentQuery>,
    pub query_history: Vec<HistoryBucket>,
    pub blocklist_domain_count: usize,
    pub blocklist_last_refresh: String,
    pub threat: ThreatInfo,
    pub config: ConfigInfo,
}

/// Threat detection / graylist summary for the TUI
pub struct ThreatInfo {
    pub enabled: bool,
    pub graylist_count: usize,
    pub total_flagged: u64,
    pub total_classifications: u64,
    pub approved_count: usize,
    pub top_graylisted: Vec<GraylistItem>,
}

impl Default for ThreatInfo {
    fn default() -> Self {
        Self {
            enabled: false,
            graylist_count: 0,
            total_flagged: 0,
            total_classifications: 0,
            approved_count: 0,
            top_graylisted: Vec::new(),
        }
    }
}

pub struct GraylistItem {
    pub domain: String,
    pub query_count: u64,
    pub entropy: f64,
    pub flags: Vec<String>,
    pub classification: Option<String>,
    pub confidence: Option<f64>,
}

pub struct ConfigInfo {
    pub listen: String,
    pub cache_max_entries: usize,
    pub blocklist_enabled: bool,
    pub blocklist_refresh_hours: u64,
    pub blocklist_sources: Vec<BlocklistSourceInfo>,
    pub upstreams: Vec<UpstreamInfo>,
}

#[derive(Clone)]
pub struct BlocklistSourceInfo {
    pub name: String,
    pub url: String,
}

pub struct UpstreamInfo {
    pub name: String,
    pub address: String,
    pub protocol: String,
}

impl Default for ConfigInfo {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:53".to_string(),
            cache_max_entries: 10000,
            blocklist_enabled: true,
            blocklist_refresh_hours: 24,
            blocklist_sources: Vec::new(),
            upstreams: Vec::new(),
        }
    }
}

/// A 10-minute bucket of query history broken down by method
#[derive(Clone)]
pub struct HistoryBucket {
    pub mins_ago: u64,
    pub cache: u64,
    pub recursive: u64,
    pub forwarded: u64,
    pub blocked: u64,
}

impl HistoryBucket {
    pub fn total(&self) -> u64 {
        self.cache + self.recursive + self.forwarded + self.blocked
    }
}

pub struct RecentQuery {
    pub domain: String,
    pub record_type: String,
    pub latency_ms: f64,
    pub method: String,
    pub dnssec: String,
}

impl DashboardState {
    /// Build a snapshot from shared stats
    pub fn from_stats(stats: &SharedStats, mode: &ResolverMode) -> Self {
        let s = stats.read().unwrap();
        let uptime = s.start_time.elapsed();

        let recent_queries: Vec<RecentQuery> = s
            .recent_queries
            .iter()
            .rev()
            .take(20)
            .map(|q| RecentQuery {
                domain: q.domain.clone(),
                record_type: q.record_type.clone(),
                latency_ms: q.latency_ms,
                method: q.method.to_string(),
                dnssec: q.dnssec.to_string(),
            })
            .collect();

        let query_history: Vec<HistoryBucket> = s
            .query_history
            .iter()
            .map(|b| HistoryBucket {
                mins_ago: b.window_start.elapsed().as_secs() / 60,
                cache: b.cache,
                recursive: b.recursive,
                forwarded: b.forwarded,
                blocked: b.blocked,
            })
            .collect();

        Self {
            mode: mode.clone(),
            uptime,
            total_queries: s.total_queries,
            cache_hits: s.cache_hits,
            cache_hit_rate: s.cache_hit_rate(),
            blocked_queries: s.blocked_queries,
            forwarded_queries: s.forwarded_queries,
            recursive_queries: s.recursive_queries,
            recent_queries,
            query_history,
            blocklist_domain_count: 0,
            blocklist_last_refresh: "N/A".to_string(),
            threat: ThreatInfo::default(),
            config: ConfigInfo::default(),
        }
    }

    /// Build state from the metrics JSON endpoint response
    pub fn from_json(json: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(json).ok()?;

        let uptime_secs = v["uptime_secs"].as_u64().unwrap_or(0);
        let total_queries = v["total_queries"].as_u64().unwrap_or(0);
        let cache_hits = v["cache_hits"].as_u64().unwrap_or(0);
        let cache_hit_rate = v["cache_hit_rate"].as_f64().unwrap_or(0.0);
        let blocked_queries = v["blocked_queries"].as_u64().unwrap_or(0);
        let forwarded_queries = v["forwarded_queries"].as_u64().unwrap_or(0);
        let recursive_queries = v["recursive_queries"].as_u64().unwrap_or(0);
        let blocklist_domain_count = v["blocklist_domains"].as_u64().unwrap_or(0) as usize;
        let refresh_secs = v["blocklist_last_refresh_secs_ago"].as_u64().unwrap_or(0);

        let blocklist_last_refresh = if refresh_secs == 0 {
            "N/A".to_string()
        } else if refresh_secs < 60 {
            format!("{refresh_secs}s ago")
        } else if refresh_secs < 3600 {
            format!("{}m ago", refresh_secs / 60)
        } else {
            format!("{}h ago", refresh_secs / 3600)
        };

        // Determine mode from which counter is higher
        let mode = if recursive_queries >= forwarded_queries {
            ResolverMode::Recursive
        } else {
            ResolverMode::Forwarding
        };

        let query_history: Vec<HistoryBucket> = v["query_history"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|b| HistoryBucket {
                        mins_ago: b["mins_ago"].as_u64().unwrap_or(0),
                        cache: b["cache"].as_u64().unwrap_or(0),
                        recursive: b["recursive"].as_u64().unwrap_or(0),
                        forwarded: b["forwarded"].as_u64().unwrap_or(0),
                        blocked: b["blocked"].as_u64().unwrap_or(0),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let recent_queries: Vec<RecentQuery> = v["recent_queries"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|q| RecentQuery {
                        domain: q["domain"].as_str().unwrap_or("?").to_string(),
                        record_type: q["type"].as_str().unwrap_or("?").to_string(),
                        latency_ms: q["latency_ms"].as_f64().unwrap_or(0.0),
                        method: q["method"].as_str().unwrap_or("?").to_string(),
                        dnssec: q["dnssec"].as_str().unwrap_or("?").to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Parse config section
        let cfg = &v["config"];
        let mode = match cfg["mode"].as_str().unwrap_or("recursive") {
            "forwarding" => ResolverMode::Forwarding,
            _ => ResolverMode::Recursive,
        };

        let upstreams: Vec<UpstreamInfo> = cfg["upstreams"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|u| UpstreamInfo {
                        name: u["name"].as_str().unwrap_or("?").to_string(),
                        address: u["address"].as_str().unwrap_or("?").to_string(),
                        protocol: u["protocol"].as_str().unwrap_or("?").to_uppercase(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let blocklist_sources: Vec<BlocklistSourceInfo> = cfg["blocklist_sources"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|s| BlocklistSourceInfo {
                        name: s["name"].as_str().unwrap_or("?").to_string(),
                        url: s["url"].as_str().unwrap_or("?").to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let config_info = ConfigInfo {
            listen: cfg["listen"].as_str().unwrap_or("0.0.0.0:53").to_string(),
            cache_max_entries: cfg["cache_max_entries"].as_u64().unwrap_or(10000) as usize,
            blocklist_enabled: cfg["blocklist_enabled"].as_bool().unwrap_or(true),
            blocklist_refresh_hours: cfg["blocklist_refresh_hours"].as_u64().unwrap_or(24),
            blocklist_sources,
            upstreams,
        };

        // Parse threat intel
        let threat_section = &v["threat"];
        let top_graylisted: Vec<GraylistItem> = threat_section["top_graylisted"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|g| {
                        let flags: Vec<String> = g["flags"]
                            .as_array()
                            .map(|f| f.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                            .unwrap_or_default();
                        let classification = g["classification"]["category"]
                            .as_str()
                            .map(String::from);
                        let confidence = g["classification"]["confidence"].as_f64();
                        GraylistItem {
                            domain: g["domain"].as_str().unwrap_or("?").to_string(),
                            query_count: g["query_count"].as_u64().unwrap_or(0),
                            entropy: g["entropy"].as_f64().unwrap_or(0.0),
                            flags,
                            classification,
                            confidence,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let threat_info = ThreatInfo {
            enabled: threat_section["enabled"].as_bool().unwrap_or(false),
            graylist_count: threat_section["graylist_count"].as_u64().unwrap_or(0) as usize,
            total_flagged: threat_section["total_flagged"].as_u64().unwrap_or(0),
            total_classifications: threat_section["total_classifications"].as_u64().unwrap_or(0),
            approved_count: threat_section["approved_count"].as_u64().unwrap_or(0) as usize,
            top_graylisted,
        };

        Some(Self {
            mode,
            uptime: Duration::from_secs(uptime_secs),
            total_queries,
            cache_hits,
            cache_hit_rate,
            blocked_queries,
            forwarded_queries,
            recursive_queries,
            recent_queries,
            query_history,
            blocklist_domain_count,
            blocklist_last_refresh,
            threat: threat_info,
            config: config_info,
        })
    }

    /// Build a demo state for testing the UI
    pub fn demo() -> Self {
        let now = Instant::now();
        let _ = now; // suppress unused warning

        let recent_queries = vec![
            RecentQuery { domain: "google.com.".into(), record_type: "A".into(), latency_ms: 12.3, method: "forwarding".into(), dnssec: "insecure".into() },
            RecentQuery { domain: "ads.doubleclick.net.".into(), record_type: "A".into(), latency_ms: 0.1, method: "blocked".into(), dnssec: "skipped".into() },
            RecentQuery { domain: "github.com.".into(), record_type: "AAAA".into(), latency_ms: 45.2, method: "recursive".into(), dnssec: "insecure".into() },
            RecentQuery { domain: "google.com.".into(), record_type: "A".into(), latency_ms: 0.2, method: "cache".into(), dnssec: "skipped".into() },
            RecentQuery { domain: "api.stripe.com.".into(), record_type: "A".into(), latency_ms: 23.1, method: "forwarding".into(), dnssec: "secure".into() },
            RecentQuery { domain: "tracker.facebook.com.".into(), record_type: "CNAME".into(), latency_ms: 0.1, method: "blocked".into(), dnssec: "skipped".into() },
            RecentQuery { domain: "rust-lang.org.".into(), record_type: "A".into(), latency_ms: 67.8, method: "recursive".into(), dnssec: "insecure".into() },
            RecentQuery { domain: "crates.io.".into(), record_type: "A".into(), latency_ms: 0.3, method: "cache".into(), dnssec: "skipped".into() },
            RecentQuery { domain: "docs.rs.".into(), record_type: "AAAA".into(), latency_ms: 34.5, method: "forwarding".into(), dnssec: "secure".into() },
            RecentQuery { domain: "analytics.google.com.".into(), record_type: "A".into(), latency_ms: 0.1, method: "blocked".into(), dnssec: "skipped".into() },
        ];

        Self {
            mode: ResolverMode::Recursive,
            uptime: Duration::from_secs(3723),
            total_queries: 14_832,
            cache_hits: 8_291,
            cache_hit_rate: 55.9,
            blocked_queries: 2_147,
            forwarded_queries: 1_203,
            recursive_queries: 3_191,
            recent_queries,
            query_history: (0..144).rev().map(|i| HistoryBucket {
                mins_ago: i * 10,
                cache: (50.0 + 30.0 * (i as f64 * 0.15).sin()) as u64,
                recursive: (20.0 + 15.0 * (i as f64 * 0.1 + 1.0).sin()) as u64,
                forwarded: (15.0 + 10.0 * (i as f64 * 0.2 + 2.0).sin()) as u64,
                blocked: (10.0 + 8.0 * (i as f64 * 0.12 + 0.5).sin()) as u64,
            }).collect(),
            blocklist_domain_count: 84_291,
            blocklist_last_refresh: "2 hours ago".to_string(),
            threat: ThreatInfo {
                enabled: true,
                graylist_count: 7,
                total_flagged: 12,
                total_classifications: 5,
                approved_count: 3,
                top_graylisted: vec![
                    GraylistItem { domain: "xk4jf9a2b7c.evil.com".into(), query_count: 47, entropy: 4.1, flags: vec!["high-entropy".into(), "suspected-dga".into()], classification: Some("malware-c2".into()), confidence: Some(0.87) },
                    GraylistItem { domain: "trk.analytics-pixel.net".into(), query_count: 31, entropy: 3.6, flags: vec!["high-freq-unknown".into()], classification: Some("ad-tracker".into()), confidence: Some(0.92) },
                    GraylistItem { domain: "cdn7-metrics.telemetry.io".into(), query_count: 18, entropy: 3.5, flags: vec!["high-freq-unknown".into()], classification: None, confidence: None },
                ],
            },
            config: ConfigInfo {
                listen: "0.0.0.0:53".to_string(),
                cache_max_entries: 10000,
                blocklist_enabled: true,
                blocklist_refresh_hours: 24,
                blocklist_sources: vec![
                    BlocklistSourceInfo { name: "stevenblack".into(), url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".into() },
                    BlocklistSourceInfo { name: "peter-lowe".into(), url: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts".into() },
                ],
                upstreams: vec![
                    UpstreamInfo { name: "quad9".into(), address: "9.9.9.9".into(), protocol: "DOT".into() },
                    UpstreamInfo { name: "cloudflare".into(), address: "1.1.1.1".into(), protocol: "DOQ".into() },
                ],
            },
        }
    }
}

fn format_uptime(d: Duration) -> String {
    let total_secs = d.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

pub fn render(frame: &mut Frame, state: &DashboardState) {
    let size = frame.area();

    // Top-level layout: header, middle, threat, config, footer
    let threat_height = if state.threat.enabled { 8 } else { 0 };
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),             // header: mode + stats
            Constraint::Min(10),              // middle: chart + query log
            Constraint::Length(threat_height), // threat detection panel
            Constraint::Length(8),            // config: settings panel
            Constraint::Length(3),            // footer: keybinds
        ])
        .split(size);

    render_header(frame, outer[0], state);
    render_middle(frame, outer[1], state);
    if state.threat.enabled {
        render_threat(frame, outer[2], state);
    }
    render_config(frame, outer[3], state);
    render_footer(frame, outer[4], state);
}

fn render_header(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    // Mode + Uptime
    let mode_str = match state.mode {
        ResolverMode::Recursive => "Recursive",
        ResolverMode::Forwarding => "Forwarding",
    };
    let mode_block = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Mode: ", Style::default().fg(Color::DarkGray)),
            Span::styled(mode_str, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Uptime: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format_uptime(state.uptime), Style::default().fg(Color::White)),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title(" Meridian ").style(Style::default().fg(Color::Cyan)));
    frame.render_widget(mode_block, chunks[0]);

    // Total queries
    let queries_block = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Total: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format_number(state.total_queries),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Cache: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:.1}%", state.cache_hit_rate),
                Style::default().fg(Color::Green),
            ),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title(" Queries "));
    frame.render_widget(queries_block, chunks[1]);

    // Resolution breakdown
    let breakdown = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Fwd: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format_number(state.forwarded_queries), Style::default().fg(Color::Blue)),
            Span::raw("  "),
            Span::styled("Rec: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format_number(state.recursive_queries), Style::default().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::styled("Cache: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format_number(state.cache_hits), Style::default().fg(Color::Green)),
            Span::raw("  "),
            Span::styled("Blk: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format_number(state.blocked_queries), Style::default().fg(Color::Red)),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title(" Breakdown "));
    frame.render_widget(breakdown, chunks[2]);

    // Blocked stats
    let blocked = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Domains: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format_number(state.blocklist_domain_count as u64),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::styled("Refresh: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&state.blocklist_last_refresh, Style::default().fg(Color::White)),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title(" Blocklist "));
    frame.render_widget(blocked, chunks[3]);
}

fn render_middle(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(14), // 24h history chart
            Constraint::Min(6),    // Query log
        ])
        .split(area);

    render_history_chart(frame, chunks[0], state);
    render_query_log(frame, chunks[1], state);
}

fn render_history_chart(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Queries (24h) ")
        .title_bottom(Line::from(vec![
            Span::styled(" ─", Style::default().fg(Color::Green)),
            Span::styled(" cache ", Style::default().fg(Color::DarkGray)),
            Span::styled("─", Style::default().fg(Color::Magenta)),
            Span::styled(" recursive ", Style::default().fg(Color::DarkGray)),
            Span::styled("─", Style::default().fg(Color::Blue)),
            Span::styled(" forwarded ", Style::default().fg(Color::DarkGray)),
            Span::styled("─", Style::default().fg(Color::Red)),
            Span::styled(" blocked ", Style::default().fg(Color::DarkGray)),
        ]));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if state.query_history.is_empty() || inner.width < 10 || inner.height < 4 {
        return;
    }

    // Prepare 4 series of (x, y) points, sorted by time
    let mut cache_pts: Vec<(f64, f64)> = Vec::new();
    let mut recursive_pts: Vec<(f64, f64)> = Vec::new();
    let mut forwarded_pts: Vec<(f64, f64)> = Vec::new();
    let mut blocked_pts: Vec<(f64, f64)> = Vec::new();

    for b in &state.query_history {
        let x = 1440.0 - b.mins_ago as f64; // 0=24h ago, 1440=now
        cache_pts.push((x, b.cache as f64));
        recursive_pts.push((x, b.recursive as f64));
        forwarded_pts.push((x, b.forwarded as f64));
        blocked_pts.push((x, b.blocked as f64));
    }

    for pts in [&mut cache_pts, &mut recursive_pts, &mut forwarded_pts, &mut blocked_pts] {
        pts.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    }

    let max_val = state
        .query_history
        .iter()
        .flat_map(|b| [b.cache, b.recursive, b.forwarded, b.blocked])
        .max()
        .unwrap_or(1)
        .max(1) as f64;

    // Layout: [y-labels 5w] [canvas] on top, [padding 5w] [x-labels] on bottom
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let top_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(5), Constraint::Min(1)])
        .split(rows[0]);

    let bot_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(5), Constraint::Min(1)])
        .split(rows[1]);

    let y_max = max_val * 1.1;

    // Canvas with braille markers for smooth lines
    let canvas = Canvas::default()
        .x_bounds([0.0, 1440.0])
        .y_bounds([0.0, y_max])
        .marker(Marker::Braille)
        .paint(|ctx| {
            // Draw lines in back-to-front order (blocked behind, cache in front)
            draw_series(ctx, &blocked_pts, Color::Red);
            draw_series(ctx, &forwarded_pts, Color::Blue);
            draw_series(ctx, &recursive_pts, Color::Magenta);
            draw_series(ctx, &cache_pts, Color::Green);
        });

    frame.render_widget(canvas, top_cols[1]);

    // Y-axis labels
    let y_area = top_cols[0];
    if y_area.height >= 3 {
        let max_label = format_compact(max_val as u64);
        let mid_label = format_compact((max_val / 2.0) as u64);

        let y_text = Paragraph::new(vec![
            Line::from(Span::styled(&max_label, Style::default().fg(Color::DarkGray))),
            // Fill middle lines empty
        ]);
        frame.render_widget(y_text, Rect { height: 1, ..y_area });

        let mid_y = y_area.y + y_area.height / 2;
        let mid_area = Rect { x: y_area.x, y: mid_y, width: y_area.width, height: 1 };
        frame.render_widget(
            Paragraph::new(Span::styled(&mid_label, Style::default().fg(Color::DarkGray))),
            mid_area,
        );

        let bot_y = y_area.y + y_area.height - 1;
        let bot_area = Rect { x: y_area.x, y: bot_y, width: y_area.width, height: 1 };
        frame.render_widget(
            Paragraph::new(Span::styled("0", Style::default().fg(Color::DarkGray))),
            bot_area,
        );
    }

    // X-axis time labels
    let x_area = bot_cols[1];
    let w = x_area.width as usize;
    if w > 20 {
        let mut label_line = vec![Span::styled("24h", Style::default().fg(Color::DarkGray))];
        let labels = ["18h", "12h", "6h", "now"];
        for (i, lbl) in labels.iter().enumerate() {
            let target_pos = ((i + 1) as f64 / 4.0 * w as f64) as usize;
            let current_len: usize = label_line.iter().map(|s| s.width()).sum();
            let padding = target_pos.saturating_sub(current_len + lbl.len() / 2);
            if padding > 0 {
                label_line.push(Span::raw(" ".repeat(padding)));
            }
            label_line.push(Span::styled(*lbl, Style::default().fg(Color::DarkGray)));
        }
        frame.render_widget(Paragraph::new(Line::from(label_line)), x_area);
    }
}

fn draw_series(ctx: &mut ratatui::widgets::canvas::Context<'_>, points: &[(f64, f64)], color: Color) {
    for w in points.windows(2) {
        ctx.draw(&CanvasLine {
            x1: w[0].0,
            y1: w[0].1,
            x2: w[1].0,
            y2: w[1].1,
            color,
        });
    }
}

fn format_compact(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.0}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn render_query_log(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let header = Row::new(vec![
        Cell::from("Domain").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Type").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Latency").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Method").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("DNSSEC").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
    ])
    .height(1);

    let rows: Vec<Row> = state
        .recent_queries
        .iter()
        .map(|q| {
            let method_color = match q.method.as_str() {
                "cache" => Color::Green,
                "blocked" => Color::Red,
                "forwarding" => Color::Blue,
                "recursive" => Color::Magenta,
                _ => Color::White,
            };

            let dnssec_color = match q.dnssec.as_str() {
                "secure" => Color::Green,
                "insecure" => Color::Yellow,
                "bogus" => Color::Red,
                _ => Color::DarkGray,
            };

            Row::new(vec![
                Cell::from(truncate_domain(&q.domain, 35)),
                Cell::from(q.record_type.as_str()),
                Cell::from(format!("{:.1}ms", q.latency_ms)),
                Cell::from(q.method.as_str()).style(Style::default().fg(method_color)),
                Cell::from(q.dnssec.as_str()).style(Style::default().fg(dnssec_color)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(20),
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Recent Queries "),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::BOLD));

    frame.render_widget(table, area);
}

fn render_threat(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(28), // threat summary
            Constraint::Min(30),   // graylisted domains table
        ])
        .split(area);

    // Summary panel
    let summary = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Graylisted: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                state.threat.graylist_count.to_string(),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Total flagged: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                state.threat.total_flagged.to_string(),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("Classified: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                state.threat.total_classifications.to_string(),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled("Approved: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                state.threat.approved_count.to_string(),
                Style::default().fg(Color::Green),
            ),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" AI Threat Detection ")
            .style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(summary, chunks[0]);

    // Top graylisted domains
    let header = Row::new(vec![
        Cell::from("Domain").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Hits").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Flags").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Classification").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
    ])
    .height(1);

    let rows: Vec<Row> = state
        .threat
        .top_graylisted
        .iter()
        .map(|g| {
            let classification_text = match (&g.classification, g.confidence) {
                (Some(cat), Some(conf)) => format!("{} ({:.0}%)", cat, conf * 100.0),
                (Some(cat), None) => cat.clone(),
                _ => "pending...".to_string(),
            };
            let class_color = match g.classification.as_deref() {
                Some("malware-c2") | Some("dga") | Some("data-exfil") => Color::Red,
                Some("ad-tracker") | Some("analytics") => Color::Yellow,
                Some("cdn") | Some("legitimate") => Color::Green,
                _ => Color::DarkGray,
            };
            Row::new(vec![
                Cell::from(truncate_domain(&g.domain, 30)),
                Cell::from(g.query_count.to_string()),
                Cell::from(g.flags.join(", ")).style(Style::default().fg(Color::Yellow)),
                Cell::from(classification_text).style(Style::default().fg(class_color)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(20),
            Constraint::Length(6),
            Constraint::Length(20),
            Constraint::Min(15),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Graylist (top by query count) "),
    );

    frame.render_widget(table, chunks[1]);
}

fn render_config(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50), // Upstreams
            Constraint::Percentage(50), // Blocklist sources
        ])
        .split(area);

    // Upstream servers panel
    let mut upstream_lines = Vec::new();
    for u in &state.config.upstreams {
        upstream_lines.push(Line::from(vec![
            Span::styled(&u.name, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("  ", Style::default()),
            Span::styled(&u.address, Style::default().fg(Color::White)),
            Span::styled("  ", Style::default()),
            Span::styled(
                &u.protocol,
                Style::default().fg(match u.protocol.as_str() {
                    "DOT" => Color::Green,
                    "DOH" => Color::Blue,
                    "DOQ" => Color::Magenta,
                    _ => Color::White,
                }),
            ),
        ]));
    }
    if upstream_lines.is_empty() {
        upstream_lines.push(Line::from(Span::styled(
            "  (none configured)",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let upstreams = Paragraph::new(upstream_lines)
        .block(Block::default().borders(Borders::ALL).title(" Upstream Servers "));
    frame.render_widget(upstreams, chunks[0]);

    // Blocklist sources panel
    let mut bl_lines = Vec::new();
    for s in &state.config.blocklist_sources {
        bl_lines.push(Line::from(vec![
            Span::styled(&s.name, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled("  ", Style::default()),
            Span::styled(
                truncate_url(&s.url, (chunks[1].width.saturating_sub(s.name.len() as u16 + 6)) as usize),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }
    if bl_lines.is_empty() {
        bl_lines.push(Line::from(Span::styled(
            "  (none configured)",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let blocklists = Paragraph::new(bl_lines)
        .block(Block::default().borders(Borders::ALL).title(" Blocklist Sources "));
    frame.render_widget(blocklists, chunks[1]);
}

fn render_footer(frame: &mut Frame, area: Rect, _state: &DashboardState) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("  q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(" quit  ", Style::default().fg(Color::DarkGray)),
        Span::styled("r", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(" refresh  ", Style::default().fg(Color::DarkGray)),
        Span::styled("a", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(" add blocklist  ", Style::default().fg(Color::DarkGray)),
        Span::styled("d", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(" remove blocklist", Style::default().fg(Color::DarkGray)),
    ]))
    .wrap(Wrap { trim: false })
    .block(Block::default().borders(Borders::ALL).title(" Keys "));
    frame.render_widget(footer, area);
}

/// Render the dashboard with an optional input overlay in the footer area
pub fn render_with_overlay(
    frame: &mut Frame,
    state: &DashboardState,
    overlay: Option<&str>,
    status: Option<&str>,
) {
    let size = frame.area();

    // Determine footer height based on overlay content
    let footer_height = if let Some(text) = overlay {
        // Count lines in overlay + borders
        (text.lines().count() as u16 + 2).max(3)
    } else {
        3
    };

    let threat_height = if state.threat.enabled { 8 } else { 0 };
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),             // header
            Constraint::Min(10),              // middle
            Constraint::Length(threat_height), // threat
            Constraint::Length(8),            // config
            Constraint::Length(footer_height), // footer / overlay
        ])
        .split(size);

    render_header(frame, outer[0], state);
    render_middle(frame, outer[1], state);
    if state.threat.enabled {
        render_threat(frame, outer[2], state);
    }
    render_config(frame, outer[3], state);

    if let Some(text) = overlay {
        // Render input overlay instead of normal footer
        let overlay_widget = Paragraph::new(text)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Input ")
                    .style(Style::default().fg(Color::Yellow)),
            );
        frame.render_widget(overlay_widget, outer[4]);
    } else if let Some(status_text) = status {
        // Render status message in footer
        let footer = Paragraph::new(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(status_text, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
            Span::styled("q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" quit  ", Style::default().fg(Color::DarkGray)),
            Span::styled("r", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" refresh  ", Style::default().fg(Color::DarkGray)),
            Span::styled("a", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" add  ", Style::default().fg(Color::DarkGray)),
            Span::styled("d", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" remove", Style::default().fg(Color::DarkGray)),
        ]))
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title(" Keys "));
        frame.render_widget(footer, outer[4]);
    } else {
        render_footer(frame, outer[4], state);
    }
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn truncate_domain(domain: &str, max_len: usize) -> String {
    if domain.len() <= max_len {
        domain.to_string()
    } else {
        format!("...{}", &domain[domain.len() - (max_len - 3)..])
    }
}

fn truncate_url(url: &str, max_len: usize) -> String {
    if max_len < 10 {
        return "...".to_string();
    }
    if url.len() <= max_len {
        url.to_string()
    } else {
        format!("{}...", &url[..max_len - 3])
    }
}
