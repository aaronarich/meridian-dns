use std::time::{Duration, Instant};

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Bar, BarChart, BarGroup, Block, Borders, Cell, Paragraph, Row, Table, Wrap,
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
    pub qps_history: Vec<u64>,
    pub blocklist_domain_count: usize,
    pub blocklist_last_refresh: String,
}

pub struct RecentQuery {
    pub domain: String,
    pub record_type: String,
    pub latency_ms: f64,
    pub method: String,
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
            })
            .collect();

        let qps_history: Vec<u64> = s
            .queries_per_second
            .iter()
            .map(|(_, count)| *count)
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
            qps_history,
            blocklist_domain_count: 0,
            blocklist_last_refresh: "N/A".to_string(),
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

        let recent_queries: Vec<RecentQuery> = v["recent_queries"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|q| RecentQuery {
                        domain: q["domain"].as_str().unwrap_or("?").to_string(),
                        record_type: q["type"].as_str().unwrap_or("?").to_string(),
                        latency_ms: q["latency_ms"].as_f64().unwrap_or(0.0),
                        method: q["method"].as_str().unwrap_or("?").to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();

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
            qps_history: Vec::new(),
            blocklist_domain_count,
            blocklist_last_refresh,
        })
    }

    /// Build a demo state for testing the UI
    pub fn demo() -> Self {
        let now = Instant::now();
        let _ = now; // suppress unused warning

        let recent_queries = vec![
            RecentQuery { domain: "google.com.".into(), record_type: "A".into(), latency_ms: 12.3, method: "forwarding".into() },
            RecentQuery { domain: "ads.doubleclick.net.".into(), record_type: "A".into(), latency_ms: 0.1, method: "blocked".into() },
            RecentQuery { domain: "github.com.".into(), record_type: "AAAA".into(), latency_ms: 45.2, method: "recursive".into() },
            RecentQuery { domain: "google.com.".into(), record_type: "A".into(), latency_ms: 0.2, method: "cache".into() },
            RecentQuery { domain: "api.stripe.com.".into(), record_type: "A".into(), latency_ms: 23.1, method: "forwarding".into() },
            RecentQuery { domain: "tracker.facebook.com.".into(), record_type: "CNAME".into(), latency_ms: 0.1, method: "blocked".into() },
            RecentQuery { domain: "rust-lang.org.".into(), record_type: "A".into(), latency_ms: 67.8, method: "recursive".into() },
            RecentQuery { domain: "crates.io.".into(), record_type: "A".into(), latency_ms: 0.3, method: "cache".into() },
            RecentQuery { domain: "docs.rs.".into(), record_type: "AAAA".into(), latency_ms: 34.5, method: "forwarding".into() },
            RecentQuery { domain: "analytics.google.com.".into(), record_type: "A".into(), latency_ms: 0.1, method: "blocked".into() },
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
            qps_history: vec![12, 8, 15, 22, 18, 9, 14, 25, 31, 19, 11, 7, 16, 20, 27, 13, 10, 23, 17, 14],
            blocklist_domain_count: 84_291,
            blocklist_last_refresh: "2 hours ago".to_string(),
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

    // Top-level layout: header, middle, footer
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // header: mode + stats
            Constraint::Min(10),   // middle: chart + query log
            Constraint::Length(3), // footer: blocklist + keybinds
        ])
        .split(size);

    render_header(frame, outer[0], state);
    render_middle(frame, outer[1], state);
    render_footer(frame, outer[2], state);
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
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(35), // QPS chart
            Constraint::Percentage(65), // Query log
        ])
        .split(area);

    render_qps_chart(frame, chunks[0], state);
    render_query_log(frame, chunks[1], state);
}

fn render_qps_chart(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let data = if state.qps_history.is_empty() {
        vec![0u64; 1]
    } else {
        state.qps_history.clone()
    };

    // How many bars fit in the available width (minus borders)
    let available_width = area.width.saturating_sub(2) as usize;
    let bar_width = 2u16;
    let gap = 1u16;
    let max_bars = available_width / (bar_width as usize + gap as usize);
    let display_data: Vec<u64> = data.iter().rev().take(max_bars).rev().copied().collect();

    let bars: Vec<Bar> = display_data
        .iter()
        .map(|&v| {
            Bar::default()
                .value(v)
                .style(Style::default().fg(Color::Cyan))
        })
        .collect();

    let chart = BarChart::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Queries/sec (last 60s) "),
        )
        .data(BarGroup::default().bars(&bars))
        .bar_width(bar_width)
        .bar_gap(gap)
        .max(display_data.iter().copied().max().unwrap_or(1).max(1));

    frame.render_widget(chart, area);
}

fn render_query_log(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let header = Row::new(vec![
        Cell::from("Domain").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Type").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Latency").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Method").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
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

            Row::new(vec![
                Cell::from(truncate_domain(&q.domain, 35)),
                Cell::from(q.record_type.as_str()),
                Cell::from(format!("{:.1}ms", q.latency_ms)),
                Cell::from(q.method.as_str()).style(Style::default().fg(method_color)),
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

fn render_footer(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let _ = state;
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("  q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(" quit  ", Style::default().fg(Color::DarkGray)),
        Span::styled("r", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(" refresh blocklist  ", Style::default().fg(Color::DarkGray)),
        Span::styled("↑↓", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(" scroll log", Style::default().fg(Color::DarkGray)),
    ]))
    .wrap(Wrap { trim: false })
    .block(Block::default().borders(Borders::ALL).title(" Keys "));
    frame.render_widget(footer, area);
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
