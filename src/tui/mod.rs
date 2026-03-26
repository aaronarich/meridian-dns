pub mod dashboard;

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::config::{ResolverMode, TuiConfig};
use crate::stats::SharedStats;
use dashboard::DashboardState;

/// Run the TUI connected to the metrics HTTP endpoint
pub fn run_remote(metrics_url: &str, tui_config: &TuiConfig) -> Result<(), io::Error> {
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    let mut terminal = setup_terminal()?;
    let tick_rate = Duration::from_millis(tui_config.tick_rate_ms);
    let url = metrics_url.to_string();

    // Shared state between fetcher thread and render loop
    let shared: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let shared_writer = shared.clone();
    let fetch_url = url.clone();
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let running_flag = running.clone();

    // Background thread fetches metrics every second
    let fetcher = std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .ok();
        let client = match client {
            Some(c) => c,
            None => return,
        };
        while running_flag.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(resp) = client.get(&fetch_url).send() {
                if let Ok(body) = resp.text() {
                    if let Ok(mut lock) = shared_writer.lock() {
                        *lock = Some(body);
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });

    let mut last_state: Option<DashboardState> = None;
    let mut qps_history: Vec<u64> = Vec::new();
    let mut last_total_queries: Option<u64> = None;
    let mut last_sample = Instant::now();

    loop {
        // Check for new metrics data (non-blocking)
        if let Ok(mut lock) = shared.try_lock() {
            if let Some(body) = lock.take() {
                if let Some(mut state) = DashboardState::from_json(&body) {
                    // Build QPS history from delta between fetches
                    let now = Instant::now();
                    let elapsed = now.duration_since(last_sample).as_secs_f64();
                    if let Some(prev) = last_total_queries {
                        if elapsed > 0.0 {
                            let delta = state.total_queries.saturating_sub(prev);
                            let qps = (delta as f64 / elapsed).round() as u64;
                            qps_history.push(qps);
                            if qps_history.len() > 60 {
                                qps_history.remove(0);
                            }
                        }
                    }
                    last_total_queries = Some(state.total_queries);
                    last_sample = now;

                    state.qps_history = qps_history.clone();
                    last_state = Some(state);
                }
            }
        }

        // Render
        if let Some(ref state) = last_state {
            terminal.draw(|frame| dashboard::render(frame, state))?;
        } else {
            terminal.draw(|frame| {
                let area = frame.area();
                let block = ratatui::widgets::Paragraph::new(format!(
                    "\n  Meridian TUI\n\n  Connecting to resolver...\n\n  Metrics endpoint: {url}\n\n  Press q to quit"
                ))
                .block(
                    ratatui::widgets::Block::default()
                        .borders(ratatui::widgets::Borders::ALL)
                        .title(" Meridian "),
                );
                frame.render_widget(block, area);
            })?;
        }

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    running.store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = fetcher.join();
    restore_terminal(&mut terminal)?;
    Ok(())
}

/// Run the TUI in demo mode (no live resolver connection)
pub fn run_demo(tui_config: &TuiConfig) -> Result<(), io::Error> {
    let mut terminal = setup_terminal()?;
    let tick_rate = Duration::from_millis(tui_config.tick_rate_ms);

    loop {
        let state = DashboardState::demo();
        terminal.draw(|frame| dashboard::render(frame, &state))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    restore_terminal(&mut terminal)?;
    Ok(())
}

/// Run the TUI connected to live resolver stats (same process)
pub fn run_live(
    stats: SharedStats,
    mode: &ResolverMode,
    tui_config: &TuiConfig,
) -> Result<(), io::Error> {
    let mut terminal = setup_terminal()?;
    let tick_rate = Duration::from_millis(tui_config.tick_rate_ms);

    loop {
        let state = DashboardState::from_stats(&stats, mode);
        terminal.draw(|frame| dashboard::render(frame, &state))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('r') => {
                            // TODO: trigger blocklist refresh
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    restore_terminal(&mut terminal)?;
    Ok(())
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>, io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn restore_terminal(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<(), io::Error> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
