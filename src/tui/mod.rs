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

/// Input mode for the TUI
enum InputMode {
    /// Normal dashboard view
    Normal,
    /// Typing a name for a new blocklist source
    AddName(String),
    /// Typing a URL for a new blocklist source (name already captured)
    AddUrl { name: String, url: String },
    /// Selecting a blocklist source to delete (shows numbered list)
    Delete,
}

/// Status message shown temporarily in the footer
struct StatusMessage {
    text: String,
    expires: std::time::Instant,
}

/// Run the TUI connected to the metrics HTTP endpoint
pub fn run_remote(metrics_url: &str, tui_config: &TuiConfig) -> Result<(), io::Error> {
    use std::sync::{Arc, Mutex};

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

    // HTTP client for POST requests (blocklist management)
    let post_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok();

    let mut last_state: Option<DashboardState> = None;
    let mut input_mode = InputMode::Normal;
    let mut status_msg: Option<StatusMessage> = None;

    loop {
        // Check for new metrics data (non-blocking)
        if let Ok(mut lock) = shared.try_lock() {
            if let Some(body) = lock.take() {
                if let Some(state) = DashboardState::from_json(&body) {
                    last_state = Some(state);
                }
            }
        }

        // Clear expired status messages
        if let Some(ref msg) = status_msg {
            if std::time::Instant::now() > msg.expires {
                status_msg = None;
            }
        }

        // Build overlay info for rendering
        let input_overlay = match &input_mode {
            InputMode::Normal => None,
            InputMode::AddName(name) => {
                Some(format!("Add blocklist — Name: {name}█  (Enter to confirm, Esc to cancel)"))
            }
            InputMode::AddUrl { name, url } => {
                Some(format!("Add blocklist \"{name}\" — URL: {url}█  (Enter to confirm, Esc to cancel)"))
            }
            InputMode::Delete => {
                let sources = last_state
                    .as_ref()
                    .map(|s| &s.config.blocklist_sources)
                    .cloned()
                    .unwrap_or_default();
                if sources.is_empty() {
                    Some("No blocklist sources to remove. (Esc to go back)".to_string())
                } else {
                    let list: Vec<String> = sources
                        .iter()
                        .enumerate()
                        .map(|(i, s)| format!("  {}. {} ({})", i + 1, s.name, s.url))
                        .collect();
                    Some(format!(
                        "Remove blocklist — press number to delete:\n{}\n  (Esc to cancel)",
                        list.join("\n")
                    ))
                }
            }
        };

        let status_text = status_msg.as_ref().map(|m| m.text.clone());

        // Render
        if let Some(ref state) = last_state {
            terminal.draw(|frame| {
                dashboard::render_with_overlay(frame, state, input_overlay.as_deref(), status_text.as_deref())
            })?;
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
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match &mut input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('r') => {
                            // Trigger blocklist refresh
                            if let Some(ref client) = post_client {
                                let refresh_url = format!("{}blocklist/refresh", url);
                                match client.post(&refresh_url).send() {
                                    Ok(_) => {
                                        status_msg = Some(StatusMessage {
                                            text: "Blocklist refresh triggered".to_string(),
                                            expires: std::time::Instant::now() + Duration::from_secs(3),
                                        });
                                    }
                                    Err(e) => {
                                        status_msg = Some(StatusMessage {
                                            text: format!("Refresh failed: {e}"),
                                            expires: std::time::Instant::now() + Duration::from_secs(5),
                                        });
                                    }
                                }
                            }
                        }
                        KeyCode::Char('a') => {
                            input_mode = InputMode::AddName(String::new());
                        }
                        KeyCode::Char('d') => {
                            input_mode = InputMode::Delete;
                        }
                        _ => {}
                    },
                    InputMode::AddName(name) => match key.code {
                        KeyCode::Char(c) => name.push(c),
                        KeyCode::Backspace => { name.pop(); }
                        KeyCode::Enter => {
                            if !name.is_empty() {
                                let captured_name = name.clone();
                                input_mode = InputMode::AddUrl {
                                    name: captured_name,
                                    url: String::new(),
                                };
                            }
                        }
                        KeyCode::Esc => {
                            input_mode = InputMode::Normal;
                        }
                        _ => {}
                    },
                    InputMode::AddUrl { name, url: input_url } => match key.code {
                        KeyCode::Char(c) => input_url.push(c),
                        KeyCode::Backspace => { input_url.pop(); }
                        KeyCode::Enter => {
                            if !input_url.is_empty() {
                                if let Some(ref client) = post_client {
                                    let add_url = format!("{}blocklist/add", url);
                                    let body = format!(
                                        r#"{{"name":"{}","url":"{}"}}"#,
                                        name.replace('"', "\\\""),
                                        input_url.replace('"', "\\\""),
                                    );
                                    let result = client.post(&add_url)
                                        .header("Content-Type", "application/json")
                                        .body(body)
                                        .send();
                                    match result {
                                        Ok(resp) => {
                                            if resp.status().is_success() {
                                                status_msg = Some(StatusMessage {
                                                    text: format!("Added blocklist \"{}\"", name),
                                                    expires: std::time::Instant::now() + Duration::from_secs(3),
                                                });
                                            } else {
                                                let err = resp.text().unwrap_or_default();
                                                status_msg = Some(StatusMessage {
                                                    text: format!("Failed to add: {err}"),
                                                    expires: std::time::Instant::now() + Duration::from_secs(5),
                                                });
                                            }
                                        }
                                        Err(e) => {
                                            status_msg = Some(StatusMessage {
                                                text: format!("Error: {e}"),
                                                expires: std::time::Instant::now() + Duration::from_secs(5),
                                            });
                                        }
                                    }
                                }
                                input_mode = InputMode::Normal;
                            }
                        }
                        KeyCode::Esc => {
                            input_mode = InputMode::Normal;
                        }
                        _ => {}
                    },
                    InputMode::Delete => match key.code {
                        KeyCode::Char(c) if c.is_ascii_digit() && c != '0' => {
                            let idx = (c as u8 - b'1') as usize;
                            let sources = last_state
                                .as_ref()
                                .map(|s| &s.config.blocklist_sources)
                                .cloned()
                                .unwrap_or_default();
                            if let Some(source) = sources.get(idx) {
                                if let Some(ref client) = post_client {
                                    let remove_url = format!("{}blocklist/remove", url);
                                    let body = format!(
                                        r#"{{"name":"{}"}}"#,
                                        source.name.replace('"', "\\\""),
                                    );
                                    let result = client.post(&remove_url)
                                        .header("Content-Type", "application/json")
                                        .body(body)
                                        .send();
                                    match result {
                                        Ok(resp) => {
                                            if resp.status().is_success() {
                                                status_msg = Some(StatusMessage {
                                                    text: format!("Removed blocklist \"{}\"", source.name),
                                                    expires: std::time::Instant::now() + Duration::from_secs(3),
                                                });
                                            } else {
                                                let err = resp.text().unwrap_or_default();
                                                status_msg = Some(StatusMessage {
                                                    text: format!("Failed to remove: {err}"),
                                                    expires: std::time::Instant::now() + Duration::from_secs(5),
                                                });
                                            }
                                        }
                                        Err(e) => {
                                            status_msg = Some(StatusMessage {
                                                text: format!("Error: {e}"),
                                                expires: std::time::Instant::now() + Duration::from_secs(5),
                                            });
                                        }
                                    }
                                }
                                input_mode = InputMode::Normal;
                            }
                        }
                        KeyCode::Esc => {
                            input_mode = InputMode::Normal;
                        }
                        _ => {}
                    },
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
