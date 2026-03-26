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
    let mut terminal = setup_terminal()?;
    let tick_rate = Duration::from_millis(tui_config.tick_rate_ms);
    let url = metrics_url.to_string();

    // We need a runtime for the HTTP client
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut last_state: Option<DashboardState> = None;
    let mut error_msg: Option<String> = None;

    loop {
        // Fetch metrics
        match client.get(&url).send() {
            Ok(resp) => {
                if let Ok(body) = resp.text() {
                    if let Some(state) = DashboardState::from_json(&body) {
                        error_msg = None;
                        last_state = Some(state);
                    }
                }
            }
            Err(e) => {
                error_msg = Some(format!("Cannot connect to resolver: {e}"));
            }
        }

        // Render
        if let Some(ref state) = last_state {
            terminal.draw(|frame| dashboard::render(frame, state))?;
        } else {
            // Show connection error
            let msg = error_msg.as_deref().unwrap_or("Connecting to resolver...");
            terminal.draw(|frame| {
                let area = frame.area();
                let block = ratatui::widgets::Paragraph::new(format!(
                    "\n  Meridian TUI\n\n  {msg}\n\n  Metrics endpoint: {url}\n\n  Press q to quit"
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

    let _ = rt; // keep runtime alive
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
