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

/// Run the TUI connected to live resolver stats
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
