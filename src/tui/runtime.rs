use crate::app::wiring::create_vault_service_with_warnings;
use crate::config::app_config::Config;
use crate::error::{TuiError, TuiResult};
use crossterm::event::KeyCode::{self, Char};
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::backend::CrosstermBackend;
use ratatui::{backend::Backend, Terminal};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::spawn_blocking;

use crate::filesystem::clipboard::ttl_seconds;
use crate::tui::app::Mode;
use crate::tui::app::{App, View};
use crate::tui::views::confirm::render_confirm;
use crate::tui::views::details::render_details;
use crate::tui::views::form::render_form;
use crate::tui::views::list::render_list;
use crate::vault::service::VaultService;

struct TerminalGuard;

impl TerminalGuard {
    fn activate() -> TuiResult<Self> {
        enable_raw_mode()?;
        crossterm::execute!(io::stdout(), crossterm::terminal::EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(
            io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::cursor::Show
        );
    }
}

pub async fn launch(config: &Config) -> TuiResult<()> {
    let warnings = Arc::new(crate::session_management::warnings::CacheWarnings::default());
    let service = create_vault_service_with_warnings(config, warnings.sink());

    // Load entries (may prompt for password if no session cache) without blocking the async runtime
    let svc = service.clone();
    let entries = spawn_blocking(move || svc.load())
        .await
        .map_err(TuiError::from)?
        .map_err(|e| TuiError::Message(format!("failed to load vault for TUI: {e}")))?;

    let (mut terminal, _guard) = setup_terminal()?;

    let ttl_secs = ttl_seconds(config, None);
    let mut app = App::new(entries.entries);
    let tick_rate = Duration::from_millis(200);

    let res = run_loop(
        &mut terminal,
        &mut app,
        tick_rate,
        ttl_secs,
        service.clone(),
        warnings,
    )
    .await;
    terminal.show_cursor()?;
    res
}

fn setup_terminal() -> TuiResult<(Terminal<CrosstermBackend<io::Stdout>>, TerminalGuard)> {
    let guard = TerminalGuard::activate()?;
    let backend = CrosstermBackend::new(io::stdout());
    let terminal = Terminal::new(backend)?;
    Ok((terminal, guard))
}

fn render_current_view<BackendType: Backend>(
    terminal: &mut Terminal<BackendType>,
    app: &App,
) -> Result<(), BackendType::Error> {
    terminal.draw(|f| {
        match app.view {
            View::List => render_list(f, app),
            View::Details => render_details(f, app),
            View::AddModal | View::EditModal => render_form(f, app),
            View::ConfirmDelete => render_confirm(f, app),
        }
        crate::tui::views::cache_warning::render_cache_warning(f, app);
    })?;
    Ok(())
}

fn should_quit(code: KeyCode, app: &App) -> bool {
    code == Char('q') && app.view == View::List && app.mode == Mode::Normal
}

fn next_timeout(last_tick: Instant, tick_rate: Duration) -> Duration {
    tick_rate
        .checked_sub(last_tick.elapsed())
        .unwrap_or(Duration::from_millis(0))
}

async fn run_loop<StoreType, CodecType, ResolverType>(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    tick_rate: Duration,
    ttl_secs: u64,
    service: Arc<VaultService<StoreType, CodecType, ResolverType>>,
    warnings: Arc<crate::session_management::warnings::CacheWarnings>,
) -> TuiResult<()>
where
    StoreType: crate::vault::ports::ByteStore + 'static,
    CodecType: crate::vault::ports::VaultCodec + 'static,
    ResolverType: crate::vault::ports::KeyResolver + 'static,
{
    let mut last_tick = Instant::now();
    loop {
        app.show_cache_warning(&warnings);
        render_current_view(terminal, app).map_err(TuiError::from)?;

        let timeout = next_timeout(last_tick, tick_rate);
        if event::poll(timeout)? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    if should_quit(k.code, app) {
                        return Ok(());
                    }
                    app.handle_key_event(k.code, ttl_secs, service.clone())
                        .await?;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.tick();
            last_tick = Instant::now();
        }
    }
}

#[cfg(test)]
#[path = "runtime_test.rs"]
mod tests;
