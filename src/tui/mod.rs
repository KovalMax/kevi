pub mod app;
pub(crate) mod theme;
pub mod views;

use crate::app::wiring::create_vault_service;
use crate::config::app_config::Config;
use crate::error::{TuiError, TuiResult};
use crossterm::event::KeyCode::{self, Char};
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::spawn_blocking;

use self::app::{App, View};
use self::views::confirm::render_confirm;
use self::views::details::render_details;
use self::views::form::render_form;
use self::views::list::render_list;
use crate::filesystem::clipboard::ttl_seconds;
use crate::tui::app::Mode;
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
    let service = create_vault_service(config);

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

fn render_current_view(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &App,
) -> TuiResult<()> {
    terminal.draw(|f| match app.view {
        View::List => render_list(f, app),
        View::Details => render_details(f, app),
        View::AddModal | View::EditModal => render_form(f, app),
        View::ConfirmDelete => render_confirm(f, app),
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
) -> TuiResult<()>
where
    StoreType: crate::vault::ports::ByteStore + 'static,
    CodecType: crate::vault::ports::VaultCodec + 'static,
    ResolverType: crate::vault::ports::KeyResolver + 'static,
{
    let mut last_tick = Instant::now();
    loop {
        render_current_view(terminal, app)?;

        let timeout = next_timeout(last_tick, tick_rate);
        if event::poll(timeout)? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    if should_quit(k.code, app) {
                        return Ok(());
                    }
                    app.handle_key_event(k.code, ttl_secs, service.clone()).await?;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.tick();
            last_tick = Instant::now();
        }
    }
}
