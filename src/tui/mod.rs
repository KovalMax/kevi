pub mod app;
pub mod theme;
pub mod views;

use crate::config::app_config::{Config, Defaults};
use anyhow::{anyhow, Result};
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
use crate::filesystem::store::FileByteStore;
use crate::session_management::resolver::CachedKeyResolver;
use crate::tui::app::Mode;
use crate::vault::codec::RonCodec;
use crate::vault::ports::{ByteStore, KeyResolver, VaultCodec};
use crate::vault::service::VaultService;

struct TerminalGuard;

impl TerminalGuard {
    fn activate() -> Result<Self> {
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

pub async fn launch(config: &Config) -> Result<()> {
    // Compose service (same defaults as CLI flows)
    let backups = config.backups.unwrap_or(Defaults::BACKUPS);
    let vault_path: std::path::PathBuf = config.vault_path.clone().into();
    let store: Arc<dyn ByteStore> =
        Arc::new(FileByteStore::new_with_backups(vault_path.clone(), backups));
    let codec: Arc<dyn VaultCodec> = Arc::new(RonCodec);
    let resolver: Arc<dyn KeyResolver> = Arc::new(CachedKeyResolver::new(vault_path.clone()));
    let service = Arc::new(VaultService::new(store, codec, resolver));

    // Load entries (may prompt for password if no session cache) without blocking the async runtime
    let svc = service.clone();
    let entries = spawn_blocking(move || svc.load())
        .await
        .map_err(|_| anyhow!("task join error"))?
        .map_err(|e| anyhow!("failed to load vault for TUI: {}", e))?;

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

fn setup_terminal() -> Result<(Terminal<CrosstermBackend<io::Stdout>>, TerminalGuard)> {
    let guard = TerminalGuard::activate()?;
    let backend = CrosstermBackend::new(io::stdout());
    let terminal = Terminal::new(backend)?;
    Ok((terminal, guard))
}

fn render_current_view(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &App,
) -> Result<()> {
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

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    tick_rate: Duration,
    ttl_secs: u64,
    service: Arc<VaultService>,
) -> Result<()> {
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
