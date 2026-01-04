pub mod app;
pub mod theme;
pub mod views;

use crate::config::app_config::Config;
use anyhow::{anyhow, Result};
use crossterm::event::KeyCode::Char;
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

pub async fn launch(config: &Config) -> Result<()> {
    // Compose service (same defaults as CLI flows)
    let store: Arc<dyn ByteStore> = Arc::new(FileByteStore::new(config.vault_path.clone()));
    let codec: Arc<dyn VaultCodec> = Arc::new(RonCodec);
    let resolver: Arc<dyn KeyResolver> =
        Arc::new(CachedKeyResolver::new(config.vault_path.clone()));
    let service = Arc::new(VaultService::new(store, codec, resolver));

    // Load entries (may prompt for password if no session cache) without blocking the async runtime
    let svc = service.clone();
    let entries = spawn_blocking(move || svc.load())
        .await
        .map_err(|_| anyhow!("task join error"))?
        .map_err(|e| anyhow!("failed to load vault for TUI: {}", e))?;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let ttl_secs = ttl_seconds(config, None);
    let mut app = App::new(entries.entries);
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(200);

    let res = loop {
        terminal.draw(|f| match app.view {
            View::List => render_list(f, &app),
            View::Details => render_details(f, &app),
            View::AddModal | View::EditModal => render_form(f, &app),
            View::ConfirmDelete => render_confirm(f, &app),
        })?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_millis(0));

        if event::poll(timeout)? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    if k.code == Char('q') && app.view == View::List && app.mode == Mode::Normal {
                        break Ok(());
                    } else {
                        app.handle_key_event(k.code, ttl_secs, service.clone())
                            .await?
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.tick();
            last_tick = Instant::now();
        }
    };

    // Restore terminal
    disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::cursor::Show
    )?;
    terminal.show_cursor()?;

    res
}
