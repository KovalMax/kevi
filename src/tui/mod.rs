pub mod app;
pub mod theme;
pub mod views;

use crate::config::app_config::Config;
use anyhow::{anyhow, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::spawn_blocking;

use crate::core::adapters::{CachedKeyResolver, FileByteStore, RonCodec};
use crate::core::clipboard::{copy_with_ttl, ttl_seconds, SystemClipboardEngine};
use crate::core::ports::PasswordGenerator;
use crate::core::ports::{ByteStore, KeyResolver, VaultCodec};
use crate::core::service::VaultService;
use crate::core::vault::GetField;
use secrecy::SecretString;

use self::app::{App, Mode, View};
use self::views::confirm::render_confirm;
use self::views::details::render_details;
use self::views::form::render_form;
use self::views::list::render_list;

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
    let mut app = App::new(entries);
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
                    // Global per-view key handling
                    match app.view {
                        View::List => {
                            match app.mode {
                                Mode::Normal => match k.code {
                                    KeyCode::Char('q') => break Ok(()),
                                    KeyCode::Down | KeyCode::Char('j') => app.next(),
                                    KeyCode::Up | KeyCode::Char('k') => app.prev(),
                                    KeyCode::Char('/') => app.enter_search(),
                                    KeyCode::Right | KeyCode::Char('l') => app.enter_details(),
                                    KeyCode::Char('a') => app.enter_add(),
                                    KeyCode::Enter => {
                                        // Copy password (legacy behavior from list)
                                        if let Some(val) = app.selected_field(GetField::Password) {
                                            if let Ok(engine) = SystemClipboardEngine::new() {
                                                let secret = SecretString::new(val.into());
                                                let _ = copy_with_ttl(
                                                    Arc::new(engine),
                                                    &secret,
                                                    Duration::from_secs(ttl_secs),
                                                );
                                                app.toast(format!(
                                                    "Password copied ({ttl_secs}s)"
                                                ));
                                            } else {
                                                app.toast("Clipboard unavailable".to_string());
                                            }
                                        }
                                    }
                                    KeyCode::Char('u') => {
                                        if let Some(val) = app.selected_field(GetField::User) {
                                            if let Ok(engine) = SystemClipboardEngine::new() {
                                                let secret = SecretString::new(val.into());
                                                let _ = copy_with_ttl(
                                                    Arc::new(engine),
                                                    &secret,
                                                    Duration::from_secs(ttl_secs),
                                                );
                                                app.toast(format!(
                                                    "Username copied ({ttl_secs}s)"
                                                ));
                                            } else {
                                                app.toast("Clipboard unavailable".to_string());
                                            }
                                        }
                                    }
                                    _ => {}
                                },
                                Mode::Search => match k.code {
                                    KeyCode::Esc => app.exit_search(),
                                    KeyCode::Backspace => app.pop_filter(),
                                    KeyCode::Enter => app.exit_search(),
                                    KeyCode::Char(c) => app.push_filter(c),
                                    _ => {}
                                },
                            }
                        }
                        View::Details => match k.code {
                            KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => {
                                app.back_to_list()
                            }
                            KeyCode::Enter => {
                                if let Some(val) = app.selected_field(GetField::Password) {
                                    if let Ok(engine) = SystemClipboardEngine::new() {
                                        let secret = SecretString::new(val.into());
                                        let _ = copy_with_ttl(
                                            Arc::new(engine),
                                            &secret,
                                            Duration::from_secs(ttl_secs),
                                        );
                                        app.toast(format!("Password copied ({ttl_secs}s)"));
                                    } else {
                                        app.toast("Clipboard unavailable".to_string());
                                    }
                                }
                            }
                            KeyCode::Char('u') => {
                                if let Some(val) = app.selected_field(GetField::User) {
                                    if let Ok(engine) = SystemClipboardEngine::new() {
                                        let secret = SecretString::new(val.into());
                                        let _ = copy_with_ttl(
                                            Arc::new(engine),
                                            &secret,
                                            Duration::from_secs(ttl_secs),
                                        );
                                        app.toast(format!("Username copied ({ttl_secs}s)"));
                                    } else {
                                        app.toast("Clipboard unavailable".to_string());
                                    }
                                } else {
                                    app.toast("No username".to_string());
                                }
                            }
                            KeyCode::Char('v') => {
                                app.reveal_password = !app.reveal_password;
                            }
                            KeyCode::Char('e') => app.enter_edit(),
                            KeyCode::Char('a') => app.enter_add(),
                            KeyCode::Char('d') => app.enter_confirm_delete(),
                            _ => {}
                        },
                        View::AddModal | View::EditModal => {
                            match k.code {
                                KeyCode::Esc => app.cancel_modal(),
                                KeyCode::Tab => app.next_field(),
                                KeyCode::BackTab => app.prev_field(),
                                KeyCode::Backspace => app.backspace_form(),
                                KeyCode::Enter => {
                                    // Validate label
                                    let label = app.form_label.trim().to_string();
                                    if label.is_empty() {
                                        app.toast("Label required".to_string());
                                    } else {
                                        // Build entry; for Add we generate a strong password by default
                                        let is_add = matches!(app.view, View::AddModal);
                                        let current_labels: Vec<String> = app.visible_labels();
                                        if is_add && current_labels.iter().any(|l| l == &label) {
                                            app.toast("Label exists".to_string());
                                        } else {
                                            // Clone options for move into closures
                                            let user_opt = if app.form_user.trim().is_empty() {
                                                None
                                            } else {
                                                Some(app.form_user.trim().to_string())
                                            };
                                            let notes_opt = if app.form_notes.trim().is_empty() {
                                                None
                                            } else {
                                                Some(app.form_notes.trim().to_string())
                                            };
                                            let label_for_save = label.clone();
                                            let original_label = app.form_original_label.clone();
                                            let svc = service.clone();
                                            if is_add {
                                                let _ = spawn_blocking(move || {
                                                    // Generate password via default generator
                                                    let gen2 = crate::core::generator::DefaultPasswordGenerator::new(Arc::new(crate::core::generator::SystemRng));
                                                    let pw2 = gen2.generate(&crate::core::ports::GenPolicy::default())?;
                                                    let entry_real = crate::core::entry::VaultEntry {
                                                        label: label_for_save,
                                                        username: user_opt.map(|u| SecretString::new(u.into())),
                                                        password: SecretString::new(pw2.into()),
                                                        notes: notes_opt,
                                                    };
                                                    svc.add_entry(entry_real)
                                                }).await.map_err(|_| anyhow!("task join error"))?;
                                            } else {
                                                spawn_blocking(move || {
                                                    let mut vault_entries = svc.load()?;
                                                    if let Some(pos) = vault_entries
                                                        .iter()
                                                        .position(|e| e.label == original_label)
                                                    {
                                                        vault_entries[pos].label = label_for_save;
                                                        vault_entries[pos].username = user_opt
                                                            .map(|u| SecretString::new(u.into()));
                                                        vault_entries[pos].notes = notes_opt;
                                                        svc.save(&vault_entries)
                                                    } else {
                                                        Ok(())
                                                    }
                                                })
                                                .await
                                                .map_err(|_| anyhow!("task join error"))??;
                                            }
                                            // Reload entries
                                            let svc_reload = service.clone();
                                            let new_entries =
                                                spawn_blocking(move || svc_reload.load())
                                                    .await
                                                    .map_err(|_| anyhow!("task join error"))??;
                                            app.replace_entries(new_entries);
                                            app.view = View::List;
                                            app.toast("Saved".to_string());
                                        }
                                    }
                                }
                                KeyCode::Char(c) => {
                                    if !c.is_control() {
                                        app.update_form_char(c);
                                    }
                                }
                                _ => {}
                            }
                        }
                        View::ConfirmDelete => {
                            match k.code {
                                KeyCode::Esc | KeyCode::Char('n') => app.cancel_confirm_delete(),
                                KeyCode::Char('y') => {
                                    if let Some(label) = app.selected_label() {
                                        let svc_rm = service.clone();
                                        let _ = spawn_blocking(move || svc_rm.remove_entry(&label))
                                            .await;
                                        // Reload
                                        let svc_reload = service.clone();
                                        if let Ok(Ok(ents)) =
                                            spawn_blocking(move || svc_reload.load())
                                                .await
                                                .map_err(|_| anyhow!("task join error"))
                                        {
                                            app.replace_entries(ents);
                                        }
                                        app.view = View::List;
                                        app.toast("Deleted".to_string());
                                    } else {
                                        app.cancel_confirm_delete();
                                    }
                                }
                                _ => {}
                            }
                        }
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
