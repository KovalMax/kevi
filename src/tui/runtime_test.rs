use super::{next_timeout, render_current_view, should_quit};
use crate::session_management::warnings::CacheWarnings;
use crate::tui::app::{App, Mode, View};
use crate::vault::models::VaultEntry;
use crossterm::event::KeyCode;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use secrecy::SecretString;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn entry(label: &str) -> VaultEntry {
    VaultEntry {
        label: label.into(),
        username: None,
        password: SecretString::new("pw".into()),
        notes: None,
    }
}

#[test]
fn should_quit_only_in_list_normal_on_q() {
    let mut app = App::new(vec![entry("a")]);
    app.view = View::List;
    app.mode = Mode::Normal;
    assert!(should_quit(KeyCode::Char('q'), &app));
    app.mode = Mode::Search;
    assert!(!should_quit(KeyCode::Char('q'), &app));
    app.mode = Mode::Normal;
    app.view = View::Details;
    assert!(!should_quit(KeyCode::Char('q'), &app));
    app.view = View::List;
    assert!(!should_quit(KeyCode::Esc, &app));
}

#[test]
fn next_timeout_never_returns_negative_duration() {
    let timeout = next_timeout(Instant::now(), Duration::from_millis(5));
    assert!(timeout <= Duration::from_millis(5));
    std::thread::sleep(Duration::from_millis(2));
    let clamped = next_timeout(Instant::now() - Duration::from_millis(2), Duration::ZERO);
    assert_eq!(clamped, Duration::ZERO);
}

fn terminal_text(terminal: &Terminal<TestBackend>) -> String {
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn cache_warnings_remain_visible_across_views_and_ticks_until_acknowledged() {
    let warnings = Arc::new(CacheWarnings::default());
    let sink = warnings.sink();
    sink(crate::session_management::resolver::CacheWarning::Failure(
        crate::error::CacheError::Unavailable,
    ));
    sink(crate::session_management::resolver::CacheWarning::Failure(
        crate::error::CacheError::Denied,
    ));
    let mut app = App::new(vec![entry("a")]);
    let mut terminal = Terminal::new(TestBackend::new(60, 12)).unwrap();

    for view in [View::Details, View::AddModal, View::ConfirmDelete] {
        app.view = view;
        app.show_cache_warning(&warnings);
        app.tick();
        render_current_view(&mut terminal, &app).unwrap();
        assert!(terminal_text(&terminal).contains("Session cache store unavailable"));
        assert!(app.cache_warning_message().is_some());
    }

    app.acknowledge_cache_warning();
    app.show_cache_warning(&warnings);
    render_current_view(&mut terminal, &app).unwrap();
    assert!(terminal_text(&terminal).contains("Session cache access denied"));
}
