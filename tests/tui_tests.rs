use crossterm::event::KeyCode;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use std::env;
use std::sync::Arc;

use kevi::filesystem::store::FileByteStore;
use kevi::session_management::resolver::CachedKeyResolver;
use kevi::tui::app::{App, Mode, View};
use kevi::tui::views::list::render_list;
use kevi::vault::codec::RonCodec;
use kevi::vault::models::VaultEntry;
use kevi::vault::service::VaultService;
use secrecy::SecretString;
use tempfile::tempdir;

fn make(label: &str, pw: &str) -> VaultEntry {
    VaultEntry {
        label: label.into(),
        username: None,
        password: SecretString::new(pw.to_string().into()),
        notes: None,
    }
}

#[test]
fn tui_renders_labels_and_never_secrets() {
    let entries = vec![make("alpha", "secret123"), make("beta", "topsecret")];
    let app = App::new(entries);

    let backend = TestBackend::new(60, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| {
            render_list(f, &app);
        })
        .unwrap();

    // Inspect buffer for content
    let buf = terminal.backend().buffer().clone();
    let mut all = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            let cell = buf.cell((x, y)).unwrap();
            all.push_str(cell.symbol().as_ref());
        }
        all.push('\n');
    }

    assert!(all.contains("alpha"));
    assert!(all.contains("beta"));
    assert!(!all.contains("secret123"));
    assert!(!all.contains("topsecret"));
}

#[test]
fn filtering_updates_visible_labels() {
    let entries = vec![make("alpha", "x"), make("beta", "x"), make("gamma", "x")];
    let mut app = App::new(entries);
    assert_eq!(app.visible_labels(), vec!["alpha", "beta", "gamma"]);
    app.enter_search();
    app.push_filter('a');
    // all include 'a'
    assert_eq!(app.visible_labels(), vec!["alpha", "beta", "gamma"]);
    app.push_filter('l');
    assert_eq!(app.visible_labels(), vec!["alpha"]);
    app.pop_filter();
    assert_eq!(app.visible_labels(), vec!["alpha", "beta", "gamma"]);
}

#[test]
fn navigation_wraps_and_ignores_empty() {
    let entries = vec![make("a", "x"), make("b", "x"), make("c", "x")];
    let mut app = App::new(entries);

    assert_eq!(app.selected, 0);
    app.next();
    assert_eq!(app.selected, 1);
    app.next();
    app.next(); // should clamp at last
    assert_eq!(app.selected, 2);
    app.prev();
    assert_eq!(app.selected, 1);
}

#[test]
fn search_filters_and_resets_selection() {
    let entries = vec![make("alpha", "x"), make("beta", "x"), make("gamma", "x")];
    let mut app = App::new(entries);

    app.enter_search();
    app.push_filter('a');
    assert_eq!(app.visible_labels(), vec!["alpha", "beta", "gamma"]);
    app.push_filter('l'); // "al"
    assert_eq!(app.visible_labels(), vec!["alpha"]);
    app.pop_filter(); // back to "a"
    assert_eq!(app.visible_labels(), vec!["alpha", "beta", "gamma"]);
    app.exit_search();
    assert_eq!(app.mode, Mode::Normal);
}

#[test]
fn view_transitions_and_form_state() {
    let entries = vec![make("alpha", "x")];
    let mut app = App::new(entries);

    app.enter_details();
    assert_eq!(app.view, View::Details);

    app.enter_add();
    assert_eq!(app.view, View::AddModal);
    assert!(app.form_label.is_empty());

    // simulate editing then cancel
    app.update_form_char('x');
    assert_eq!(app.form_label, "x");
    app.backspace_form();
    assert!(app.form_label.is_empty());
    app.cancel_modal();
    assert_eq!(app.view, View::List);
}

#[test]
fn toast_and_tick_clears_message() {
    let entries = vec![make("alpha", "x")];
    let mut app = App::new(entries);

    app.toast("hello".to_string());
    assert_eq!(app.toast_message(), Some("hello"));

    for _ in 0..20 {
        app.tick();
    }

    assert!(app.toast_message().is_none());
}

#[tokio::test]
async fn list_navigation_keys_update_app_state() {
    let entries = vec![make("a", "x"), make("b", "x"), make("c", "x")];

    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    env::set_var("KEVI_PASSWORD", "svcpass");
    let store = Arc::new(FileByteStore::new(path.clone()));
    let codec = Arc::new(RonCodec);
    let resolver = Arc::new(CachedKeyResolver::new(path.clone()));
    let service = Arc::new(VaultService::new(store, codec, resolver));

    let mut app = App::new(entries);
    assert_eq!(app.selected, 0);

    app.handle_key_event(KeyCode::Down, 10, service.clone())
        .await
        .unwrap();
    assert_eq!(app.selected, 1);

    app.handle_key_event(KeyCode::Char('j'), 10, service.clone())
        .await
        .unwrap();
    assert_eq!(app.selected, 2);

    app.handle_key_event(KeyCode::Char('/'), 10, service.clone())
        .await
        .unwrap();
    assert_eq!(app.mode, Mode::Search);
}

#[tokio::test]
async fn search_mode_handles_chars_and_backspace() {
    let entries = vec![make("art", "x"), make("bow", "x"), make("cross", "x")];
    let mut app = App::new(entries);
    app.enter_search();

    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    env::set_var("KEVI_PASSWORD", "svcpass");
    let store = Arc::new(FileByteStore::new(path.clone()));
    let codec = Arc::new(RonCodec);
    let resolver = Arc::new(CachedKeyResolver::new(path.clone()));
    let service = Arc::new(VaultService::new(store, codec, resolver));

    app.handle_key_event(KeyCode::Char('f'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.filter, "f");

    app.handle_key_event(KeyCode::Backspace, 15, service.clone())
        .await
        .unwrap();
    assert!(app.filter.is_empty());

    app.handle_key_event(KeyCode::Esc, 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.mode, Mode::Normal);
}
