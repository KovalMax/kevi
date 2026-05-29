use crossterm::event::KeyCode;
use kevi::api::{
    render_list, App, CachedKeyResolver, FileByteStore, FormField, Mode, RonCodec, VaultEntry,
    VaultService, View,
};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use secrecy::SecretString;
use std::env;
use std::sync::Arc;
use tempfile::tempdir;

fn entry(label: &str, pw: Option<&str>) -> VaultEntry {
    let pw = pw.unwrap_or("test");
    VaultEntry {
        label: label.into(),
        username: None,
        password: SecretString::new(pw.to_string().into()),
        notes: None,
    }
}

#[test]
fn tui_renders_labels_and_never_secrets() {
    let entries = vec![
        entry("alpha", Some("secret123")),
        entry("beta", Some("topsecret")),
    ];
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
    let entries = vec![
        entry("alpha", None),
        entry("beta", None),
        entry("gamma", None),
    ];
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
    let entries = vec![entry("a", None), entry("b", None), entry("c", None)];
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
    let entries = vec![
        entry("alpha", None),
        entry("beta", None),
        entry("gamma", None),
    ];
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
    let entries = vec![entry("alpha", None)];
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
    let entries = vec![entry("alpha", None)];
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
    let entries = vec![entry("a", None), entry("b", None), entry("c", None)];

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
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    env::set_var("KEVI_PASSWORD", "svcpass");
    let store = Arc::new(FileByteStore::new(path.clone()));
    let codec = Arc::new(RonCodec);
    let resolver = Arc::new(CachedKeyResolver::new(path.clone()));
    let service = Arc::new(VaultService::new(store, codec, resolver));

    let entries = vec![entry("art", None), entry("bow", None), entry("cross", None)];
    let mut app = App::new(entries);
    app.enter_search();

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

#[tokio::test]
async fn confirm_delete_modal() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    env::set_var("KEVI_PASSWORD", "svcpass");
    let store = Arc::new(FileByteStore::new(path.clone()));
    let codec = Arc::new(RonCodec);
    let resolver = Arc::new(CachedKeyResolver::new(path.clone()));
    let service = Arc::new(VaultService::new(store, codec, resolver));

    let entries = vec![entry("to-delete", None)];
    let mut app = App::new(entries);
    app.enter_confirm_delete();
    assert_eq!(app.view, View::ConfirmDelete);

    // n → cancel
    app.handle_key_event(KeyCode::Char('n'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::Details);

    app.handle_key_event(KeyCode::Char('d'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::ConfirmDelete);

    // y → delete
    app.handle_key_event(KeyCode::Char('y'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::List);
    assert_eq!(app.visible_labels().len(), 0);
}

#[tokio::test]
async fn edit_modal_form_navigation() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    env::set_var("KEVI_PASSWORD", "svcpass");
    let store = Arc::new(FileByteStore::new(path.clone()));
    let codec = Arc::new(RonCodec);
    let resolver = Arc::new(CachedKeyResolver::new(path.clone()));
    let service = Arc::new(VaultService::new(store, codec, resolver));

    let entries = vec![VaultEntry {
        label: "edit-me".into(),
        username: Some(SecretString::new("olduser".into())),
        password: SecretString::new("oldpass".into()),
        notes: Some("old-note".into()),
    }];
    let mut app = App::new(entries);
    app.enter_edit();
    assert_eq!(app.view, View::EditModal);

    // Form should be pre-filled
    assert_eq!(app.form_label, "edit-me");
    assert_eq!(app.form_user, "olduser");
    assert_eq!(app.form_password, "oldpass");
    assert_eq!(app.form_notes, "old-note");

    // Same navigation as add modal
    app.handle_key_event(KeyCode::Tab, 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.form_field, FormField::User);

    app.handle_key_event(KeyCode::Tab, 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.form_field, FormField::Password);

    // Enter → save (validation happens in real handler)
    app.handle_key_event(KeyCode::Enter, 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::List);

    // Esc → cancel
    app.enter_edit();
    app.handle_key_event(KeyCode::Esc, 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::List); // Edit cancel → back to details
}

#[tokio::test]
async fn list_normal_mode_basic_navigation() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    env::set_var("KEVI_PASSWORD", "svcpass");
    let store = Arc::new(FileByteStore::new(path.clone()));
    let codec = Arc::new(RonCodec);
    let resolver = Arc::new(CachedKeyResolver::new(path.clone()));
    let service = Arc::new(VaultService::new(store, codec, resolver));

    let entries = vec![
        entry("alpha", None),
        entry("beta", None),
        entry("gamma", None),
    ];
    let mut app = App::new(entries);
    assert_eq!(app.view, View::List);
    assert_eq!(app.mode, Mode::Normal);

    // j/down → next
    app.handle_key_event(KeyCode::Char('j'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.selected, 1);

    // k/up → prev
    app.handle_key_event(KeyCode::Char('k'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.selected, 0);

    // / → enter search
    app.handle_key_event(KeyCode::Char('/'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.mode, Mode::Search);

    app.handle_key_event(KeyCode::Esc, 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.mode, Mode::Normal);

    // l/right → details
    app.handle_key_event(KeyCode::Char('l'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::Details);

    // e → edit
    app.handle_key_event(KeyCode::Char('e'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::EditModal);

    // esc -> list
    app.handle_key_event(KeyCode::Esc, 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::List);

    // a → add
    app.handle_key_event(KeyCode::Char('a'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::AddModal);

    // esc -> list
    app.handle_key_event(KeyCode::Esc, 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::List);

    // left → details
    app.handle_key_event(KeyCode::Right, 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::Details);

    // d → delete modal
    app.handle_key_event(KeyCode::Char('d'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::ConfirmDelete);
}

#[tokio::test]
async fn empty_state_handling() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    env::set_var("KEVI_PASSWORD", "svcpass");
    let store = Arc::new(FileByteStore::new(path.clone()));
    let codec = Arc::new(RonCodec);
    let resolver = Arc::new(CachedKeyResolver::new(path.clone()));
    let service = Arc::new(VaultService::new(store, codec, resolver));

    let mut app = App::new(vec![]); // No entries
    assert_eq!(app.visible_labels().len(), 0);

    app.handle_key_event(KeyCode::Down, 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.selected, 0); // No crash, stays at 0

    app.handle_key_event(KeyCode::Char('l'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.view, View::Details); // Allow details on empty?

    app.enter_search();
    assert_eq!(app.mode, Mode::Search);
    app.handle_key_event(KeyCode::Char('t'), 15, service.clone())
        .await
        .unwrap();
    assert_eq!(app.visible_labels().len(), 0); // Filter on empty stays empty
}
