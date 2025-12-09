use ratatui::backend::TestBackend;
use ratatui::Terminal;

use kevi::core::entry::VaultEntry;
use kevi::tui::app::App;
use kevi::tui::views::confirm::render_confirm;
use kevi::tui::views::details::render_details;
use kevi::tui::views::form::render_form;
use secrecy::SecretString;

fn make(label: &str, user: Option<&str>, pw: &str, notes: Option<&str>) -> VaultEntry {
    VaultEntry {
        label: label.into(),
        username: user.map(|u| SecretString::new(u.into())),
        password: SecretString::new(pw.to_string().into()),
        notes: notes.map(|n| n.into()),
    }
}

fn buffer_to_string(t: &Terminal<TestBackend>) -> String {
    let buf = t.backend().buffer().clone();
    let mut all = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            let cell = buf.cell((x, y)).unwrap();
            all.push_str(cell.symbol().as_ref());
        }
        all.push('\n');
    }
    all
}

#[test]
fn details_view_masks_secrets() {
    let entries = vec![make("alpha", Some("alice"), "secret123", Some("noteZ"))];
    let mut app = App::new(entries);
    app.enter_details();

    let backend = TestBackend::new(60, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render_details(f, &app)).unwrap();

    let all = buffer_to_string(&terminal);
    assert!(all.contains("alpha"));

    // User and Notes are visible now
    assert!(all.contains("alice"));
    assert!(all.contains("noteZ"));

    // Password should be masked by default
    assert!(!all.contains("secret123"));
    assert!(all.contains("********"));

    // Test reveal
    app.reveal_password = true;
    terminal.draw(|f| render_details(f, &app)).unwrap();
    let all_revealed = buffer_to_string(&terminal);
    assert!(all_revealed.contains("secret123"));
}

#[test]
fn form_view_renders_fields_without_secrets_echo() {
    let entries = vec![make("alpha", Some("alice"), "secret123", Some("noteZ"))];
    let mut app = App::new(entries);
    app.enter_add();
    app.form_label = "new".to_string();
    app.form_user = "bob".to_string();
    app.form_notes = "n".to_string();

    let backend = TestBackend::new(60, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render_form(f, &app)).unwrap();
    let all = buffer_to_string(&terminal);

    // Shows typed form fields
    assert!(all.contains("Label: new"));
    assert!(all.contains("Username: bob"));
    assert!(all.contains("Notes: n"));
    // Does not render any current entry secret
    assert!(!all.contains("secret123"));
}

#[test]
fn confirm_delete_overlay_shows_label_only() {
    let entries = vec![make("alpha", Some("alice"), "secret123", Some("noteZ"))];
    let mut app = App::new(entries);
    app.enter_details();
    app.enter_confirm_delete();

    let backend = TestBackend::new(60, 6);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render_confirm(f, &app)).unwrap();
    let all = buffer_to_string(&terminal);
    assert!(all.contains("alpha"));
    assert!(all.contains("Delete"));
    // No secrets
    assert!(!all.contains("alice"));
    assert!(!all.contains("secret123"));
    assert!(!all.contains("noteZ"));
}
