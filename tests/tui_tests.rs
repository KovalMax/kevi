use ratatui::backend::TestBackend;
use ratatui::Terminal;

use kevi::core::entry::VaultEntry;
use kevi::tui::app::App;
use kevi::tui::views::list::render_list;
use secrecy::SecretString;

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
    terminal.draw(|f| {
        render_list(f, &app);
    }).unwrap();

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
