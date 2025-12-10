use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::tui::app::{App, FormField, View};
use crate::tui::theme::Theme;

fn field_line<'a>(
    label: &'a str,
    value: &'a str,
    focused: bool,
    theme: &'a Theme,
) -> Paragraph<'a> {
    let text = format!("{label}: {value}");
    let mut p = Paragraph::new(text);
    if focused {
        p = p.style(theme.selection_style());
    } else {
        p = p.style(theme.normal_style());
    }
    p
}

pub fn render_form(f: &mut Frame, app: &App) {
    let theme = Theme::default();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title
            Constraint::Min(1),    // form
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    let title = match app.view {
        View::AddModal => "Kevi — Add Entry",
        View::EditModal => "Kevi — Edit Entry",
        _ => "Kevi",
    };
    f.render_widget(Paragraph::new(title).style(theme.title_style()), chunks[0]);

    let block = Block::default().borders(Borders::ALL).title("Form");
    let inner_area = block.inner(chunks[1]);
    f.render_widget(block, chunks[1]);

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner_area);

    let label_para = field_line(
        "Label",
        &app.form_label,
        matches!(app.form_field, FormField::Label),
        &theme,
    );
    let user_para = field_line(
        "Username",
        &app.form_user,
        matches!(app.form_field, FormField::User),
        &theme,
    );
    let password_para = field_line(
        "Password",
        &app.form_password,
        matches!(app.form_field, FormField::Password),
        &theme,
    );
    let notes_para = field_line(
        "Notes",
        &app.form_notes,
        matches!(app.form_field, FormField::Notes),
        &theme,
    );

    f.render_widget(label_para, inner[0]);
    f.render_widget(user_para, inner[1]);
    f.render_widget(password_para, inner[2]);
    f.render_widget(notes_para, inner[3]);

    let footer = "Esc=cancel  Tab/Shift-Tab=switch  Enter=submit";
    f.render_widget(Paragraph::new(footer).style(theme.toast_style()), chunks[2]);
}
