use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::tui::app::{App, View};
use crate::tui::theme::Theme;

pub fn render_details(f: &mut Frame, app: &App) {
    let theme = Theme::default();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title
            Constraint::Min(1),    // details
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    let title = Paragraph::new("Kevi — Details").style(theme.title_style());
    f.render_widget(title, chunks[0]);

    let label = app.selected_label().unwrap_or_else(|| "(none)".to_string());

    let user = app
        .selected_field(crate::core::vault::GetField::User)
        .unwrap_or_else(|| "(none)".to_string());

    let pass_raw = app
        .selected_field(crate::core::vault::GetField::Password)
        .unwrap_or_default();
    let pass_display = if app.reveal_password {
        pass_raw
    } else {
        "********".to_string()
    };

    let notes = app
        .selected_field(crate::core::vault::GetField::Notes)
        .unwrap_or_else(|| "(none)".to_string());

    let body =
        format!("Label: {label}\nUsername: {user}\nPassword: {pass_display}\nNotes: {notes}");
    let para = Paragraph::new(body)
        .block(Block::default().borders(Borders::ALL).title("Entry"))
        .style(theme.normal_style());
    f.render_widget(para, chunks[1]);

    let footer = match app.view {
        View::Details => {
            "q=back  Enter=copy password  u=copy user  v=toggle password  e=edit  d=delete"
        }
        _ => "",
    };
    f.render_widget(Paragraph::new(footer).style(theme.toast_style()), chunks[2]);
}
