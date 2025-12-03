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
    // Never render secrets: show placeholders
    let user_mask = if app.selected_field(crate::core::vault::GetField::User).is_some() { "hidden" } else { "(none)" };
    let pass_mask = if app.selected_field(crate::core::vault::GetField::Password).is_some() { "hidden" } else { "(none)" };
    let notes_mask = if app.selected_field(crate::core::vault::GetField::Notes).is_some() { "hidden" } else { "(none)" };

    let body = format!(
        "Label: {label}\nUsername: {user_mask}\nPassword: {pass_mask}\nNotes: {notes_mask}"
    );
    let para = Paragraph::new(body)
        .block(Block::default().borders(Borders::ALL).title("Entry"))
        .style(theme.normal_style());
    f.render_widget(para, chunks[1]);

    let footer = match app.view {
        View::Details => "q=back  Enter=copy password  u=copy user  e=edit  d=delete",
        _ => "",
    };
    f.render_widget(Paragraph::new(footer).style(theme.toast_style()), chunks[2]);
}
