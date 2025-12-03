use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::tui::app::{App, Mode};
use crate::tui::theme::Theme;

pub fn render_list(f: &mut Frame, app: &App) {
    let theme = Theme::default();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title
            Constraint::Length(1), // search / hint
            Constraint::Min(1),    // list
            Constraint::Length(1), // footer/toast
        ]).split(f.area());

    let title = Paragraph::new("Kevi — Secure Vault (TUI)")
        .style(theme.title_style());
    f.render_widget(title, chunks[0]);

    let search_label = match app.mode {
        Mode::Normal => format!("Press / to search  |  {} items", app.visible_labels().len()),
        Mode::Search => format!("Search: {}", app.filter),
    };
    let search = Paragraph::new(search_label).style(theme.muted_style());
    f.render_widget(search, chunks[1]);

    // Build items (labels only; never render secrets)
    let labels = app.visible_labels();
    let items: Vec<ListItem> = labels.iter().enumerate().map(|(i, lbl)| {
        let style = if i == app.selected { theme.selection_style() } else { theme.normal_style() };
        ListItem::new(Line::from(lbl.clone())).style(style)
    }).collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Entries"));
    f.render_widget(list, chunks[2]);

    let footer_text = app.toast_message().unwrap_or("q=quit  Enter=copy password  u=copy user");
    let footer = Paragraph::new(footer_text).style(theme.toast_style());
    f.render_widget(footer, chunks[3]);
}
