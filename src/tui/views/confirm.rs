use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use crate::tui::app::App;
use crate::tui::theme::Theme;

pub fn render_confirm(f: &mut Frame, app: &App) {
    let theme = Theme::default();
    let area = f.area();
    let label = app.selected_label().unwrap_or_else(|| "(none)".to_string());
    let text = format!("Delete '{label}'? (y/N)");
    let para = Paragraph::new(text).style(theme.toast_style());
    f.render_widget(para, area);
}
