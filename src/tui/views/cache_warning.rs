use crate::tui::app::App;
use crate::tui::theme::Theme;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

pub fn render_cache_warning(frame: &mut Frame, app: &App) {
    if let Some(message) = app.cache_warning_message() {
        let area = frame.area();
        let height = area.height.min(4);
        let warning_area = Rect::new(area.x, area.bottom() - height, area.width, height);
        frame.render_widget(Clear, warning_area);
        frame.render_widget(
            Paragraph::new(message)
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Session cache warning"),
                )
                .style(Theme::default().toast_style()),
            warning_area,
        );
    }
}
