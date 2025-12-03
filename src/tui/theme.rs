use ratatui::style::{Color, Modifier, Style};

#[derive(Clone, Debug)]
pub struct Theme {
    pub bg: Color,
    pub fg: Color,
    pub primary: Color,
    pub accent: Color,
    pub muted: Color,
    pub selection: Color,
}

impl Default for Theme {
    fn default() -> Self {
        // NES/SEGA inspired palette
        Self {
            bg: Color::Black,
            fg: Color::White,
            primary: Color::Blue,
            accent: Color::Red,
            muted: Color::DarkGray,
            selection: Color::Cyan,
        }
    }
}

impl Theme {
    pub fn title_style(&self) -> Style {
        Style::default().fg(self.primary).add_modifier(Modifier::BOLD)
    }
    pub fn normal_style(&self) -> Style { Style::default().fg(self.fg) }
    pub fn muted_style(&self) -> Style { Style::default().fg(self.muted) }
    pub fn selection_style(&self) -> Style { Style::default().fg(self.selection).add_modifier(Modifier::BOLD) }
    pub fn toast_style(&self) -> Style { Style::default().fg(self.accent).add_modifier(Modifier::BOLD) }
}
