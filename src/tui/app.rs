use crate::core::entry::VaultEntry;
use crate::core::vault::GetField;
use secrecy::ExposeSecret;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum View {
    List,
    Details,
    AddModal,
    EditModal,
    ConfirmDelete,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FormField { Label, User, Notes }

pub struct App {
    entries: Vec<VaultEntry>,
    filtered: Vec<usize>,
    pub selected: usize,
    pub mode: Mode,
    pub filter: String,
    toast: Option<String>,
    toast_ticks: u16,
    pub view: View,
    // Form state (Add/Edit)
    pub form_field: FormField,
    pub form_label: String,
    pub form_user: String,
    pub form_notes: String,
    pub form_original_label: String,
}

impl App {
    pub fn new(entries: Vec<VaultEntry>) -> Self {
        let mut app = Self {
            entries,
            filtered: Vec::new(),
            selected: 0,
            mode: Mode::Normal,
            filter: String::new(),
            toast: None,
            toast_ticks: 0,
            view: View::List,
            form_field: FormField::Label,
            form_label: String::new(),
            form_user: String::new(),
            form_notes: String::new(),
            form_original_label: String::new(),
        };
        app.recompute();
        app
    }

    pub fn next(&mut self) {
        if self.filtered.is_empty() { return; }
        self.selected = (self.selected + 1).min(self.filtered.len().saturating_sub(1));
    }

    pub fn prev(&mut self) {
        if self.filtered.is_empty() { return; }
        if self.selected > 0 { self.selected -= 1; }
    }

    pub fn enter_search(&mut self) {
        self.mode = Mode::Search;
    }

    pub fn exit_search(&mut self) {
        self.mode = Mode::Normal;
    }

    pub fn push_filter(&mut self, c: char) {
        self.filter.push(c);
        self.recompute();
    }

    pub fn pop_filter(&mut self) {
        self.filter.pop();
        self.recompute();
    }

    pub fn toast(&mut self, msg: String) {
        self.toast = Some(msg);
        self.toast_ticks = 10; // ~2s at 200ms tick
    }

    pub fn toast_message(&self) -> Option<&str> { self.toast.as_deref() }

    pub fn tick(&mut self) {
        if self.toast_ticks > 0 {
            self.toast_ticks -= 1;
            if self.toast_ticks == 0 {
                self.toast = None;
            }
        }
    }

    pub fn visible_labels(&self) -> Vec<String> {
        self.filtered
            .iter()
            .map(|&i| self.entries[i].label.clone())
            .collect()
    }

    pub fn replace_entries(&mut self, new_entries: Vec<VaultEntry>) {
        self.entries = new_entries;
        self.recompute();
    }

    fn recompute(&mut self) {
        self.filtered.clear();
        if self.filter.is_empty() {
            self.filtered.extend(0..self.entries.len());
        } else {
            let q = self.filter.to_lowercase();
            for (i, e) in self.entries.iter().enumerate() {
                if e.label.to_lowercase().contains(&q) {
                    self.filtered.push(i);
                }
            }
        }
        if self.selected >= self.filtered.len() {
            self.selected = self.filtered.len().saturating_sub(1);
        }
    }

    pub fn selected_field(&self, field: GetField) -> Option<String> {
        if self.filtered.is_empty() { return None; }
        let idx = self.filtered[self.selected];
        let e = &self.entries[idx];
        match field {
            GetField::Password => Some(e.password.expose_secret().to_string()),
            GetField::User => e.username.as_ref().map(|u| u.expose_secret().to_string()),
            GetField::Notes => e.notes.clone(),
        }
    }

    pub fn selected_label(&self) -> Option<String> {
        if self.filtered.is_empty() { return None; }
        Some(self.entries[self.filtered[self.selected]].label.clone())
    }

    // View navigation
    pub fn enter_details(&mut self) { self.view = View::Details; }
    pub fn back_to_list(&mut self) { self.view = View::List; }

    pub fn enter_add(&mut self) {
        self.view = View::AddModal;
        self.form_field = FormField::Label;
        self.form_label.clear();
        self.form_user.clear();
        self.form_notes.clear();
        self.form_original_label.clear();
    }

    pub fn enter_edit(&mut self) {
        self.view = View::EditModal;
        self.form_field = FormField::Label;
        if let Some(idx) = self.filtered.get(self.selected).cloned() {
            let e = &self.entries[idx];
            self.form_label = e.label.clone();
            self.form_user = e.username.as_ref().map(|s| s.expose_secret().to_string()).unwrap_or_default();
            self.form_notes = e.notes.clone().unwrap_or_default();
            self.form_original_label = e.label.clone();
        }
    }

    pub fn enter_confirm_delete(&mut self) { self.view = View::ConfirmDelete; }
    pub fn cancel_confirm_delete(&mut self) { self.view = View::Details; }

    // Form editing
    pub fn next_field(&mut self) {
        self.form_field = match self.form_field {
            FormField::Label => FormField::User,
            FormField::User => FormField::Notes,
            FormField::Notes => FormField::Label
        };
    }
    pub fn prev_field(&mut self) {
        self.form_field = match self.form_field {
            FormField::Label => FormField::Notes,
            FormField::User => FormField::Label,
            FormField::Notes => FormField::User
        };
    }
    pub fn update_form_char(&mut self, c: char) {
        match self.form_field {
            FormField::Label => self.form_label.push(c),
            FormField::User => self.form_user.push(c),
            FormField::Notes => self.form_notes.push(c),
        }
    }
    pub fn backspace_form(&mut self) {
        match self.form_field {
            FormField::Label => { self.form_label.pop(); }
            FormField::User => { self.form_user.pop(); }
            FormField::Notes => { self.form_notes.pop(); }
        }
    }
    pub fn cancel_modal(&mut self) { self.view = View::List; }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn make(label: &str) -> VaultEntry {
        VaultEntry { label: label.into(), username: None, password: SecretString::new("x".into()), notes: None }
    }

    #[test]
    fn filtering_updates_visible_labels() {
        let entries = vec![make("alpha"), make("beta"), make("gamma")];
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
}
