use crate::cryptography::generator::{DefaultPasswordGenerator, SystemRng};
use crate::error::{TuiError, TuiResult};
use crate::filesystem::clipboard::{copy_with_ttl_using_system_clipboard, ClipboardCopyError};
use crate::vault::handlers::GetField;
use crate::vault::models::VaultEntry;
use crate::vault::ports::{ByteStore, GenPolicy, KeyResolver, PasswordGenerator, VaultCodec};
use crate::vault::service::VaultService;
use crossterm::event::KeyCode;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::spawn_blocking;

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
pub enum FormField {
    Label,
    User,
    Password,
    Notes,
}

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
    pub form_password: String,
    pub form_notes: String,
    pub form_original_label: String,
    // Toggle for revealing password in the Details view
    pub reveal_password: bool,
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
            form_password: String::new(),
            form_notes: String::new(),
            form_original_label: String::new(),
            reveal_password: false,
        };
        app.recompute();
        app
    }

    pub fn next(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        self.selected = (self.selected + 1).min(self.filtered.len().saturating_sub(1));
    }

    pub fn prev(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        if self.selected > 0 {
            self.selected -= 1;
        }
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

    pub fn toast_message(&self) -> Option<&str> {
        self.toast.as_deref()
    }

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
            .map(|&i| self.entries[i].label.to_string())
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
                if e.label.as_str().to_lowercase().contains(&q) {
                    self.filtered.push(i);
                }
            }
        }
        if self.selected >= self.filtered.len() {
            self.selected = self.filtered.len().saturating_sub(1);
        }
    }

    pub fn selected_field(&self, field: GetField) -> Option<String> {
        if self.filtered.is_empty() {
            return None;
        }
        let idx = self.filtered[self.selected];
        let e = &self.entries[idx];
        match field {
            GetField::Password => Some(e.password.expose_secret().to_string()),
            GetField::User => e.username.as_ref().map(|u| u.expose_secret().to_string()),
            GetField::Notes => e.notes.clone(),
        }
    }

    pub fn copy_value_to_clipboard(&mut self, field: GetField, value: String, ttl: u64) {
        let secret = SecretString::new(value.into());
        match copy_with_ttl_using_system_clipboard(&secret, Duration::from_secs(ttl)) {
            Ok(()) => self.toast(format!("{field} copied ({ttl}s)")),
            Err(ClipboardCopyError::Unavailable(_)) | Err(ClipboardCopyError::CopyFailed(_)) => {
                self.toast("Clipboard unavailable".to_string());
            }
        }
    }

    pub fn selected_label(&self) -> Option<String> {
        if self.filtered.is_empty() {
            return None;
        }
        Some(self.entries[self.filtered[self.selected]].label.to_string())
    }

    // View navigation
    pub fn enter_details(&mut self) {
        self.view = View::Details;
        self.reveal_password = false;
    }
    pub fn back_to_list(&mut self) {
        self.view = View::List;
        self.reveal_password = false;
    }

    pub fn enter_add(&mut self) {
        self.view = View::AddModal;
        self.form_field = FormField::Label;
        self.form_label.clear();
        self.form_user.clear();
        self.form_password.clear();
        self.form_notes.clear();
        self.form_original_label.clear();
    }

    pub fn enter_edit(&mut self) {
        self.view = View::EditModal;
        self.form_field = FormField::Label;
        if let Some(idx) = self.filtered.get(self.selected).cloned() {
            let e = &self.entries[idx];
            self.form_label = e.label.to_string();
            self.form_user = e
                .username
                .as_ref()
                .map(|s| s.expose_secret().to_string())
                .unwrap_or_default();
            self.form_password = e.password.expose_secret().to_string();
            self.form_notes = e.notes.clone().unwrap_or_default();
            self.form_original_label = e.label.to_string();
        }
    }

    pub fn enter_confirm_delete(&mut self) {
        self.view = View::ConfirmDelete;
    }
    pub fn cancel_confirm_delete(&mut self) {
        self.view = View::Details;
    }

    // Form editing
    pub fn next_field(&mut self) {
        self.form_field = match self.form_field {
            FormField::Label => FormField::User,
            FormField::User => FormField::Password,
            FormField::Password => FormField::Notes,
            FormField::Notes => FormField::Label,
        };
    }
    pub fn prev_field(&mut self) {
        self.form_field = match self.form_field {
            FormField::Label => FormField::Notes,
            FormField::User => FormField::Label,
            FormField::Password => FormField::User,
            FormField::Notes => FormField::Password,
        };
    }
    pub fn update_form_char(&mut self, c: char) {
        match self.form_field {
            FormField::Label => self.form_label.push(c),
            FormField::User => self.form_user.push(c),
            FormField::Password => self.form_password.push(c),
            FormField::Notes => self.form_notes.push(c),
        }
    }
    pub fn backspace_form(&mut self) {
        match self.form_field {
            FormField::Label => {
                self.form_label.pop();
            }
            FormField::User => {
                self.form_user.pop();
            }
            FormField::Password => {
                self.form_password.pop();
            }
            FormField::Notes => {
                self.form_notes.pop();
            }
        }
    }
    pub fn cancel_modal(&mut self) {
        self.view = View::List;
    }

    pub async fn handle_key_event<StoreType, CodecType, ResolverType>(
        &mut self,
        code: KeyCode,
        ttl_secs: u64,
        service: Arc<VaultService<StoreType, CodecType, ResolverType>>,
    ) -> TuiResult<()>
    where
        StoreType: ByteStore + 'static,
        CodecType: VaultCodec + 'static,
        ResolverType: KeyResolver + 'static,
    {
        match self.view {
            View::List => match self.mode {
                Mode::Normal => match code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.next();
                        Ok(())
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.prev();
                        Ok(())
                    }
                    KeyCode::Char('/') => {
                        self.enter_search();
                        Ok(())
                    }
                    KeyCode::Right | KeyCode::Char('l') => {
                        self.enter_details();
                        Ok(())
                    }
                    KeyCode::Char('a') => {
                        self.enter_add();
                        Ok(())
                    }
                    KeyCode::Enter => {
                        if let Some(val) = self.selected_field(GetField::Password) {
                            self.copy_value_to_clipboard(GetField::Password, val, ttl_secs)
                        }
                        Ok(())
                    }
                    KeyCode::Char('u') => {
                        if let Some(val) = self.selected_field(GetField::User) {
                            self.copy_value_to_clipboard(GetField::User, val, ttl_secs)
                        }
                        Ok(())
                    }

                    _ => Ok(()),
                },
                Mode::Search => match code {
                    KeyCode::Esc => {
                        self.exit_search();
                        Ok(())
                    }
                    KeyCode::Backspace => {
                        self.pop_filter();
                        Ok(())
                    }
                    KeyCode::Enter => {
                        self.exit_search();
                        Ok(())
                    }
                    KeyCode::Char(c) => {
                        self.push_filter(c);
                        Ok(())
                    }
                    _ => Ok(()),
                },
            },
            View::Details => match code {
                KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => {
                    self.back_to_list();
                    Ok(())
                }
                KeyCode::Enter => {
                    if let Some(val) = self.selected_field(GetField::Password) {
                        self.copy_value_to_clipboard(GetField::Password, val, ttl_secs);
                    }
                    Ok(())
                }
                KeyCode::Char('u') => {
                    if let Some(val) = self.selected_field(GetField::User) {
                        self.copy_value_to_clipboard(GetField::User, val, ttl_secs);
                    } else {
                        self.toast("No username".to_string());
                    }
                    Ok(())
                }
                KeyCode::Char('v') => {
                    self.reveal_password = !self.reveal_password;
                    Ok(())
                }
                KeyCode::Char('e') => {
                    self.enter_edit();
                    Ok(())
                }
                KeyCode::Char('a') => {
                    self.enter_add();
                    Ok(())
                }
                KeyCode::Char('d') => {
                    self.enter_confirm_delete();
                    Ok(())
                }
                _ => Ok(()),
            },
            View::AddModal | View::EditModal => {
                match code {
                    KeyCode::Esc => {
                        self.cancel_modal();
                        Ok(())
                    }
                    KeyCode::Tab => {
                        self.next_field();
                        Ok(())
                    }
                    KeyCode::BackTab => {
                        self.prev_field();
                        Ok(())
                    }
                    KeyCode::Backspace => {
                        self.backspace_form();
                        Ok(())
                    }
                    KeyCode::Enter => {
                        // Validate label
                        let label = self.form_label.trim().to_string();
                        if label.is_empty() {
                            self.toast("Label required".to_string());
                        } else {
                            // Build entry; for Add we generate a strong password by default
                            let is_add = matches!(self.view, View::AddModal);
                            let current_labels: Vec<String> = self.visible_labels();
                            if is_add && current_labels.iter().any(|l| l == &label) {
                                self.toast("Label exists".to_string());
                            } else {
                                // Clone options for move into closures
                                let user_opt = if self.form_user.trim().is_empty() {
                                    None
                                } else {
                                    Some(self.form_user.trim().to_string())
                                };
                                let notes_opt = if self.form_notes.trim().is_empty() {
                                    None
                                } else {
                                    Some(self.form_notes.trim().to_string())
                                };
                                let label_for_save = crate::domain::EntryLabel::from(label.clone());
                                let form_pw = self.form_password.clone();
                                let original_label = crate::domain::EntryLabel::from(
                                    self.form_original_label.clone(),
                                );
                                let svc = service.clone();
                                if is_add {
                                    let _ = spawn_blocking(move || {
                                        let pw_final = if form_pw.is_empty() {
                                            // Generate password via default generator
                                            let gen2 =
                                                DefaultPasswordGenerator::new(Arc::new(SystemRng));
                                            gen2.generate(&GenPolicy::default())?
                                        } else {
                                            form_pw
                                        };

                                        let entry_real = VaultEntry {
                                            label: label_for_save,
                                            username: user_opt.map(|u| SecretString::new(u.into())),
                                            password: SecretString::new(pw_final.into()),
                                            notes: notes_opt,
                                        };
                                        svc.add_entry(entry_real)
                                    })
                                    .await
                                    .map_err(crate::error::TuiError::from)?;
                                } else {
                                    let _ = spawn_blocking(move || {
                                        let mut vault = svc.load()?;
                                        if let Some(pos) = vault
                                            .entries
                                            .iter()
                                            .position(|e| e.label == original_label)
                                        {
                                            vault.entries[pos].label = label_for_save;
                                            vault.entries[pos].username =
                                                user_opt.map(|u| SecretString::new(u.into()));
                                            vault.entries[pos].password =
                                                SecretString::new(form_pw.into());
                                            vault.entries[pos].notes = notes_opt;
                                            svc.save(&vault)
                                        } else {
                                            Ok(())
                                        }
                                    })
                                    .await
                                    .map_err(crate::error::TuiError::from)?;
                                }
                                // Reload entries
                                let svc_reload = service.clone();
                                let new_entries = spawn_blocking(move || svc_reload.load())
                                    .await?
                                    .map_err(|e| TuiError::Message(e.to_string()))?;
                                self.replace_entries(new_entries.entries);
                                self.view = View::List;
                                self.toast("Saved".to_string());
                            }
                        }
                        Ok(())
                    }
                    KeyCode::Char(c) => {
                        if !c.is_control() {
                            self.update_form_char(c);
                        }
                        Ok(())
                    }
                    _ => Ok(()),
                }
            }
            View::ConfirmDelete => {
                match code {
                    KeyCode::Esc | KeyCode::Char('n') => {
                        self.cancel_confirm_delete();
                        Ok(())
                    }
                    KeyCode::Char('y') => {
                        if let Some(label) = self.selected_label() {
                            let svc_rm = service.clone();
                            let _ = spawn_blocking(move || svc_rm.remove_entry(&label)).await?;
                            // Reload
                            let svc_reload = service.clone();
                            if let Ok(Ok(ents)) = spawn_blocking(move || svc_reload.load())
                                .await
                                .map_err(crate::error::TuiError::from)
                            {
                                self.replace_entries(ents.entries);
                            }
                            self.view = View::List;
                            self.toast("Deleted".to_string());
                        } else {
                            self.cancel_confirm_delete();
                        }
                        Ok(())
                    }
                    _ => Ok(()),
                }
            }
        }
    }
}
