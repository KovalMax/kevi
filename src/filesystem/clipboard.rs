use crate::config::app_config::Config;
use crate::domain::VaultResult;
use crate::error::KeviError;
use copypasta::{ClipboardContext, ClipboardProvider};
use secrecy::{ExposeSecret, SecretString};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub trait ClipboardEngine: Send + Sync + 'static {
    fn get_contents(&self) -> VaultResult<Option<String>>;
    fn set_contents(&self, contents: &str) -> VaultResult<()>;
}

pub struct SystemClipboardEngine {
    ctx: Mutex<ClipboardContext>,
}

impl SystemClipboardEngine {
    pub fn new() -> VaultResult<Self> {
        let ctx = ClipboardContext::new()
            .map_err(|e| KeviError::io(format!("Failed to access clipboard: {e}")))?;
        Ok(Self {
            ctx: Mutex::new(ctx),
        })
    }
}

impl ClipboardEngine for SystemClipboardEngine {
    fn get_contents(&self) -> VaultResult<Option<String>> {
        let mut guard = self.ctx.lock().unwrap();
        match guard.get_contents() {
            Ok(s) => Ok(Some(s)),
            Err(_) => Ok(None),
        }
    }

    fn set_contents(&self, contents: &str) -> VaultResult<()> {
        let mut guard = self.ctx.lock().unwrap();
        guard
            .set_contents(contents.to_string())
            .map_err(|e| KeviError::io(format!("Failed to copy to clipboard: {e}")))
    }
}

pub fn copy_with_ttl(
    engine: Arc<dyn ClipboardEngine>,
    secret: &SecretString,
    ttl: Duration,
) -> VaultResult<()> {
    let previous = engine.get_contents()?;
    engine.set_contents(secret.expose_secret())?;

    let engine_clone = engine.clone();
    thread::spawn(move || {
        thread::sleep(ttl);
        let _ = match &previous {
            Some(prev) => engine_clone.set_contents(prev),
            None => engine_clone.set_contents(""),
        };
    });

    Ok(())
}

#[derive(Debug)]
pub enum ClipboardCopyError {
    Unavailable(KeviError),
    CopyFailed(KeviError),
}

pub fn clipboard_copy_error_message(error: &ClipboardCopyError) -> String {
    match error {
        ClipboardCopyError::Unavailable(error) => {
            format!("⚠️ Clipboard not available: {error}")
        }
        ClipboardCopyError::CopyFailed(error) => {
            format!("⚠️ Failed to copy to clipboard: {error}")
        }
    }
}

pub fn report_clipboard_copy_result(result: Result<(), ClipboardCopyError>) {
    match result {
        Ok(()) => {}
        Err(error) => eprintln!("{}", clipboard_copy_error_message(&error)),
    }
}

pub fn copy_with_ttl_using_system_clipboard(
    secret: &SecretString,
    ttl: Duration,
) -> Result<(), ClipboardCopyError> {
    let engine = SystemClipboardEngine::new().map_err(ClipboardCopyError::Unavailable)?;
    copy_with_ttl(Arc::new(engine), secret, ttl).map_err(ClipboardCopyError::CopyFailed)
}

/// Resolve clipboard TTL seconds with precedence: override > KEVI_CLIP_TTL > config.clipboard_ttl > default (20)
pub fn ttl_seconds(config: &Config, override_ttl: Option<u64>) -> u64 {
    override_ttl
        .or_else(|| {
            std::env::var("KEVI_CLIP_TTL")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
        })
        .or(config.clipboard_ttl)
        .unwrap_or(20)
}

/// Best-effort environment warning when clipboard is likely unavailable (SSH/headless)
pub fn environment_warning() -> Option<String> {
    let is_ssh = std::env::var("SSH_CONNECTION").is_ok() || std::env::var("SSH_TTY").is_ok();
    #[cfg(all(target_family = "unix", not(target_os = "macos")))]
    let headless = std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err();
    #[cfg(any(not(target_family = "unix"), target_os = "macos"))]
    let headless = false;
    if is_ssh {
        return Some(
            "Detected SSH session; clipboard may be unavailable. Consider --no-copy --echo"
                .to_string(),
        );
    }
    if headless {
        return Some("No DISPLAY/WAYLAND detected; clipboard may be unavailable.".to_string());
    }
    None
}
