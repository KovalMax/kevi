use kevi::filesystem::clipboard::{copy_with_ttl, ClipboardEngine};
use secrecy::SecretString;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct MockClipboard {
    buf: Mutex<String>,
}

impl MockClipboard {
    fn new(initial: &str) -> Self {
        Self {
            buf: Mutex::new(initial.to_string()),
        }
    }
}

impl ClipboardEngine for MockClipboard {
    fn get_contents(&self) -> anyhow::Result<Option<String>> {
        Ok(Some(self.buf.lock().unwrap().clone()))
    }

    fn set_contents(&self, contents: &str) -> anyhow::Result<()> {
        *self.buf.lock().unwrap() = contents.to_string();
        Ok(())
    }
}

#[test]
fn test_copy_with_ttl_restores_previous() {
    let engine: Arc<dyn ClipboardEngine> = Arc::new(MockClipboard::new("old"));
    let secret = SecretString::new("new-secret".into());

    // Copy with small TTL
    copy_with_ttl(engine.clone(), &secret, Duration::from_millis(50)).expect("copy ok");

    // Immediately should be the secret
    let now = engine.get_contents().unwrap().unwrap();
    assert_eq!(now, "new-secret");

    // After TTL it should be restored to previous (allow lag for slower CI schedulers)
    let start = std::time::Instant::now();
    let mut restored = None;
    while start.elapsed() < Duration::from_millis(500) {
        if let Some(current) = engine.get_contents().unwrap() {
            if current == "old" {
                restored = Some(current);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(restored.as_deref(), Some("old"));
}
