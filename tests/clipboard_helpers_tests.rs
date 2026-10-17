use kevi::api::{clipboard_copy_error_message, ClipboardCopyError, KeviError};

#[test]
fn clipboard_unavailable_message_is_stable() {
    let message = clipboard_copy_error_message(&ClipboardCopyError::Unavailable(KeviError::io(
        "backend unavailable",
    )));

    assert_eq!(
        message,
        "⚠️ Clipboard not available: I/O error: backend unavailable"
    );
}

#[test]
fn clipboard_copy_failed_message_is_stable() {
    let message = clipboard_copy_error_message(&ClipboardCopyError::CopyFailed(KeviError::io(
        "copy command failed",
    )));

    assert_eq!(
        message,
        "⚠️ Failed to copy to clipboard: I/O error: copy command failed"
    );
}
