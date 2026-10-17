use kevi::api::{App, CacheError, CacheWarning, CacheWarnings};
use std::sync::Arc;

#[test]
fn tui_warning_queue_is_typed_bounded_deduplicated_and_visible() {
    let warnings = Arc::new(CacheWarnings::default());
    let sink = warnings.sink();
    for _ in 0..20 {
        sink(CacheWarning::InsecureFile);
    }
    for kind in [
        CacheError::Missing,
        CacheError::Denied,
        CacheError::Unavailable,
        CacheError::Malformed,
        CacheError::Delete,
        CacheError::Clock,
        CacheError::Identity,
        CacheError::Persist,
    ] {
        sink(CacheWarning::Failure(kind));
    }
    let mut count = 0;
    while warnings.pop().is_some() {
        count += 1;
    }
    assert_eq!(count, 8);
    sink(CacheWarning::Failure(CacheError::Denied));
    let mut app = App::new(vec![]);
    app.show_cache_warning(&warnings);
    assert!(app
        .cache_warning_message()
        .unwrap()
        .contains("access denied"));
    sink(CacheWarning::Failure(CacheError::Persist));
    app.show_cache_warning(&warnings);
    assert!(app
        .cache_warning_message()
        .unwrap()
        .contains("access denied"));
    for _ in 0..10 {
        app.tick();
    }
    assert!(app
        .cache_warning_message()
        .unwrap()
        .contains("access denied"));
    app.acknowledge_cache_warning();
    app.show_cache_warning(&warnings);
    assert!(app
        .cache_warning_message()
        .unwrap()
        .contains("persistence failed"));
}
