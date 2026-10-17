use crate::session_management::resolver::{CacheWarning, WarningSink};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct CacheWarnings {
    queue: Mutex<VecDeque<CacheWarning>>,
}

impl CacheWarnings {
    pub fn sink(self: &Arc<Self>) -> WarningSink {
        let warnings = self.clone();
        Arc::new(move |warning| {
            let mut queue = warnings
                .queue
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if !queue.contains(&warning) && queue.len() < 8 {
                queue.push_back(warning);
            }
        })
    }
    pub fn pop(&self) -> Option<CacheWarning> {
        self.queue
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop_front()
    }
}
