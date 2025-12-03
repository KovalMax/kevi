#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Header parser should never panic on arbitrary input
    let _ = kevi::core::crypto::parse_kevi_header(data);
});
