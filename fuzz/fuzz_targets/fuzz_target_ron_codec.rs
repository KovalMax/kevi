#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Decoder must not panic on arbitrary inputs
    let codec = kevi::core::adapters::RonCodec;
    let _ = codec.decode(data);
});
