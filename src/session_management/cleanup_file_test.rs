use super::cleanup_file::check_target;
use std::fs;
use tempfile::tempdir;

#[test]
fn generic_ron_with_expiry_and_arbitrary_data_is_not_a_cache() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("ambiguous.ron");
    let bytes = b"(expires_at_unix: 200, data: \"unrelated file\")";
    fs::write(&path, bytes).unwrap();

    assert!(check_target(&[], &path).is_err());
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn legacy_ron_session_is_not_recognized_as_a_current_cache() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("legacy.ron");
    let bytes = format!(
        "(expires_at_unix: 200, data: (header_fingerprint_hex: \"{}\", key_b64: \"{}\"))",
        "ab".repeat(32),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    );
    fs::write(&path, &bytes).unwrap();

    assert!(check_target(&[], &path).is_err());
    assert_eq!(fs::read(path).unwrap(), bytes.as_bytes());
}

#[test]
fn bare_key_shaped_ron_is_ambiguous_and_preserved() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("unrelated.ron");
    let bytes = format!(
        "(header_fingerprint_hex: \"{}\", key_b64: \"{}\")",
        "ab".repeat(32),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    );
    fs::write(&path, &bytes).unwrap();

    assert!(check_target(&[], &path).is_err());
    assert_eq!(fs::read(path).unwrap(), bytes.as_bytes());
}
