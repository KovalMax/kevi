use super::classify;
use crate::error::CacheError;

#[test]
fn os_status_mapping_is_typed_without_contacting_keychain() {
    for (code, expected) in [
        (-25300, CacheError::Missing),
        (-25293, CacheError::Denied),
        (-25308, CacheError::Denied),
        (-128, CacheError::Denied),
        (-25291, CacheError::Unavailable),
        (-50, CacheError::Unavailable),
    ] {
        assert_eq!(
            classify(security_framework::base::Error::from_code(code)),
            expected
        );
    }
}
