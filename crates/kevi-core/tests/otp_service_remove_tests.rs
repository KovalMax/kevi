use kevi_core::otp::models::{OtpAlgorithm, OtpEntry};
use kevi_core::otp::service::{OtpDomainService, OtpVaultRepository};
use kevi_core::vault::models::VaultData;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq, Eq)]
struct TestError;

struct InMemoryOtpRepository {
    data: Rc<RefCell<VaultData>>,
    save_calls: Rc<RefCell<usize>>,
}

impl InMemoryOtpRepository {
    fn new(data: Rc<RefCell<VaultData>>, save_calls: Rc<RefCell<usize>>) -> Self {
        Self { data, save_calls }
    }
}

impl OtpVaultRepository for InMemoryOtpRepository {
    type Error = TestError;

    fn load(&self) -> Result<VaultData, Self::Error> {
        Ok(self.data.borrow().clone())
    }

    fn save(&self, data: &VaultData) -> Result<(), Self::Error> {
        *self.data.borrow_mut() = data.clone();
        *self.save_calls.borrow_mut() += 1;
        Ok(())
    }
}

fn otp_entry(name: &str) -> OtpEntry {
    OtpEntry {
        name: name.into(),
        secret: "JBSWY3DPEHPK3PXP".to_string(),
        issuer: Some("demo".to_string()),
        username: "user".to_string(),
        digits: 6,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: None,
    }
}

#[test]
fn remove_entry_returns_false_and_skips_save_when_name_is_missing() {
    let data = Rc::new(RefCell::new(VaultData {
        entries: Vec::new(),
        otps: vec![otp_entry("existing")],
    }));
    let save_calls = Rc::new(RefCell::new(0));
    let repository = InMemoryOtpRepository::new(data, save_calls.clone());
    let service = OtpDomainService::new(repository);

    let removed = service
        .remove_entry("missing")
        .expect("remove should succeed");

    assert!(!removed);
    assert_eq!(*save_calls.borrow(), 0);
}
