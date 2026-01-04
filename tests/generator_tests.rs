use anyhow::Result;
use kevi::cryptography::generator::DefaultPasswordGenerator;
use kevi::vault::ports::{GenPolicy, PasswordGenerator, Rng};
use std::sync::Arc;

struct MockRng {
    data: std::sync::Mutex<Vec<u8>>,
}
impl MockRng {
    fn new(seq: &[u8]) -> Self {
        Self {
            data: std::sync::Mutex::new(seq.to_vec()),
        }
    }
}
impl Rng for MockRng {
    fn fill(&self, bytes: &mut [u8]) -> Result<()> {
        let mut guard = self.data.lock().unwrap();
        if guard.is_empty() {
            *guard = vec![0u8; 1024];
        }
        for b in bytes.iter_mut() {
            let v = guard.remove(0);
            *b = v;
            guard.push(v.wrapping_add(1));
        }
        Ok(())
    }
}

#[test]
fn char_generator_respects_classes_and_length() {
    let rng = Arc::new(MockRng::new(&[1, 2, 3, 4, 5, 6, 7, 8]));
    let gen = DefaultPasswordGenerator::new(rng);
    let p = GenPolicy {
        length: 24,
        ..GenPolicy::default()
    };
    let s = gen.generate(&p).unwrap();
    assert_eq!(s.len(), 24);
    assert!(s.chars().any(|c| c.is_ascii_lowercase()));
    assert!(s.chars().any(|c| c.is_ascii_uppercase()));
    assert!(s.chars().any(|c| c.is_ascii_digit()));
    assert!(s.chars().any(|c| !c.is_ascii_alphanumeric()));
}

#[test]
fn char_generator_no_symbols_no_digits() {
    let rng = Arc::new(MockRng::new(&[9, 9, 9, 9, 9, 9, 9, 9]));
    let gen = DefaultPasswordGenerator::new(rng);
    let p = GenPolicy {
        symbols: false,
        digits: false,
        length: 12,
        ..GenPolicy::default()
    };
    let s = gen.generate(&p).unwrap();
    assert_eq!(s.len(), 12);
    assert!(s.chars().all(|c| c.is_ascii_alphabetic()));
}

#[test]
fn invalid_policy_rejected() {
    let rng = Arc::new(MockRng::new(&[0; 32]));
    let gen = DefaultPasswordGenerator::new(rng);
    let mut p = GenPolicy {
        lower: false,
        upper: false,
        digits: false,
        symbols: false,
        ..GenPolicy::default()
    };
    assert!(gen.generate(&p).is_err());
    p.lower = true;
    p.upper = true;
    p.digits = false;
    p.symbols = false;
    p.length = 1;
    assert!(gen.generate(&p).is_err());
}

#[test]
fn passphrase_mode_generates_words() {
    let rng = Arc::new(MockRng::new(&[1, 2, 3, 4, 5, 6, 7, 8]));
    let gen = DefaultPasswordGenerator::new(rng);
    let p = GenPolicy {
        passphrase: true,
        words: 5,
        sep: ":".to_string(),
        ..GenPolicy::default()
    };
    let s = gen.generate(&p).unwrap();
    let parts: Vec<&str> = s.split(':').collect();
    assert_eq!(parts.len(), 5);
    assert!(parts.iter().all(|w| !w.is_empty()));
    assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == ':'));
}
