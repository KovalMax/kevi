use kevi::api::{
    estimate_bits_char_mode, estimate_bits_passphrase, strength_label, CoreRng,
    DefaultPasswordGenerator, GenPolicy, KeviError, PasswordGenerator,
};
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
impl CoreRng for MockRng {
    type Error = KeviError;

    fn fill(&self, bytes: &mut [u8]) -> Result<(), KeviError> {
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

struct SeqRng {
    data: std::sync::Mutex<Vec<u32>>,
}

impl SeqRng {
    fn new(seq: &[u32]) -> Self {
        Self {
            data: std::sync::Mutex::new(seq.to_vec()),
        }
    }
}

impl CoreRng for SeqRng {
    type Error = KeviError;

    fn fill(&self, bytes: &mut [u8]) -> Result<(), KeviError> {
        let mut guard = self.data.lock().unwrap();
        let val = if guard.is_empty() { 0 } else { guard.remove(0) };
        let le = val.to_le_bytes();
        let mut idx = 0;
        while idx < bytes.len() {
            let len = (bytes.len() - idx).min(le.len());
            bytes[idx..idx + len].copy_from_slice(&le[..len]);
            idx += len;
        }
        guard.push(val.wrapping_add(1));
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

#[test]
fn char_generator_avoids_ambiguous_when_requested() {
    let rng = Arc::new(MockRng::new(&[7, 3, 9, 1, 5, 11, 13, 17]));
    let gen = DefaultPasswordGenerator::new(rng);
    let policy = GenPolicy {
        length: 32,
        avoid_ambiguous: true,
        ..GenPolicy::default()
    };
    let s = gen.generate(&policy).unwrap();
    let ambiguous = ['O', '0', 'I', 'l', '|', '1'];
    assert!(s.chars().all(|c| !ambiguous.contains(&c)));
}

#[test]
fn passphrase_respects_custom_wordlist_and_separator() {
    static WORDS: [&str; 3] = ["alpha", "beta", "gamma"];
    let rng = Arc::new(SeqRng::new(&[0, 1, 2, 0]));
    let gen = DefaultPasswordGenerator::new_with_wordlist(rng, &WORDS);
    let policy = GenPolicy {
        passphrase: true,
        words: 4,
        sep: "--".to_string(),
        ..GenPolicy::default()
    };
    let s = gen.generate(&policy).unwrap();
    assert_eq!(s, "alpha--beta--gamma--alpha");
}

#[test]
fn strength_estimators_scale_with_entropy() {
    let mut policy = GenPolicy {
        length: 8,
        ..GenPolicy::default()
    };
    let short_bits = estimate_bits_char_mode(&policy);
    policy.length = 24;
    let long_bits = estimate_bits_char_mode(&policy);
    assert!(long_bits > short_bits);

    let phrase3 = estimate_bits_passphrase(3, 2048);
    let phrase6 = estimate_bits_passphrase(6, 2048);
    assert!(phrase6 > phrase3);

    assert_eq!(strength_label(20.0), "very weak");
    assert_eq!(strength_label(30.0), "weak");
    assert_eq!(strength_label(50.0), "fair");
    assert_eq!(strength_label(100.0), "strong");
    assert_eq!(strength_label(130.0), "excellent");
}
