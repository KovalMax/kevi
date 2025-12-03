use anyhow::{anyhow, Result};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::Arc;

use crate::core::ports::{GenPolicy, PasswordGenerator, Rng};
use crate::core::wordlist::WORDS;

pub struct SystemRng;

impl Rng for SystemRng {
    fn fill(&self, bytes: &mut [u8]) -> Result<()> {
        let rng = SystemRandom::new();
        rng.fill(bytes)
            .map_err(|_| anyhow!("failed to obtain system randomness"))
    }
}

pub struct DefaultPasswordGenerator {
    rng: Arc<dyn Rng>,
    wordlist: &'static [&'static str],
}

impl DefaultPasswordGenerator {
    pub fn new(rng: Arc<dyn Rng>) -> Self {
        Self { rng, wordlist: WORDS }
    }

    #[cfg(test)]
    pub fn new_with_wordlist(rng: Arc<dyn Rng>, wordlist: &'static [&'static str]) -> Self {
        Self { rng, wordlist }
    }
}

impl PasswordGenerator for DefaultPasswordGenerator {
    fn generate(&self, policy: &GenPolicy) -> Result<String> {
        if policy.passphrase {
            return generate_passphrase(&*self.rng, self.wordlist, policy.words, &policy.sep);
        }
        generate_chars(&*self.rng, policy)
    }
}

// ===== Character-mode generator =====

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/\\|`~";
const AMBIGUOUS: &[u8] = b"O0Il|1"; // Avoid common ambiguities

fn filter_ambiguous(mut v: Vec<u8>) -> Vec<u8> {
    v.retain(|c| !AMBIGUOUS.contains(c));
    v
}

fn uniform_index(rng: &dyn Rng, len: usize) -> Result<usize> {
    if len == 0 { return Err(anyhow!("empty pool")); }
    // Rejection sampling on u32 space
    let n = len as u32;
    let zone = (u32::MAX / n) * n;
    loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b)?;
        let x = u32::from_le_bytes(b);
        if x < zone {
            return Ok((x % n) as usize);
        }
    }
}

fn fy_shuffle(rng: &dyn Rng, data: &mut [u8]) -> Result<()> {
    if data.len() <= 1 { return Ok(()); }
    for i in (1..data.len()).rev() {
        let j = uniform_index(rng, i + 1)?;
        data.swap(i, j);
    }
    Ok(())
}

fn generate_chars(rng: &dyn Rng, policy: &GenPolicy) -> Result<String> {
    let mut classes: Vec<Vec<u8>> = Vec::new();
    if policy.lower { classes.push(LOWER.to_vec()); }
    if policy.upper { classes.push(UPPER.to_vec()); }
    if policy.digits { classes.push(DIGITS.to_vec()); }
    if policy.symbols { classes.push(SYMBOLS.to_vec()); }
    if classes.is_empty() {
        return Err(anyhow!("No character classes selected"));
    }
    if policy.avoid_ambiguous {
        for cls in &mut classes {
            *cls = filter_ambiguous(std::mem::take(cls));
        }
    }
    // Ensure all classes are non-empty after filtering
    if classes.iter().any(|c| c.is_empty()) {
        return Err(anyhow!("Selected classes empty after filtering (too restrictive)"));
    }

    let need = policy.length as usize;
    if need < classes.len() {
        return Err(anyhow!("Length must be >= number of selected classes"));
    }

    // Pick one from each class first
    let mut out: Vec<u8> = Vec::with_capacity(need);
    for cls in &classes {
        let idx = uniform_index(rng, cls.len())?;
        out.push(cls[idx]);
    }

    // Build combined pool
    let mut pool: Vec<u8> = Vec::new();
    for cls in &classes { pool.extend_from_slice(cls); }

    // Fill the rest
    while out.len() < need {
        let idx = uniform_index(rng, pool.len())?;
        out.push(pool[idx]);
    }

    // Shuffle to avoid predictable class order
    fy_shuffle(rng, &mut out)?;
    Ok(String::from_utf8(out).unwrap())
}

// ===== Passphrase-mode generator =====

fn generate_passphrase(rng: &dyn Rng, wordlist: &'static [&'static str], words: u16, sep: &str) -> Result<String> {
    if wordlist.is_empty() { return Err(anyhow!("wordlist empty")); }
    let count = words.max(1) as usize;
    let mut parts: Vec<&'static str> = Vec::with_capacity(count);
    let n = wordlist.len();
    for _ in 0..count {
        let idx = uniform_index(rng, n)?;
        parts.push(wordlist[idx]);
    }
    Ok(parts.join(sep))
}

// ===== Basic strength estimator (optional UI hint) =====
pub fn estimate_bits_char_mode(policy: &GenPolicy) -> f64 {
    let mut pool: usize = 0;
    if policy.lower { pool += LOWER.len(); }
    if policy.upper { pool += UPPER.len(); }
    if policy.digits { pool += DIGITS.len(); }
    if policy.symbols { pool += SYMBOLS.len(); }
    if policy.avoid_ambiguous {
        // Remove ambiguous characters approximately
        let ambiguous_set = AMBIGUOUS.len();
        // Roughly distribute removal across pools
        pool = pool.saturating_sub(ambiguous_set.min(pool));
    }
    if pool == 0 { return 0.0; }
    let per_char = (pool as f64).log2();
    per_char * (policy.length as f64)
}

pub fn estimate_bits_passphrase(words: u16, wordlist_len: usize) -> f64 {
    if wordlist_len == 0 { return 0.0; }
    (wordlist_len as f64).log2() * (words as f64)
}

pub fn strength_label(bits: f64) -> &'static str {
    if bits < 28.0 { "very weak" } else if bits < 36.0 { "weak" } else if bits < 60.0 { "fair" } else if bits < 128.0 { "strong" } else { "excellent" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::sync::Arc;

    struct MockRng {
        data: std::sync::Mutex<Vec<u8>>,
    }
    impl MockRng { fn new(seq: &[u8]) -> Self { Self { data: std::sync::Mutex::new(seq.to_vec()) } } }
    impl Rng for MockRng {
        fn fill(&self, bytes: &mut [u8]) -> Result<()> {
            let mut guard = self.data.lock().unwrap();
            if guard.is_empty() { *guard = vec![0u8; 1024]; }
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
        let mut p = GenPolicy::default();
        p.length = 24;
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
        let mut p = GenPolicy::default();
        p.symbols = false;
        p.digits = false;
        p.length = 12;
        let s = gen.generate(&p).unwrap();
        assert_eq!(s.len(), 12);
        assert!(s.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn invalid_policy_rejected() {
        let rng = Arc::new(MockRng::new(&[0; 32]));
        let gen = DefaultPasswordGenerator::new(rng);
        let mut p = GenPolicy::default();
        p.lower = false;
        p.upper = false;
        p.digits = false;
        p.symbols = false;
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
        let mut p = GenPolicy::default();
        p.passphrase = true;
        p.words = 5;
        p.sep = ":".to_string();
        let s = gen.generate(&p).unwrap();
        let parts: Vec<&str> = s.split(':').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts.iter().all(|w| !w.is_empty()));
        assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == ':'));
    }
}
