use crate::domain::OtpName;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OtpEntry {
    pub name: OtpName,
    pub secret: String,
    pub issuer: Option<String>,
    pub username: String,
    pub digits: u32,
    pub period: u64,
    pub algorithm: OtpAlgorithm,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl OtpAlgorithm {
    pub fn map_to_totp(algo: &OtpAlgorithm) -> totp_rs::Algorithm {
        match algo {
            OtpAlgorithm::Sha1 => totp_rs::Algorithm::SHA1,
            OtpAlgorithm::Sha256 => totp_rs::Algorithm::SHA256,
            OtpAlgorithm::Sha512 => totp_rs::Algorithm::SHA512,
        }
    }

    pub fn format(&self) -> &'static str {
        match self {
            OtpAlgorithm::Sha1 => "SHA1",
            OtpAlgorithm::Sha256 => "SHA256",
            OtpAlgorithm::Sha512 => "SHA512",
        }
    }
}
