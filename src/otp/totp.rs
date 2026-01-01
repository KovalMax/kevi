use crate::otp::handlers::OtpAddOptions;
use crate::otp::models::{OtpAlgorithm, OtpEntry};
use anyhow::anyhow;
use totp_rs::Secret;

/// Build a TOTP generator from an OtpEntry. Base32 secret is expected to be valid.
pub fn build_totp(entry: &OtpEntry) -> anyhow::Result<totp_rs::TOTP> {
    let algo = OtpAlgorithm::map_to_totp(&entry.algorithm);
    let encoded = Secret::Encoded(entry.secret.clone())
        .to_bytes()
        .map_err(|e| anyhow!("invalid TOTP secret (expected Base32): {e}"))?;

    Ok(totp_rs::TOTP::new_unchecked(
        algo,
        entry.digits as usize,
        1,
        entry.period,
        encoded,
        entry.issuer.clone(),
        entry.username.clone(),
    ))
}

/// Validate digits, period and secret according to our constraints.
pub fn validate_totp_params(opts: &OtpAddOptions) -> anyhow::Result<()> {
    if opts.digits != 6 && opts.digits != 8 {
        anyhow::bail!("digits must be 6 or 8");
    }

    if opts.period == 0 {
        anyhow::bail!("period must be positive");
    }

    if opts.secret.is_none() && opts.from_uri.is_none() {
        anyhow::bail!("either --secret or --from-uri must be provided");
    }

    Ok(())
}
