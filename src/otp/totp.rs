use crate::otp::handlers::OtpAddOptions;
use crate::otp::models::{OtpAlgorithm, OtpEntry};
use crate::error::{OtpError, OtpResult};
use totp_rs::Secret;

/// Build a TOTP generator from an OtpEntry. Base32 secret is expected to be valid.
pub fn build_totp(entry: &OtpEntry) -> OtpResult<totp_rs::TOTP> {
    let algo = OtpAlgorithm::map_to_totp(&entry.algorithm);
    let encoded = Secret::Encoded(entry.secret.clone())
        .to_bytes()
        .map_err(|e| OtpError::InvalidSecretBase32(e.to_string()))?;

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
pub fn validate_totp_params(opts: &OtpAddOptions) -> OtpResult<()> {
    if opts.digits != 6 && opts.digits != 8 {
        return Err(OtpError::InvalidDigits);
    }

    if opts.period == 0 {
        return Err(OtpError::InvalidPeriod);
    }

    if opts.secret.is_none() && opts.from_uri.is_none() {
        return Err(OtpError::MissingSecretSource);
    }

    Ok(())
}
