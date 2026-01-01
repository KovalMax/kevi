use crate::otp::handlers::OtpAddOptions;
use crate::otp::models::OtpEntry;
use totp_rs::TOTP;

/// Parse an otp-auth://totp URI and produce an OtpEntry scaffold.
/// Note: secret is kept in base32 form; caller should validate further if needed.
pub fn parse_otp_entry(opts: &OtpAddOptions) -> anyhow::Result<OtpEntry> {
    let secret_string = if let Some(uri) = opts.from_uri.as_ref() {
        let parsed = TOTP::from_url_unchecked(uri)?;
        parsed.get_secret_base32()
    } else {
        let secret = opts.secret.clone().unwrap_or_default();
        if secret.trim().is_empty() {
            anyhow::bail!("secret cannot be empty");
        }
        secret
    };

    let entry = OtpEntry {
        name: opts.name.clone(),
        secret: secret_string,
        issuer: opts.issuer.clone(),
        username: opts.username.clone().unwrap_or_default(),
        digits: opts.digits,
        period: opts.period,
        algorithm: opts.algorithm.clone(),
        notes: opts.notes.clone(),
    };
    Ok(entry)
}
