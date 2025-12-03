// Custom serde helpers for secrecy::SecretString
// Serializes the underlying secret as a regular string while keeping Debug redacted.
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S>(value: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.expose_secret())
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(SecretString::new(s.into()))
}
