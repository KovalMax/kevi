use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serializer};

// Serde helpers for Option<SecretString>
pub fn serialize<S>(value: &Option<SecretString>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(s) => serializer.serialize_some(s.expose_secret()),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::<String>::deserialize(deserializer)?;
    Ok(opt.map(|s| SecretString::new(s.into())))
}
