pub mod secret_string {
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
}

pub mod secret_string_option {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};

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
}
