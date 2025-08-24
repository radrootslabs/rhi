use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyProfile {
    pub key: String,
    pub identifier: String,
    pub metadata: Option<nostr::Event>,
    pub application_handler: Option<nostr::Event>,
}

impl radroots_identity::IdentitySpec for KeyProfile {
    type Keys = nostr::Keys;
    type ParseError = nostr::key::Error;

    fn generate_new() -> Self {
        let keys = nostr::Keys::generate();
        Self {
            key: keys.secret_key().to_secret_hex(),
            identifier: uuid::Uuid::new_v4().to_string(),
            metadata: None,
            application_handler: None,
        }
    }

    fn to_keys(&self) -> Result<Self::Keys, Self::ParseError> {
        use std::str::FromStr;
        nostr::Keys::from_str(&self.key)
    }
}
