use biscuit::{jwa::SignatureAlgorithm, jws::Secret};
use openidconnect::{core::CoreJsonWebKey, JsonWebKey};

#[derive(Clone)]
pub struct Key {
    id: String,
    key: Vec<u8>,
}

impl Key {
    pub fn new(id: impl Into<String>, key: impl Into<Vec<u8>>) -> Self {
        Self {
            id: id.into(),
            key: key.into(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn secret(&self) -> Secret {
        Secret::Bytes(self.key.clone())
    }

    pub fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::HS256
    }

    pub fn key(&self) -> CoreJsonWebKey {
        CoreJsonWebKey::new_symmetric(self.key.clone())
    }
}
