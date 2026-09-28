use biscuit::{jwa::SignatureAlgorithm, jws::Secret};
use openidconnect::{
    JsonWebKeyId,
    core::{CoreJsonWebKey, CoreJwsSigningAlgorithm},
};
use ring::signature::RsaKeyPair;
use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey, traits::PublicKeyParts};
use std::sync::Arc;

#[derive(Clone)]
pub struct Key {
    id: String,
    key_pair: Arc<RsaKeyPair>,
    n: Vec<u8>,
    e: Vec<u8>,
}

impl Key {
    pub fn generate(id: impl Into<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let pkcs8_der = private_key.to_pkcs8_der()?;
        let key_pair =
            RsaKeyPair::from_pkcs8(pkcs8_der.as_bytes()).map_err(|e| format!("ring: {e}"))?;

        let public_key = private_key.to_public_key();
        let n = public_key.n().to_bytes_be();
        let e = public_key.e().to_bytes_be();

        Ok(Self {
            id: id.into(),
            key_pair: Arc::new(key_pair),
            n,
            e,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn secret(&self) -> Secret {
        Secret::RsaKeyPair(self.key_pair.clone())
    }

    pub fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RS256
    }

    pub(crate) fn core_alg(&self) -> CoreJwsSigningAlgorithm {
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256
    }

    pub fn key(&self) -> CoreJsonWebKey {
        CoreJsonWebKey::new_rsa(
            self.n.clone(),
            self.e.clone(),
            Some(JsonWebKeyId::new(self.id.clone())),
        )
    }
}
