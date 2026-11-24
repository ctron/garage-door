use crate::{extensions::ConnectionInformation, oidc::AccessTokenClaims, secrets::Key};
use anyhow::bail;
use biscuit::{
    ClaimsSet, CompactJson, CompactPart, RegisteredClaims, SingleOrMultiple,
    jws::{Compact, RegisteredHeader},
};
use openidconnect::{
    Audience, EmptyAdditionalClaims, IssuerUrl, Nonce, StandardClaims, SubjectIdentifier,
    core::CoreIdTokenClaims,
};
use oxide_auth::primitives::{generator::TagGrant, grant::Grant};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct JwtAccessGenerator {
    /// The relative base of the issuer
    issuer_base: String,
    key: Key,
}

impl JwtAccessGenerator {
    pub fn new(issuer_base: String, key: Key) -> Self {
        Self { issuer_base, key }
    }

    fn create(&self, grant: &Grant) -> Result<String, anyhow::Error> {
        let issued_at: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .try_into()?;

        let Some(conn) = grant
            .extensions
            .private()
            .filter_map(|(k, v)| {
                if k == ConnectionInformation::id() {
                    v
                } else {
                    None
                }
            })
            .filter_map(ConnectionInformation::decode)
            .next()
        else {
            bail!("Missing connection information");
        };

        let issuer = format!("{}://{}{}", conn.scheme, conn.host, self.issuer_base);

        let expected_claims = ClaimsSet::<AccessTokenClaims> {
            registered: RegisteredClaims {
                issuer: Some(issuer),
                subject: Some(grant.owner_id.clone()),
                issued_at: Some(issued_at.into()),
                audience: Some(SingleOrMultiple::Single(grant.client_id.clone())),
                expiry: Some(grant.until.into()),
                ..Default::default()
            },
            private: AccessTokenClaims {
                azp: Some(grant.client_id.clone()),
                scope: grant.scope.to_string(),
                ..Default::default()
            },
        };

        encode(&self.key, expected_claims)
    }
}

fn encode<T: CompactPart>(key: &Key, claims: T) -> Result<String, anyhow::Error> {
    let jwt = Compact::new_decoded(
        From::from(RegisteredHeader {
            algorithm: key.algorithm(),
            key_id: Some(key.id().to_string()),
            ..Default::default()
        }),
        claims,
    );

    Ok(jwt.into_encoded(&key.secret())?.encoded()?.to_string())
}

impl TagGrant for JwtAccessGenerator {
    fn tag(&mut self, _usage: u64, grant: &Grant) -> Result<String, ()> {
        self.create(grant).map_err(|err| {
            tracing::warn!("Unable to create JWT: {err}");
        })
    }
}

pub struct JwtIdGenerator {
    issuer: IssuerUrl,
    key: Key,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CoreIdToken(CoreIdTokenClaims);

impl CompactJson for CoreIdToken {}

impl JwtIdGenerator {
    pub fn new(key: Key, issuer: IssuerUrl) -> Self {
        Self { key, issuer }
    }

    pub fn create(&self, client_id: &str, nonce: Option<&str>) -> Result<String, anyhow::Error> {
        let aud = vec![Audience::new(client_id.into())];
        let issue_time = SystemTime::now();
        let expiration_time = issue_time + Duration::from_secs(600);
        let subject = SubjectIdentifier::new("Marvin".into());
        let std = StandardClaims::new(subject);

        let claims = CoreIdTokenClaims::new(
            self.issuer.clone(),
            aud,
            expiration_time.into(),
            issue_time.into(),
            std,
            EmptyAdditionalClaims::default(),
        )
        .set_nonce(nonce.map(|n| Nonce::new(n.to_string())));

        encode(&self.key, CoreIdToken(claims))
    }
}
