use crate::oidc::AccessTokenClaims;
use biscuit::{
    jwa::SignatureAlgorithm,
    jws::{Compact, RegisteredHeader, Secret},
    ClaimsSet, CompactJson, CompactPart, RegisteredClaims, SingleOrMultiple, Timestamp,
};
use chrono::{Duration, Utc};
use openidconnect::core::CoreIdTokenClaims;
use openidconnect::{
    Audience, EmptyAdditionalClaims, IssuerUrl, StandardClaims, SubjectIdentifier,
};
use oxide_auth::primitives::{generator::TagGrant, grant::Grant};
use serde::{Deserialize, Serialize};

const AUD: &str = "some-audience";

pub struct JwtAccessGenerator {
    issuer: String,
    secret: Secret,
}

impl JwtAccessGenerator {
    pub fn new(issuer: String, secret: Secret) -> Self {
        Self { issuer, secret }
    }

    fn create(&self, grant: &Grant) -> Result<String, anyhow::Error> {
        let expiry =
            chrono::DateTime::from_timestamp(grant.until.timestamp(), 0).map(Timestamp::from);

        let expected_claims = ClaimsSet::<AccessTokenClaims> {
            registered: RegisteredClaims {
                issuer: Some(self.issuer.clone()),
                subject: Some(grant.owner_id.clone()),
                issued_at: Some(Utc::now().into()),
                audience: Some(SingleOrMultiple::Single(AUD.to_string())),
                expiry,
                ..Default::default()
            },
            private: AccessTokenClaims {
                azp: Some(grant.client_id.clone()),
                scope: grant.scope.to_string(),
                ..Default::default()
            },
        };

        encode(&self.secret, expected_claims)
    }
}

fn encode<T: CompactPart>(secret: &Secret, claims: T) -> Result<String, anyhow::Error> {
    // FIXME: need to implement
    let jwt = Compact::new_decoded(
        From::from(RegisteredHeader {
            algorithm: SignatureAlgorithm::None,
            ..Default::default()
        }),
        claims,
    );

    Ok(jwt.into_encoded(secret)?.encoded()?.to_string())
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
    secret: Secret,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CoreIdToken(CoreIdTokenClaims);

impl CompactJson for CoreIdToken {}

impl JwtIdGenerator {
    pub fn new(secret: Secret, issuer: IssuerUrl) -> Self {
        Self { secret, issuer }
    }

    pub fn create(&self) -> Result<String, anyhow::Error> {
        let aud = vec![Audience::new(AUD.into())];
        let issue_time = Utc::now();
        let expiration_time = Utc::now() + Duration::seconds(600);
        let subject = SubjectIdentifier::new("Marvin".into());
        let std = StandardClaims::new(subject);

        let claims = CoreIdTokenClaims::new(
            self.issuer.clone(),
            aud,
            expiration_time,
            issue_time,
            std,
            EmptyAdditionalClaims::default(),
        );

        encode(&self.secret, CoreIdToken(claims))
    }
}
