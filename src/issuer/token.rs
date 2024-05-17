use crate::oidc::AccessTokenClaims;
use biscuit::{
    jwa::SignatureAlgorithm,
    jws::{Compact, RegisteredHeader, Secret},
    ClaimsSet, RegisteredClaims, SingleOrMultiple, Timestamp,
};
use oxide_auth::primitives::{generator::TagGrant, grant::Grant};

pub struct JwtGenerator {
    issuer: String,
    secret: Secret,
}

impl JwtGenerator {
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
                audience: Some(SingleOrMultiple::Single(
                    "https://acme-customer.com/".to_string(),
                )),
                expiry,
                ..Default::default()
            },
            private: AccessTokenClaims {
                azp: Some(grant.client_id.clone()),
                auth_time: None,
                scope: grant.scope.to_string(),
            },
        };

        let jwt = Compact::new_decoded(
            From::from(RegisteredHeader {
                algorithm: SignatureAlgorithm::None,
                ..Default::default()
            }),
            expected_claims.clone(),
        );

        Ok(jwt.into_encoded(&self.secret)?.encoded()?.to_string())
    }
}

impl TagGrant for JwtGenerator {
    fn tag(&mut self, _usage: u64, grant: &Grant) -> Result<String, ()> {
        self.create(grant).map_err(|err| {
            tracing::warn!("Unable to create JWT: {err}");
        })
    }
}
