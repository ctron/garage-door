mod token;

use crate::endpoints::Error;
use crate::issuer::token::JwtGenerator;
use actix_web::web::Bytes;
use biscuit::jws::Secret;
use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
    CoreJsonWebKey, CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
    CoreSubjectIdentifierType,
};
use openidconnect::{
    AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySetUrl, LogoutProviderMetadata,
    ProviderMetadata, ProviderMetadataWithLogout, ResponseTypes, TokenUrl,
};
use oxide_auth::frontends::simple::endpoint::{Generic, Vacant};
use oxide_auth::primitives::issuer::TokenMap;
use oxide_auth::primitives::prelude::*;
use oxide_auth::primitives::registrar::RegisteredUrl;
use oxide_auth_actix::OAuthResponse;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

type Endpoint = Generic<
    ClientMap,
    AuthMap<RandomGenerator>,
    TokenMap<JwtGenerator>,
    Vacant,
    Vec<Scope>,
    fn() -> OAuthResponse,
>;

#[derive(Clone, Debug)]
pub struct Issuer {
    pub name: String,
    pub url: Url,
}

impl Issuer {
    pub fn new(
        name: impl Into<String>,
        // TODO: it would be best to make the token generation dynamic, right now oxide-auth prevents us from doing this
        public_url: Url,
    ) -> anyhow::Result<Self> {
        let name = name.into();
        let url = public_url.join(&name)?;
        Ok(Self { name, url })
    }

    pub fn build(self) -> IssuerState {
        let url = RegisteredUrl::Semantic(Url::parse("http://localhost").unwrap());

        // FIXME: keys
        let secret = Secret::None;

        let endpoint = Endpoint {
            registrar: vec![Client::confidential(
                "client-id",
                url,
                "default-scope".parse().unwrap(),
                "client-secret".as_bytes(),
            )]
            .into_iter()
            .collect(),
            authorizer: AuthMap::new(RandomGenerator::new(16)),
            issuer: TokenMap::new(JwtGenerator::new(self.url.to_string(), secret)),
            solicitor: Vacant,
            scopes: vec!["default-scope".parse().unwrap()],
            response: OAuthResponse::ok,
        };

        IssuerState {
            name: self.name,
            inner: Arc::new(RwLock::new(InnerState { endpoint })),
        }
    }
}

#[derive(Clone)]
pub struct IssuerState {
    pub name: String,
    pub inner: Arc<RwLock<InnerState>>,
}

impl IssuerState {
    pub fn keys(&self) -> Result<CoreJsonWebKeySet, Error> {
        let keys = vec![];

        Ok(CoreJsonWebKeySet::new(keys))
    }

    pub fn discovery(&self, base: Url) -> Result<ProviderMetadataWithLogout, Error> {
        let build = {
            let base = base.clone();
            move |segment| {
                let mut url = base.clone();
                url.path_segments_mut()
                    .map_err(|()| Error::Url)?
                    .push(segment);
                Ok::<Url, Error>(url)
            }
        };

        let issuer = IssuerUrl::from_url(base);
        let authorization_endpoint = AuthUrl::from_url(build("auth")?);
        let jwks_uri = JsonWebKeySetUrl::from_url(build("keys")?);

        let response_types_supported: Vec<_> =
            vec![ResponseTypes::new(vec![CoreResponseType::Token])];
        let subject_types_supported = vec![CoreSubjectIdentifierType::Public];
        let id_token_signing_alg_values_supported = vec![]; // CoreJwsSigningAlgorithm::HmacSha256
        let additional_metadata = LogoutProviderMetadata {
            end_session_endpoint: None,
            additional_metadata: EmptyAdditionalProviderMetadata::default(),
        };

        Ok(ProviderMetadataWithLogout::new(
            issuer,
            authorization_endpoint,
            jwks_uri,
            response_types_supported,
            subject_types_supported,
            id_token_signing_alg_values_supported,
            additional_metadata,
        )
        .set_token_endpoint(Some(TokenUrl::from_url(build("token")?)))
        .set_token_endpoint_auth_methods_supported(Some(vec![
            CoreClientAuthMethod::ClientSecretBasic,
            CoreClientAuthMethod::ClientSecretPost,
        ])))
    }
}

impl IssuerState {}

pub struct InnerState {
    pub endpoint: Endpoint,
}
