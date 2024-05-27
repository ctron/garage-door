mod redirect_url;
mod token;

pub use redirect_url::*;
pub use token::*;

use crate::endpoints::Error;
use biscuit::jws::Secret;
use hide::Hide;
use openidconnect::core::{
    CoreClientAuthMethod, CoreGrantType, CoreJsonWebKeySet, CoreResponseType,
    CoreSubjectIdentifierType, CoreUserInfoClaims,
};
use openidconnect::{
    AuthUrl, EmptyAdditionalClaims, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySetUrl,
    LogoutProviderMetadata, ProviderMetadataWithLogout, ResponseTypes, StandardClaims,
    SubjectIdentifier, TokenUrl, UserInfoUrl,
};
use oxide_auth::{
    frontends::simple::{
        endpoint::{Generic, Vacant},
        extensions::{AddonList, Extended},
    },
    primitives::{
        prelude::{Client as OxideClient, *},
        registrar::RegisteredUrl,
        scope::ParseScopeErr,
    },
};
use oxide_auth_actix::OAuthResponse;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

pub type Endpoint = Generic<
    ClientMap,
    AuthMap<RandomGenerator>,
    TokenMap<JwtAccessGenerator>,
    Vacant,
    Vec<Scope>,
    fn() -> OAuthResponse,
>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Client {
    #[serde(rename_all = "camelCase")]
    Confidential {
        id: String,
        secret: Hide<String>,
        #[serde(default = "default::default_scope")]
        default_scope: String,
    },
    #[serde(rename_all = "camelCase")]
    Public {
        id: String,
        #[serde(deserialize_with = "redirect_url::or_string::deserialize_vec")]
        #[schemars(with = "Vec<redirect_url::RedirectUrlOrString>")]
        redirect_urls: Vec<RedirectUrl>,
        #[serde(default = "default::default_scope")]
        default_scope: String,
    },
}

impl Client {
    pub fn id(&self) -> &str {
        match self {
            Client::Confidential { id, .. } => id,
            Client::Public { id, .. } => id,
        }
    }
}

mod default {
    pub fn default_scope() -> String {
        "openid".to_string()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IssueBuildError {
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Scope(#[from] ParseScopeErr),
    #[error("Public client requires at least one redirect URI")]
    MissingRedirectUri,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct Issuer {
    pub scopes: Vec<String>,
    pub clients: Vec<Client>,
}

impl Issuer {
    pub fn new<I, S>(scopes: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Ok(Self {
            scopes: scopes.into_iter().map(|s| s.into()).collect(),
            clients: Default::default(),
        })
    }

    pub fn add_client(mut self, client: Client) -> Self {
        self.clients.push(client);
        self
    }

    pub fn build(self, base: Url) -> Result<IssuerState, IssueBuildError> {
        let mut registrar = vec![];

        for client in self.clients {
            match client {
                Client::Confidential {
                    id,
                    secret,
                    default_scope,
                } => {
                    // for the confidential client we don't really need it
                    let url = RegisteredUrl::Semantic(Url::parse("http://localhost")?);
                    registrar.push(OxideClient::confidential(
                        &id,
                        url,
                        default_scope.parse()?,
                        secret.as_bytes(),
                    ));
                }
                Client::Public {
                    id,
                    redirect_urls,
                    default_scope,
                } => {
                    let mut i = redirect_urls.into_iter();
                    let redirect_uri = i.next().ok_or(IssueBuildError::MissingRedirectUri)?;
                    registrar.push(
                        OxideClient::public(&id, redirect_uri.try_into()?, default_scope.parse()?)
                            .with_additional_redirect_uris(
                                i.map(|uri| uri.try_into()).collect::<Result<Vec<_>, _>>()?,
                            ),
                    );
                }
            }
        }

        // FIXME: keys
        let secret = Secret::None;

        let addons = AddonList::new();
        let endpoint = Extended {
            inner: Endpoint {
                registrar: registrar.into_iter().collect(),
                authorizer: AuthMap::new(RandomGenerator::new(16)),
                issuer: TokenMap::new(JwtAccessGenerator::new(base.path().into(), secret)),
                solicitor: Vacant,
                scopes: self
                    .scopes
                    .into_iter()
                    .map(|scope| scope.parse())
                    .collect::<Result<Vec<_>, _>>()?,
                response: OAuthResponse::ok,
            },
            addons,
        };

        Ok(IssuerState {
            inner: Arc::new(RwLock::new(InnerState { endpoint })),
        })
    }
}

#[derive(Clone)]
pub struct IssuerState {
    pub inner: Arc<RwLock<InnerState>>,
}

impl IssuerState {
    pub fn keys(&self) -> Result<CoreJsonWebKeySet, Error> {
        let keys = vec![];

        Ok(CoreJsonWebKeySet::new(keys))
    }

    pub async fn discovery(&self, base: Url) -> Result<ProviderMetadataWithLogout, Error> {
        let scopes = self
            .inner
            .read()
            .await
            .endpoint
            .inner
            .scopes
            .iter()
            .map(|scope| oauth2::Scope::new(scope.to_string()))
            .collect();

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
        ]))
        .set_scopes_supported(Some(scopes))
        .set_grant_types_supported(Some(vec![
            CoreGrantType::ClientCredentials,
            CoreGrantType::AuthorizationCode,
        ]))
        .set_userinfo_endpoint(Some(UserInfoUrl::from_url(build("userinfo")?))))
    }

    pub fn userinfo(&self) -> CoreUserInfoClaims {
        let subject = SubjectIdentifier::new("Marvin".into());
        let claims = StandardClaims::new(subject);
        CoreUserInfoClaims::new(claims, EmptyAdditionalClaims::default())
    }
}

impl IssuerState {}

pub struct InnerState {
    pub endpoint: Extended<Endpoint, AddonList>,
}

#[cfg(test)]
mod test {
    use crate::issuer::RedirectUrl;
    use oxide_auth::primitives::registrar::RegisteredUrl;
    use serde_json::json;

    #[test]
    fn test_redirect_serde() {
        let url: RedirectUrl = serde_json::from_value(json!({
            "exact": {
                "url": "http://localhost",
                "ignoreLocalhostPort": true,
            }
        }))
        .unwrap();

        println!("Url: {url:#?}");

        let url = RegisteredUrl::try_from(url).unwrap();

        println!("Url: {url:#?}");

        assert_eq!(
            serde_json::to_value(&url).unwrap(),
            json!({
                "IgnorePortOnLocalhost": "http://localhost/"
            })
        );
    }
}
