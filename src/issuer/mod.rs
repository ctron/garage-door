mod token;

use crate::endpoints::Error;
use crate::issuer::token::JwtGenerator;
use biscuit::jws::Secret;
use openidconnect::core::{
    CoreClientAuthMethod, CoreJsonWebKeySet, CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{
    AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySetUrl, LogoutProviderMetadata,
    ProviderMetadataWithLogout, ResponseTypes, TokenUrl,
};
use oxide_auth::{
    frontends::simple::endpoint::{Generic, Vacant},
    primitives::{
        prelude::{Client as OxideClient, *},
        registrar::{ExactUrl, RegisteredUrl},
        scope::ParseScopeErr,
    },
};
use oxide_auth_actix::OAuthResponse;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

pub type Endpoint = Generic<
    ClientMap,
    AuthMap<RandomGenerator>,
    TokenMap<JwtGenerator>,
    Vacant,
    Vec<Scope>,
    fn() -> OAuthResponse,
>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct Issuer {
    pub name: String,
    pub clients: Vec<Client>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Client {
    Confidential {
        id: String,
        secret: String,
        #[serde(default = "default::default_scope")]
        default_scope: String,
    },
    Public {
        id: String,
        redirect_url: RedirectUrl,
        #[serde(default = "default::default_scope")]
        default_scope: String,
    },
}

mod default {
    pub fn default_scope() -> String {
        "openid".to_string()
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum RedirectUrl {
    Semantic(Url),
    Exact(String),
    // FIXME: use once https://github.com/HeroicKatora/oxide-auth/issues/175 is fixed
    /*
    #[serde(rename_all = "camelCase")]
    Exact {
        url: String,
        /// ignore the port on localhost URLs
        ignore_localhost_port: bool,
    },*/
}

impl TryFrom<RedirectUrl> for RegisteredUrl {
    type Error = url::ParseError;

    fn try_from(value: RedirectUrl) -> Result<Self, Self::Error> {
        Ok(match value {
            RedirectUrl::Semantic(url) => Self::Semantic(url),
            RedirectUrl::Exact(url) => Self::Exact(ExactUrl::from_str(&url)?),
            // FIXME: use once https://github.com/HeroicKatora/oxide-auth/issues/175 is fixed
            /*
            RedirectUrl::Exact {
                url,
                ignore_localhost_port: false,
            } => Self::Exact(ExactUrl::from_str(&url)?),
            RedirectUrl::Exact {
                url,
                ignore_localhost_port: true,
            } => Self::IgnorePortOnLocalhost(IgnoreLocalPortUrl::from_str(&url)?),
             */
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IssueBuildError {
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Scope(#[from] ParseScopeErr),
}

impl Issuer {
    pub fn new(name: impl Into<String>) -> anyhow::Result<Self> {
        let name = name.into();
        Ok(Self {
            name,
            clients: Default::default(),
        })
    }

    pub fn add_client(mut self, client: Client) -> Self {
        self.clients.push(client);
        self
    }

    pub fn build(self, base: Url) -> Result<IssuerState, IssueBuildError> {
        let base = base.join(&self.name)?;

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
                    redirect_url,
                    default_scope,
                } => {
                    registrar.push(OxideClient::public(
                        &id,
                        redirect_url.try_into()?,
                        default_scope.parse()?,
                    ));
                }
            }
        }

        // FIXME: keys
        let secret = Secret::None;

        let endpoint = Endpoint {
            registrar: registrar.into_iter().collect(),
            authorizer: AuthMap::new(RandomGenerator::new(16)),
            issuer: TokenMap::new(JwtGenerator::new(base.to_string(), secret)),
            solicitor: Vacant,
            scopes: vec!["default-scope".parse().unwrap()],
            response: OAuthResponse::ok,
        };

        Ok(IssuerState {
            name: self.name,
            inner: Arc::new(RwLock::new(InnerState { endpoint })),
        })
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
