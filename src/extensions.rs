use actix_web::dev::ConnectionInfo;
use oxide_auth::{
    code_grant::accesstoken::Request,
    frontends::simple::extensions::{
        AccessTokenAddon, AddonResult, ClientCredentialsAddon, ClientCredentialsRequest,
    },
    primitives::grant::{GrantExtension, Value},
};
use std::borrow::Cow;

pub struct ConnectionInformation(pub ConnectionInfo);

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConnectionInformationData<'a> {
    pub scheme: Cow<'a, str>,
    pub host: Cow<'a, str>,
}

impl ConnectionInformation {
    pub fn id() -> &'static str {
        "garage_door::connection_information"
    }

    pub fn encode(&self) -> Value {
        Value::Private(
            serde_json::to_string(&ConnectionInformationData {
                scheme: self.0.scheme().into(),
                host: self.0.host().into(),
            })
            .ok(),
        )
    }

    pub fn decode(s: &str) -> Option<ConnectionInformationData> {
        serde_json::from_str(s).ok()
    }
}

impl GrantExtension for ConnectionInformation {
    fn identifier(&self) -> &'static str {
        Self::id()
    }
}

impl AccessTokenAddon for ConnectionInformation {
    fn execute(&self, _request: &dyn Request, _code_data: Option<Value>) -> AddonResult {
        log::debug!("Adding connection information (access token): {:?}", self.0);
        AddonResult::Data(self.encode())
    }
}

impl ClientCredentialsAddon for ConnectionInformation {
    fn execute(&self, _request: &dyn ClientCredentialsRequest) -> AddonResult {
        log::debug!("Adding connection information (access token): {:?}", self.0);
        AddonResult::Data(self.encode())
    }
}
