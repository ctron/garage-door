use biscuit::SingleOrMultiple;
use serde::{Deserialize, Serialize};
use url::Url;

/// Access token claims
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessTokenClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
}
