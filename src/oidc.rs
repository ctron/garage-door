use serde::{Deserialize, Serialize};

/// Access token claims
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AccessTokenClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<u64>,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}
