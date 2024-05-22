use crate::issuer::Issuer;
use std::collections::HashMap;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct Configuration {
    pub issuers: HashMap<String, Issuer>,
}
