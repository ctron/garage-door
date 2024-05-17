use crate::issuer::Issuer;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct Configuration {
    pub issuers: Vec<Issuer>,
}
