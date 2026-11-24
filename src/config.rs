use crate::issuer::Issuer;
use std::collections::HashMap;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct Configuration {
    pub issuers: HashMap<String, Issuer>,
}

#[cfg(all(test, feature = "serde-saphyr"))]
mod tests {
    use super::*;
    use crate::issuer::{Client, RedirectUrl};

    #[test]
    fn reads_example_yaml_configuration() -> anyhow::Result<()> {
        let config: Configuration =
            serde_saphyr::from_reader(include_bytes!("../examples/config.yaml").as_slice())?;
        let issuer = &config.issuers["chickens"];
        assert_eq!(issuer.scopes, ["openid", "foo"]);
        assert_eq!(issuer.clients.len(), 2);
        assert!(matches!(&issuer.clients[0], Client::Confidential { id, .. } if id == "client-id"));

        let Client::Public {
            id,
            redirect_urls,
            default_scope,
        } = &issuer.clients[1]
        else {
            panic!("expected a public client");
        };
        assert_eq!(id, "frontend");
        assert_eq!(default_scope, "openid");
        assert_eq!(
            redirect_urls,
            &[RedirectUrl::Exact {
                url: "http://localhost".into(),
                ignore_localhost_port: true,
            }]
        );
        Ok(())
    }
}
