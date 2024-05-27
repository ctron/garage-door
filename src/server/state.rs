use crate::issuer::{IssueBuildError, Issuer, IssuerState};
use actix_web::dev::ConnectionInfo;
use log::Level::Info;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub struct ApplicationState {
    base_path: Option<String>,
    inner: Arc<InnerApplicationState>,
}

impl ApplicationState {
    pub fn new(
        issuers: HashMap<String, Issuer>,
        public_base: Url,
        base_path: Option<String>,
    ) -> Result<Self, IssueBuildError> {
        let base = match &base_path {
            Some(base_path) => public_base.join(base_path)?,
            None => public_base,
        };

        if log::log_enabled!(Info) {
            log::info!("Issuers:");
            for (name, issuer) in &issuers {
                log::info!("  {name}");
                log::info!("  Clients:");
                for client in &issuer.clients {
                    log::info!("    {} = {:?}", client.id(), client);
                }
            }
        }

        let inner = InnerApplicationState {
            issuers: issuers
                .into_iter()
                .map(|(name, issuer)| {
                    let mut base = base.clone();
                    base.path_segments_mut()
                        .map_err(|()| url::ParseError::RelativeUrlWithCannotBeABaseBase)?
                        .push(&name);
                    let state = issuer.build(base)?;
                    Ok::<_, IssueBuildError>((name, state))
                })
                .collect::<Result<_, _>>()?,
        };
        Ok(Self {
            inner: Arc::new(inner),
            base_path,
        })
    }

    /// Get a single issuer by name
    pub fn issuer(&self, name: &str) -> Option<IssuerState> {
        self.inner.issuers.get(name).cloned()
    }

    /// Get the names of all issuers
    pub fn issuers(&self) -> Vec<String> {
        self.inner.issuers.keys().cloned().collect()
    }

    /// Build the base URL based on the request
    pub fn build_base(&self, conn: &ConnectionInfo) -> Result<Url, url::ParseError> {
        let url = format!("{}://{}", conn.scheme(), conn.host());
        let mut url = Url::parse(&url)?;

        if let Some(base) = &self.base_path {
            url.path_segments_mut()
                .map_err(|()| url::ParseError::RelativeUrlWithCannotBeABaseBase)?
                .push(base);
        }

        Ok(url)
    }
}

struct InnerApplicationState {
    issuers: HashMap<String, IssuerState>,
}
