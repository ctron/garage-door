use crate::issuer::{IssueBuildError, Issuer, IssuerState};
use log::Level::Info;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub struct ApplicationState {
    inner: Arc<InnerApplicationState>,
}

impl ApplicationState {
    pub fn new(issuers: HashMap<String, Issuer>, base: Url) -> Result<Self, IssueBuildError> {
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
                    let base = base.join(&name)?;
                    let state = issuer.build(base)?;
                    Ok::<_, IssueBuildError>((name, state))
                })
                .collect::<Result<_, _>>()?,
        };
        Ok(Self {
            inner: Arc::new(inner),
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
}

struct InnerApplicationState {
    issuers: HashMap<String, IssuerState>,
}
