use crate::issuer::{IssueBuildError, Issuer, IssuerState};
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub struct ServerState {
    inner: Arc<InnerServerState>,
}

impl ServerState {
    pub fn new(issuer: Vec<Issuer>, base: Url) -> Result<Self, IssueBuildError> {
        let inner = InnerServerState {
            issuers: issuer
                .into_iter()
                .map(|issuer| {
                    let name = issuer.name.clone();
                    let state = issuer.build(base.clone())?;
                    Ok::<_, IssueBuildError>((name, state))
                })
                .collect::<Result<_, _>>()?,
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    pub fn issuer(&self, name: &str) -> Option<IssuerState> {
        self.inner.issuers.get(name).cloned()
    }
}

struct InnerServerState {
    issuers: HashMap<String, IssuerState>,
}
