use crate::issuer::{Issuer, IssuerState};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct ServerState {
    inner: Arc<InnerServerState>,
}

impl ServerState {
    pub fn new(issuer: Vec<Issuer>) -> Self {
        let inner = InnerServerState {
            issuers: issuer
                .into_iter()
                .map(|issuer| (issuer.name.clone(), issuer.build()))
                .collect(),
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    pub fn issuer(&self, name: &str) -> Option<IssuerState> {
        self.inner.issuers.get(name).cloned()
    }
}

struct InnerServerState {
    issuers: HashMap<String, IssuerState>,
}
