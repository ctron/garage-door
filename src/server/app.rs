use crate::{
    endpoints,
    issuer::{IssueBuildError, Issuer},
    server::state::ApplicationState,
};
use actix_web::{web, web::ServiceConfig};
use std::collections::HashMap;
use url::Url;

#[derive(Clone)]
pub struct Application {
    state: web::Data<ApplicationState>,
}

impl Application {
    pub fn new(
        base: Url,
        path: Option<String>,
        issuers: HashMap<String, Issuer>,
    ) -> Result<Self, IssueBuildError> {
        let state = ApplicationState::new(issuers, base, path)?;
        let state = web::Data::new(state);

        Ok(Self { state })
    }

    pub fn configure(&self, svc: &mut ServiceConfig) {
        svc.app_data(self.state.clone())
            .service(endpoints::index)
            .service(endpoints::issuer::index)
            .service(endpoints::issuer::discovery)
            .service(endpoints::issuer::auth_get)
            .service(endpoints::issuer::auth_post)
            .service(endpoints::issuer::keys)
            .service(endpoints::issuer::token);
    }
}
