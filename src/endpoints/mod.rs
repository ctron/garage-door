use crate::server::state::ApplicationState;
use actix_web::body::BoxBody;
use actix_web::{HttpResponse, Responder, ResponseError, get, web};
use oxide_auth_actix::WebError;
use serde::Serialize;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
pub enum Error {
    #[error("unknown issuer: {0}")]
    UnknownIssuer(String),
    #[error("url error")]
    Url,
    #[error("url parse error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("json error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Oxide(#[from] WebError),
    #[error("generic error: {0}")]
    Generic(String),
}

#[derive(Serialize)]
struct ErrorInformation {
    error: &'static str,
    message: String,
}

impl Error {
    fn to_body(&self) -> ErrorInformation {
        ErrorInformation {
            error: self.into(),
            message: self.to_string(),
        }
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match &self {
            Self::UnknownIssuer(_) => HttpResponse::NotFound().json(self.to_body()),
            _ => HttpResponse::InternalServerError().json(self.to_body()),
        }
    }
}

#[get("")]
pub async fn index(app: web::Data<ApplicationState>) -> impl Responder {
    #[allow(clippy::format_collect)]
    let issuers = app
        .issuers()
        .into_iter()
        .map(|name| format!("  * {name}\n"))
        .collect::<String>();
    format!(
        r#"Garage Door
============

Issuers:

{issuers}

"#
    )
}

pub mod issuer;
