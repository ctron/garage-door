use actix_web::body::BoxBody;
use actix_web::{get, HttpResponse, ResponseError};
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

#[get("/")]
pub async fn index() -> String {
    "Hello World!".into()
}

pub mod issuer;
