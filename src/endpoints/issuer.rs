use crate::endpoints::Error;
use crate::server::state::ServerState;
use actix_web::dev::ConnectionInfo;
use actix_web::web::Json;
use actix_web::{get, post, web, HttpResponse, Responder};
use oxide_auth::endpoint::{ClientCredentialsFlow, OwnerConsent, QueryParameter, Solicitation};
use oxide_auth::frontends::simple::endpoint::{FnSolicitor, Generic};
use oxide_auth_actix::{OAuthOperation, OAuthRequest, OAuthResponse, Token, WebError};
use url::Url;

#[get("/{issuer}/.well-known/openid-configuration")]
pub async fn discovery(
    server: web::Data<ServerState>,
    path: web::Path<String>,
    conn: ConnectionInfo,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let base = Url::parse(&format!("{}://{}/{name}", conn.scheme(), conn.host()))?;

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    Ok(HttpResponse::Ok().json(issuer.discovery(base)?))
}

#[get("/{issuer}")]
pub async fn index(
    server: web::Data<ServerState>,
    path: web::Path<String>,
) -> Result<String, Error> {
    let name = path.into_inner();

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    Ok(format!("Issuer: {}", issuer.name))
}

#[get("/{issuer}/auth")]
pub async fn auth(
    server: web::Data<ServerState>,
    path: web::Path<String>,
    req: OAuthRequest,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    Ok(HttpResponse::NotImplemented())
}

#[get("/{issuer}/keys")]
pub async fn keys(
    server: web::Data<ServerState>,
    path: web::Path<String>,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    Ok(Json(issuer.keys()?))
}

#[post("/{issuer}/token")]
pub async fn token(
    server: web::Data<ServerState>,
    path: web::Path<String>,
    req: OAuthRequest,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    let endpoint = &mut issuer.inner.write().await.endpoint;

    let grant_type = req.body().and_then(|body| body.unique_value("grant_type"));

    Ok(match grant_type.as_deref() {
        Some("client_credentials") => {
            let mut flow = ClientCredentialsFlow::prepare(Generic {
                registrar: &mut endpoint.registrar,
                authorizer: &mut endpoint.authorizer,
                issuer: &mut endpoint.issuer,
                solicitor: FnSolicitor(move |_: &mut OAuthRequest, solicitation: Solicitation| {
                    OwnerConsent::Authorized(solicitation.pre_grant().client_id.clone())
                }),
                scopes: &mut endpoint.scopes,
                response: OAuthResponse::ok,
            })
            .map_err(WebError::from)?;
            flow.allow_credentials_in_body(true);
            flow.execute(req).map_err(WebError::from)?
        }

        _ => Token(req).run(endpoint)?,
    })
}