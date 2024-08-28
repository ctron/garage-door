mod helper;

use crate::{endpoints::Error, server::state::ApplicationState};
use actix_web::http::header;
use actix_web::{
    dev::ConnectionInfo,
    get, post,
    web::{self, Json},
    HttpResponse, Responder,
};
use helper::*;
use oxide_auth::{
    endpoint::{ClientCredentialsFlow, OwnerConsent, QueryParameter, Solicitation},
    frontends::simple::endpoint::FnSolicitor,
};
use oxide_auth_actix::{Authorize, OAuthOperation, OAuthRequest, Refresh, Token, WebError};
use serde::Deserialize;
use url::Url;

#[get("/{issuer}/.well-known/openid-configuration")]
pub async fn discovery(
    server: web::Data<ApplicationState>,
    path: web::Path<String>,
    conn: ConnectionInfo,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let base = issuer_url(&server, &conn, &name, [])?;

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    Ok(HttpResponse::Ok().json(issuer.discovery(base).await?))
}

fn issuer_url(
    server: &ApplicationState,
    conn: &ConnectionInfo,
    issuer: &str,
    path: impl IntoIterator<Item = &'static str>,
) -> Result<Url, Error> {
    let mut url = server.build_base(conn)?;

    {
        let mut p = url
            .path_segments_mut()
            .map_err(|()| url::ParseError::RelativeUrlWithCannotBeABaseBase)?;

        p.push(issuer);

        for seg in path {
            p.push(seg);
        }
    }

    Ok(url)
}

#[get("/{issuer}")]
pub async fn index(
    server: web::Data<ApplicationState>,
    path: web::Path<String>,
) -> Result<String, Error> {
    let name = path.into_inner();

    let _issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name.clone()))?;

    Ok(format!("Issuer: {name}"))
}

#[get("/{issuer}/auth")]
pub async fn auth_get(
    server: web::Data<ApplicationState>,
    conn: ConnectionInfo,
    path: web::Path<String>,
    req: OAuthRequest,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    let endpoint = &mut issuer.inner.write().await.endpoint;

    Ok(Authorize(req).run(with_conninfo(
        with_solicitor(
            endpoint,
            FnSolicitor(move |_: &mut OAuthRequest, _: Solicitation| {
                OwnerConsent::Authorized("Marvin".into())
            }),
        ),
        conn,
    )))
}

#[get("/{issuer}/keys")]
pub async fn keys(
    server: web::Data<ApplicationState>,
    path: web::Path<String>,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    Ok(Json(issuer.keys()?))
}

#[get("/{issuer}/userinfo")]
pub async fn userinfo_get(
    server: web::Data<ApplicationState>,
    path: web::Path<String>,
) -> Result<impl Responder, Error> {
    userinfo(server, path).await
}

#[post("/{issuer}/userinfo")]
pub async fn userinfo_post(
    server: web::Data<ApplicationState>,
    path: web::Path<String>,
) -> Result<impl Responder, Error> {
    userinfo(server, path).await
}

async fn userinfo(
    server: web::Data<ApplicationState>,
    path: web::Path<String>,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    Ok(Json(issuer.userinfo()))
}

#[post("/{issuer}/refresh")]
pub async fn refresh(
    server: web::Data<ApplicationState>,
    conn: ConnectionInfo,
    req: OAuthRequest,
    path: web::Path<String>,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    let endpoint = &mut issuer.inner.write().await.endpoint;

    Ok(Refresh(req).run(with_conninfo(endpoint, conn.clone()))?)
}

#[post("/{issuer}/token")]
pub async fn token(
    server: web::Data<ApplicationState>,
    conn: ConnectionInfo,
    path: web::Path<String>,
    req: OAuthRequest,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name.clone()))?;

    let endpoint = &mut issuer.inner.write().await.endpoint;

    let grant_type = req.body().and_then(|body| body.unique_value("grant_type"));

    Ok(match grant_type.as_deref() {
        Some("client_credentials") => {
            let mut flow = ClientCredentialsFlow::prepare(with_conninfo(
                with_solicitor(
                    endpoint,
                    FnSolicitor(move |_: &mut OAuthRequest, solicitation: Solicitation| {
                        OwnerConsent::Authorized(solicitation.pre_grant().client_id.clone())
                    }),
                ),
                conn.clone(),
            ))
            .map_err(WebError::from)?;
            flow.allow_credentials_in_body(true);
            flow.execute(req).map_err(WebError::from)?
        }
        Some("refresh_token") => Refresh(req).run(with_conninfo(endpoint, conn.clone()))?,
        _ => {
            let resp = Token(req).run(with_conninfo(endpoint, conn.clone()))?;
            amend_id_token(resp, &server, &issuer, &conn, &name)?
        }
    })
}

#[derive(Clone, Debug, Deserialize)]
struct LogoutQuery {
    pub post_logout_redirect_uri: Option<String>,
}

#[get("/{issuer}/logout")]
pub async fn logout(
    server: web::Data<ApplicationState>,
    path: web::Path<String>,
    web::Query(LogoutQuery {
        post_logout_redirect_uri,
    }): web::Query<LogoutQuery>,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let _issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    match post_logout_redirect_uri {
        Some(uri) => Ok(HttpResponse::TemporaryRedirect()
            .append_header((header::LOCATION, uri))
            .finish()),
        None => Ok(HttpResponse::NoContent().finish()),
    }
}
