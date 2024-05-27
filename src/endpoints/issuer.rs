use crate::{endpoints::Error, issuer::JwtIdGenerator, server::state::ApplicationState};
use actix_web::{
    dev::ConnectionInfo,
    get, post,
    web::{self, Json},
    HttpResponse, Responder,
};
use biscuit::jws::Secret;
use openidconnect::IssuerUrl;
use oxide_auth::endpoint::{
    ClientCredentialsFlow, Endpoint, OwnerConsent, OwnerSolicitor, QueryParameter, Solicitation,
    WebResponse,
};
use oxide_auth::frontends::simple::endpoint::{ErrorInto, FnSolicitor, Generic};
use oxide_auth_actix::{Authorize, OAuthOperation, OAuthRequest, OAuthResponse, Token, WebError};
use serde_json::Value;
use url::Url;

#[get("/{issuer}/.well-known/openid-configuration")]
pub async fn discovery(
    server: web::Data<ApplicationState>,
    path: web::Path<String>,
    conn: ConnectionInfo,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let base = issuer_url(&server, &conn, &name)?;

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    Ok(HttpResponse::Ok().json(issuer.discovery(base).await?))
}

fn issuer_url(
    server: &ApplicationState,
    conn: &ConnectionInfo,
    issuer: &str,
) -> Result<Url, Error> {
    let mut url = server.build_base(conn)?;
    url.path_segments_mut()
        .map_err(|()| url::ParseError::RelativeUrlWithCannotBeABaseBase)?
        .push(issuer);
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
    path: web::Path<String>,
    req: OAuthRequest,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    let endpoint = &mut issuer.inner.write().await.endpoint;

    Ok(Authorize(req).run(with_solicitor(
        endpoint,
        FnSolicitor(move |_: &mut OAuthRequest, _: Solicitation| {
            OwnerConsent::Authorized("Marvin".into())
        }),
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

// FIXME: we need to post version as well
#[get("/{issuer}/userinfo")]
pub async fn userinfo_get(
    server: web::Data<ApplicationState>,
    path: web::Path<String>,
) -> Result<impl Responder, Error> {
    let name = path.into_inner();

    let issuer = server
        .issuer(&name)
        .ok_or_else(|| Error::UnknownIssuer(name))?;

    Ok(Json(issuer.userinfo()))
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
            let mut flow = ClientCredentialsFlow::prepare(with_solicitor(
                endpoint,
                FnSolicitor(move |_: &mut OAuthRequest, solicitation: Solicitation| {
                    OwnerConsent::Authorized(solicitation.pre_grant().client_id.clone())
                }),
            ))
            .map_err(WebError::from)?;
            flow.allow_credentials_in_body(true);
            flow.execute(req).map_err(WebError::from)?
        }

        _ => {
            let resp = Token(req).run(endpoint)?;
            amend_id_token(resp, &server, &conn, &name)?
        }
    })
}

/// take a token response and add an id token
fn amend_id_token(
    mut resp: OAuthResponse,
    server: &ApplicationState,
    conn: &ConnectionInfo,
    issuer: &str,
) -> Result<OAuthResponse, Error> {
    let Some(Ok(mut value)) = resp
        .get_body()
        .map(|body| serde_json::from_str::<Value>(&body))
    else {
        return Ok(resp);
    };

    let Some(_access_token) = value["access_token"].as_str() else {
        return Ok(resp);
    };

    let base = issuer_url(server, conn, issuer)?;

    let id_token = JwtIdGenerator::new(Secret::None, IssuerUrl::from_url(base))
        .create()
        .map_err(|err| Error::Generic(err.to_string()))?;

    value["id_token"] = serde_json::to_value(id_token)?;

    resp.body_json(&serde_json::to_string(&value)?)?;

    Ok(resp)
}

pub fn with_solicitor<S>(
    endpoint: &mut crate::issuer::Endpoint,
    solicitor: S,
) -> impl Endpoint<OAuthRequest, Error = WebError> + '_
where
    S: OwnerSolicitor<OAuthRequest> + 'static,
{
    ErrorInto::new(Generic {
        authorizer: &mut endpoint.authorizer,
        registrar: &mut endpoint.registrar,
        issuer: &mut endpoint.issuer,
        solicitor,
        scopes: &mut endpoint.scopes,
        response: OAuthResponse::ok,
    })
}
