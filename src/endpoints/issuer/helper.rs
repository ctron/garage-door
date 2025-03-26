use crate::{
    endpoints::{Error, issuer::issuer_url},
    extensions::ConnectionInformation,
    issuer::{IssuerState, JwtIdGenerator},
    server::state::ApplicationState,
};
use actix_web::dev::ConnectionInfo;
use openidconnect::IssuerUrl;
use oxide_auth::endpoint::WebResponse;
use oxide_auth::{
    endpoint::{Endpoint, OwnerSolicitor},
    frontends::simple::{
        endpoint::{ErrorInto, Generic},
        extensions::{AddonList, Extended},
    },
};
use oxide_auth_actix::{OAuthRequest, OAuthResponse, WebError};
use serde_json::Value;
use std::sync::Arc;

/// take a token response and add an id token
pub fn amend_id_token(
    mut resp: OAuthResponse,
    server: &ApplicationState,
    issuer: &IssuerState,
    conn: &ConnectionInfo,
    issuer_name: &str,
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

    let base = issuer_url(server, conn, issuer_name, [])?;

    let id_token = JwtIdGenerator::new(issuer.key.clone(), IssuerUrl::from_url(base))
        .create()
        .map_err(|err| Error::Generic(err.to_string()))?;

    value["id_token"] = serde_json::to_value(id_token)?;

    resp.body_json(&serde_json::to_string(&value)?)?;

    Ok(resp)
}

pub fn with_conninfo<Inner>(inner: Inner, conn: ConnectionInfo) -> Extended<Inner, AddonList> {
    log::debug!("Adding conninfo: {conn:?}");

    let conn = Arc::new(ConnectionInformation(conn));

    let mut addons = AddonList::new();
    addons.push_access_token(conn.clone());
    addons.push_client_credentials(conn);

    Extended::extend_with(inner, addons)
}

pub fn with_solicitor<S>(
    endpoint: &mut Extended<crate::issuer::Endpoint, AddonList>,
    solicitor: S,
) -> impl Endpoint<OAuthRequest, Error = WebError> + '_
where
    S: OwnerSolicitor<OAuthRequest> + 'static,
{
    ErrorInto::new(Extended {
        inner: Generic {
            authorizer: &mut endpoint.inner.authorizer,
            registrar: &mut endpoint.inner.registrar,
            issuer: &mut endpoint.inner.issuer,
            solicitor,
            scopes: &mut endpoint.inner.scopes,
            response: OAuthResponse::ok,
        },
        addons: &mut endpoint.addons,
    })
}
