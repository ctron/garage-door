pub mod state;

use crate::{endpoints, issuer::Issuer, server::state::ServerState};
use actix_web::middleware::{Logger, NormalizePath};
use actix_web::{web, App, HttpServer};
use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::{AddrParseError, IpAddr, Ipv6Addr, SocketAddr},
};
use tokio::net::TcpListener;

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Addr(#[from] AddrParseError),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("duplicate issuer: {0}")]
    DuplicateIssuer(String),
}

pub struct Server {
    port: u16,
    bind: IpAddr,

    issuers: HashMap<String, Issuer>,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    pub fn new() -> Self {
        Self {
            port: 8080,
            bind: IpAddr::V6(Ipv6Addr::LOCALHOST),
            issuers: Default::default(),
        }
    }

    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }

    pub fn bind(&mut self, bind: IpAddr) -> &mut Self {
        self.bind = bind;
        self
    }

    pub fn add_issuer(&mut self, issuer: Issuer) -> Result<&mut Self, Error> {
        let name = issuer.name.clone();
        match self.issuers.entry(name) {
            Entry::Vacant(entry) => {
                entry.insert(issuer);
                Ok(self)
            }
            Entry::Occupied(_) => Err(Error::DuplicateIssuer(issuer.name)),
        }
    }

    /// Run the server until it's shut down
    pub async fn run(self) -> Result<(), StartupError> {
        let state = ServerState::new(self.issuers.into_values().collect());

        let addr = SocketAddr::new(self.bind, self.port);
        let listener = TcpListener::bind(addr).await?;
        let listener = listener.into_std()?;

        if let Ok(addr) = listener.local_addr() {
            log::info!("Listening on: http://{addr}");
        }

        let state = web::Data::new(state);

        HttpServer::new(move || {
            App::new()
                .wrap(NormalizePath::trim())
                .wrap(Logger::default())
                .app_data(state.clone())
                .service(endpoints::index)
                .service(endpoints::issuer::index)
                .service(endpoints::issuer::discovery)
                .service(endpoints::issuer::auth)
                .service(endpoints::issuer::keys)
                .service(endpoints::issuer::token)
        })
        .listen(listener)?
        .run()
        .await?;

        Ok(())
    }
}
