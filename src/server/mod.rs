pub mod app;
pub mod state;

use crate::{issuer::IssueBuildError, issuer::Issuer, server::app::Application};
use actix_web::{
    middleware::{Logger, NormalizePath},
    web, App, HttpServer,
};
use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::{AddrParseError, IpAddr, Ipv6Addr, SocketAddr},
};
use tokio::net::TcpListener;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Addr(#[from] AddrParseError),
    #[error("failed to construct base URL: {0}")]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Issue(#[from] IssueBuildError),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("duplicate issuer: {0}")]
    DuplicateIssuer(String),
}

pub struct Server {
    port: u16,
    bind: IpAddr,

    base: Option<String>,

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
            base: None,
        }
    }

    pub fn base(&mut self, base: impl Into<String>) -> &mut Self {
        self.base = Some(base.into());
        self
    }

    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }

    pub fn bind(&mut self, bind: IpAddr) -> &mut Self {
        self.bind = bind;
        self
    }

    pub fn add_issuer(&mut self, name: String, issuer: Issuer) -> Result<&mut Self, Error> {
        match self.issuers.entry(name.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(issuer);
                Ok(self)
            }
            Entry::Occupied(_) => Err(Error::DuplicateIssuer(name)),
        }
    }

    /// Run the server
    pub async fn run(self) -> Result<(), StartupError> {
        self.create().await?.await?;
        Ok(())
    }

    /// Turn the server into an http server, runs when polled (using .await)
    pub async fn create(self) -> Result<actix_web::dev::Server, StartupError> {
        let addr = SocketAddr::new(self.bind, self.port);
        let listener = TcpListener::bind(addr).await?;
        let listener = listener.into_std()?;

        let addr = listener.local_addr()?;
        let mut base = Url::parse(&format!("http://{addr}"))?;
        if let Some(path) = &self.base {
            base = base.join(path)?;
        }
        log::info!("Listening on: {base}");

        let app = Application::new(base, self.issuers)?;

        Ok(HttpServer::new(move || {
            App::new()
                .wrap(NormalizePath::trim())
                .wrap(Logger::default())
                .configure(|svc| match &self.base {
                    Some(path) => {
                        let scope = format!("/{path}");
                        svc.service(web::scope(&scope).configure(|svc| app.configure(svc)));
                    }
                    None => app.configure(svc),
                })
        })
        .listen(listener)?
        .run())
    }
}
