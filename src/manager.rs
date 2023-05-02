use async_trait::async_trait;
#[cfg(feature = "tls")]
use rustls::{client::InvalidDnsNameError, ClientConfig, ServerName};
use std::convert::TryFrom;
use std::net::SocketAddr;
#[cfg(feature = "tls")]
use tokio_rustls::rustls::OwnedTrustAnchor;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    system_conf::read_system_conf,
};
use url::Url;

use crate::connection::Connection;
use crate::{MemcacheError, driver};
#[cfg(feature = "tls")]
use crate::{ErrorKind, connection::TlsConfig};

/// A `bb8::ManageConnection` for `memcache_async::ascii::Protocol`.
#[derive(Clone, Debug)]
pub struct ConnectionManager {
    url: Url,
    resolver: TokioAsyncResolver,
    #[cfg(feature = "tls")]
    tls_config: TlsConfig
}

#[cfg(not(feature = "tls"))]
impl ConnectionManager {
    /// Initialize ConnectionManager with given URL
    pub fn new(url: Url, resolver: TokioAsyncResolver) -> ConnectionManager {
        ConnectionManager { url, resolver }
    }
}

#[cfg(feature = "tls")]
impl ConnectionManager {
    /// Initialize secure ConnectionManager with given URL and default TLS config
    pub fn new(url: Url, resolver: TokioAsyncResolver) -> ConnectionManager {
        Self::new_with_config(url, resolver, TlsConfig::new(Self::default_tls_config()))
    }

    /// Initialize secure ConnectionManager with given URL and custom TLS config
    pub fn new_with_config(url: Url, resolver: TokioAsyncResolver, tls_config: TlsConfig) -> ConnectionManager {
        ConnectionManager { url, resolver, tls_config }
    }

    fn default_tls_config() -> ClientConfig {
        let mut root_cert_store = rustls::RootCertStore::empty();

        // Add default WebPKI certs
        root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
            |ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            },
        ));

        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth()
    }
}

impl TryFrom<Url> for ConnectionManager {
    type Error = MemcacheError;

    fn try_from(value: Url) -> Result<Self, Self::Error> {
        let (config, opts) = read_system_conf()?;

        let resolver = TokioAsyncResolver::tokio(config, opts)?;

        Ok(Self::new(value, resolver))
    }
}

impl TryFrom<&str> for ConnectionManager {
    type Error = MemcacheError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let (config, opts) = read_system_conf()?;

        let resolver = TokioAsyncResolver::tokio(config, opts)?;

        Ok(Self::new(Url::parse(value)?, resolver))
    }
}

impl TryFrom<(&str, ResolverConfig, ResolverOpts)> for ConnectionManager {
    type Error = MemcacheError;

    fn try_from(value: (&str, ResolverConfig, ResolverOpts)) -> Result<Self, Self::Error> {
        let resolver = TokioAsyncResolver::tokio(value.1, value.2)?;

        Ok(Self::new(Url::parse(value.0)?, resolver))
    }
}

impl TryFrom<(Url, ResolverConfig, ResolverOpts)> for ConnectionManager {
    type Error = MemcacheError;

    fn try_from(value: (Url, ResolverConfig, ResolverOpts)) -> Result<Self, Self::Error> {
        let resolver = TokioAsyncResolver::tokio(value.1, value.2)?;

        Ok(Self::new(value.0, resolver))
    }
}

#[cfg(feature = "tls")]
impl TryFrom<(&str, TlsConfig)> for ConnectionManager {
    type Error = MemcacheError;

    fn try_from(value: (&str, TlsConfig)) -> Result<Self, Self::Error> {
        let (config, opts) = read_system_conf()?;

        let resolver = TokioAsyncResolver::tokio(config, opts)?;

        Ok(Self::new_with_config(Url::parse(value.0)?, resolver, value.1))
    }
}

#[cfg(feature = "tls")]
impl TryFrom<(Url, TlsConfig)> for ConnectionManager {
    type Error = MemcacheError;

    fn try_from(value: (Url, TlsConfig)) -> Result<Self, Self::Error> {
        let (config, opts) = read_system_conf()?;

        let resolver = TokioAsyncResolver::tokio(config, opts)?;

        Ok(Self::new_with_config(value.0, resolver, value.1))
    }
}

#[cfg(feature = "tls")]
impl TryFrom<(&str, ResolverConfig, ResolverOpts, TlsConfig)> for ConnectionManager {
    type Error = MemcacheError;

    fn try_from(value: (&str, ResolverConfig, ResolverOpts, TlsConfig)) -> Result<Self, Self::Error> {
        let resolver = TokioAsyncResolver::tokio(value.1, value.2)?;

        Ok(Self::new_with_config(Url::parse(value.0)?, resolver, value.3))
    }
}


#[async_trait]
impl bb8::ManageConnection for ConnectionManager {
    type Connection = Connection;
    type Error = MemcacheError;

    #[cfg(not(feature = "tls"))]
    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let addresses = match self.url.domain() {
            Some(domain) => {
                let response = self.resolver.lookup_ip(domain).await?;

                let port = self.url.port().unwrap_or(11211);

                response
                    .iter()
                    .map(|address| SocketAddr::new(address, port))
                    .collect()
            }
            None => self.url.socket_addrs(|| None)?,
        };

        Connection::connect(&*addresses).await.map_err(Into::into)
    }

    #[cfg(feature = "tls")]
    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let (addresses, server_name) = match self.url.domain() {
            Some(domain) => {
                let response = self.resolver.lookup_ip(domain).await?;

                let port = self.url.port().unwrap_or(11211);

                let addresses = response
                    .iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect();

                (addresses, ServerName::try_from(domain)?)
            }
            None => {
                let addresses = self.url.socket_addrs(|| None)?;
                match addresses.first().map(|it| it.ip()) {
                    Some(addr) => {
                        (addresses, ServerName::IpAddress(addr))
                    }
                    None => {
                        return Err(MemcacheError::Memcache(ErrorKind::Generic("No IP addresses resolved".to_string())));
                    }
                }
            }
        };

        Connection::connect(&*addresses, server_name, self.tls_config.clone()).await.map_err(Into::into)
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        driver::ping(conn).await
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.has_broken()
    }
}

#[cfg(feature = "tls")]
impl From<InvalidDnsNameError> for MemcacheError {
    fn from(value: InvalidDnsNameError) -> Self {
        MemcacheError::Memcache(ErrorKind::Generic(value.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    #[test]
    fn test_url_domain() {
        let link = Url::parse("https://with.sub.example.org:2993/").unwrap();
        assert_eq!(link.domain().unwrap(), "with.sub.example.org");
    }
}
