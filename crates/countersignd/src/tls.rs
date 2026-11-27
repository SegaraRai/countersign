//! Serving HTTPS: TLS termination for the web UI and the intake API.
//!
//! countersign assumes no particular network. A listener either terminates
//! TLS itself (`tls = { cert_file, key_file }`) or sits behind a reverse
//! proxy or tunnel that does, on a loopback or private address. Certificates
//! are loaded at startup and reloaded without downtime on `SIGHUP`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::server::TlsStream;

/// How long a client may take to finish the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshakes finished but not yet picked up by the server.
const BACKLOG: usize = 64;
/// Most TLS handshakes running concurrently.
const MAX_CONCURRENT_HANDSHAKES: usize = 64;

/// `tls = { cert_file = "...", key_file = "..." }`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain, leaf first.
    pub cert_file: PathBuf,
    /// PEM private key (PKCS#8, PKCS#1 or SEC1).
    pub key_file: PathBuf,
}

/// Holds a dynamically reloadable TLS certificate chain and private key.
pub struct CertReloader {
    config: TlsConfig,
    current: RwLock<Arc<CertifiedKey>>,
}

impl std::fmt::Debug for CertReloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertReloader").field("cert_file", &self.config.cert_file).finish_non_exhaustive()
    }
}

impl CertReloader {
    fn load(c: &TlsConfig) -> Result<Arc<CertifiedKey>, String> {
        let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
        let certs = CertificateDer::pem_slice_iter(&read(&c.cert_file)?)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{}: {e}", c.cert_file.display()))?;
        if certs.is_empty() {
            return Err(format!("{}: no certificate found", c.cert_file.display()));
        }
        let key = PrivateKeyDer::from_pem_slice(&read(&c.key_file)?)
            .map_err(|e| format!("{}: no usable private key ({e})", c.key_file.display()))?;
        let provider = tokio_rustls::rustls::crypto::ring::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| format!("{}: invalid private key ({e})", c.key_file.display()))?;
        let certified = CertifiedKey::new(certs, signing_key);
        certified
            .keys_match()
            .map_err(|e| format!("{}: certificate and key do not match ({e})", c.cert_file.display()))?;
        Ok(Arc::new(certified))
    }

    /// Re-read the certificate and private key from disk and swap them in for
    /// new TLS handshakes. On error, the previous certificate stays active.
    pub fn reload(&self) -> Result<(), String> {
        let next = Self::load(&self.config)?;
        *self.current.write().unwrap_or_else(std::sync::PoisonError::into_inner) = next;
        Ok(())
    }
}

impl ResolvesServerCert for CertReloader {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.current.read().unwrap_or_else(std::sync::PoisonError::into_inner)))
    }
}

/// Load the certificate and key into a reloadable server configuration.
pub fn reloadable_server_config(c: &TlsConfig) -> Result<(Arc<ServerConfig>, Arc<CertReloader>), String> {
    let certified = CertReloader::load(c)?;
    let reloader = Arc::new(CertReloader { config: c.clone(), current: RwLock::new(certified) });
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(Arc::clone(&reloader) as Arc<dyn ResolvesServerCert>);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((Arc::new(config), reloader))
}

/// Load the certificate and key into a server configuration.
pub fn server_config(c: &TlsConfig) -> Result<Arc<ServerConfig>, String> {
    reloadable_server_config(c).map(|(cfg, _)| cfg)
}

/// A TCP listener that hands axum only connections that completed a TLS
/// handshake. Handshakes run concurrently, so a slow client cannot hold up
/// the others.
#[derive(Debug)]
pub struct TlsListener {
    rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl TlsListener {
    pub fn new(tcp: TcpListener, config: Arc<ServerConfig>) -> std::io::Result<Self> {
        let local = tcp.local_addr()?;
        let acceptor = TlsAcceptor::from(config);
        let (tx, rx) = mpsc::channel(BACKLOG);
        let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES));
        let task = tokio::spawn(async move {
            loop {
                let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
                    break;
                };
                let (stream, peer) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(e) => {
                        drop(permit);
                        // Usually running out of file descriptors; back off.
                        tracing::warn!(error = %e, "accepting a connection failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            if tx.try_send((tls, peer)).is_err() {
                                tracing::debug!(%peer, "TLS accept backlog full; dropping connection");
                            }
                        }
                        Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                        Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                    }
                });
            }
        });
        Ok(Self { rx, local, task })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(c) => c,
            // The accept task only ends when aborted, i.e. on drop.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_garbage_files_are_reported() {
        let dir = std::env::temp_dir().join(format!("cs-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let garbage = dir.join("garbage.pem");
        std::fs::write(&garbage, "not a certificate").unwrap();
        let c = TlsConfig { cert_file: dir.join("missing.pem"), key_file: garbage.clone() };
        assert!(server_config(&c).unwrap_err().contains("missing.pem"));
        let c = TlsConfig { cert_file: garbage.clone(), key_file: garbage };
        assert!(server_config(&c).unwrap_err().contains("no certificate"));
    }
}
