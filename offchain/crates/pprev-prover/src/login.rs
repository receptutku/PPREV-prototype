//! Login to the registry over an ordinary TLS connection, outside the notarised session.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Exchanges account credentials for a bearer token.
pub async fn login(
    addr: SocketAddr,
    server_name: &str,
    ca_der: &[u8],
    account: &str,
    password: &str,
) -> Result<String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec()))?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(addr).await?;
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(server_name.to_string())?, tcp)
        .await?;

    let body = serde_json::json!({ "account": account, "password": password }).to_string();
    let request = format!(
        "POST /login HTTP/1.1\r\nHost: {server_name}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;

    let head_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed login response")?;
    ensure!(
        response.starts_with(b"HTTP/1.1 200 "),
        "login rejected: {}",
        String::from_utf8_lossy(&response[..head_end])
    );
    let json: serde_json::Value = serde_json::from_slice(&response[head_end + 4..])?;
    json["token"]
        .as_str()
        .map(str::to_string)
        .context("login response has no token")
}
