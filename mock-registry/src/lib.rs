//! Local HTTPS registry with fixed-layout responses (D4).
//!
//! `POST /login` exchanges account credentials for a bearer token; `GET /title/{propertyId}` returns
//! the title record, rendered by [`pprev_types::Layout`], together with the identifier of the
//! account that asked. With the Apply and Settle layouts, the registry also serves the sources of
//! phi_A and phi_S, rendered by [`pprev_types::RecordLayout`]: `GET /income` returns the eligibility
//! record of the logged-in account, and `GET /tenancy/{notationId}` returns a tenancy notation. TLS
//! is restricted to what TLSNotary's MPC mode handles: TLS 1.2,
//! `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, ECDHE over secp256r1.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use pprev_types::{Layout, RecordLayout, TitleRecord};
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::ServerConfig;
use rustls::crypto::ring as ring_provider;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Largest request the registry reads.
const MAX_REQUEST: usize = 8 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Account {
    pub id: String,
    pub password: String,
}

/// The eligibility record of one account: the source of phi_A.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IncomeRecord {
    pub account: String,
    /// Zero-padded decimal digits, in the denomination and scale the policy fixes.
    pub monthly_income: String,
}

/// A tenancy notation: the source of phi_S.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenancyNotation {
    pub id: String,
    pub property_id: String,
    pub tenant: String,
    /// `YYYY-MM-DD` in the registry's time zone.
    pub record_date: String,
}

impl TenancyNotation {
    fn values(&self) -> [&str; 3] {
        [&self.property_id, &self.tenant, &self.record_date]
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Fixtures {
    pub accounts: Vec<Account>,
    pub records: Vec<TitleRecord>,
    #[serde(default)]
    pub incomes: Vec<IncomeRecord>,
    #[serde(default)]
    pub tenancies: Vec<TenancyNotation>,
}

impl Fixtures {
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = path.as_ref();
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).context("parsing fixtures")
    }
}

/// A local certificate authority and the registry's leaf certificate, generated at run time.
#[derive(Clone)]
pub struct Certs {
    pub ca_der: Vec<u8>,
    pub leaf_der: Vec<u8>,
    pub leaf_key_der: Vec<u8>,
}

impl Certs {
    pub fn generate(server_name: &str) -> Result<Self> {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "PPREV test registry CA");
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key)?;

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut leaf_params = CertificateParams::new(vec![server_name.to_string()])?;
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, server_name);
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params.signed_by(&leaf_key, &ca)?;

        Ok(Self {
            ca_der: ca.der().to_vec(),
            leaf_der: leaf.der().to_vec(),
            leaf_key_der: leaf_key.serialize_der(),
        })
    }
}

/// TLS server configuration: TLS 1.2 only, one cipher suite, secp256r1 only.
pub fn tls_config(certs: &Certs) -> Result<Arc<ServerConfig>> {
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![ring_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        kx_groups: vec![ring_provider::kx_group::SECP256R1],
        ..ring_provider::default_provider()
    };
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certs.leaf_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certs.leaf_key_der.clone())),
        )?;
    Ok(Arc::new(config))
}

/// Layouts of the Apply and Settle sources, when the registry serves them.
#[derive(Clone, Debug, Default)]
pub struct PhaseLayouts {
    pub income: Option<RecordLayout>,
    pub tenancy: Option<RecordLayout>,
}

/// Registry state: fixtures, issued tokens, and the log of record responses sent.
pub struct Registry {
    layout: Layout,
    phases: PhaseLayouts,
    fixtures: Fixtures,
    tokens: Mutex<HashMap<String, String>>,
    sent: Mutex<Vec<Vec<u8>>>,
}

impl Registry {
    pub fn new(layout: Layout, fixtures: Fixtures) -> Result<Self> {
        Self::with_phases(layout, PhaseLayouts::default(), fixtures)
    }

    pub fn with_phases(layout: Layout, phases: PhaseLayouts, fixtures: Fixtures) -> Result<Self> {
        // Every record must render under its layout before the registry serves anything.
        for record in &fixtures.records {
            for account in &fixtures.accounts {
                layout.render_response(&account.id, record)?;
            }
        }
        if let Some(income) = &phases.income {
            for record in &fixtures.incomes {
                income.render_response(&record.account, &[&record.monthly_income])?;
            }
        }
        if let Some(tenancy) = &phases.tenancy {
            for notation in &fixtures.tenancies {
                for account in &fixtures.accounts {
                    tenancy.render_response(&account.id, &notation.values())?;
                }
            }
        }
        Ok(Self {
            layout,
            phases,
            fixtures,
            tokens: Mutex::default(),
            sent: Mutex::default(),
        })
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Exact bytes of every record response sent so far, in order.
    pub fn sent_log(&self) -> Vec<Vec<u8>> {
        self.sent.lock().expect("sent log").clone()
    }

    fn login(&self, body: &[u8]) -> Response {
        #[derive(Deserialize)]
        struct Credentials {
            account: String,
            password: String,
        }
        let Ok(creds) = serde_json::from_slice::<Credentials>(body) else {
            return Response::status(400, "Bad Request");
        };
        let known = self
            .fixtures
            .accounts
            .iter()
            .any(|a| a.id == creds.account && a.password == creds.password);
        if !known {
            return Response::status(401, "Unauthorized");
        }
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = hex::encode(raw);
        self.tokens
            .lock()
            .expect("tokens")
            .insert(token.clone(), creds.account);
        Response::json(
            200,
            "OK",
            &serde_json::json!({ "token": token }).to_string(),
        )
    }

    /// The account of a bearer token.
    fn account_of(&self, authorization: Option<&str>) -> Option<String> {
        authorization
            .and_then(|v| v.strip_prefix("Bearer "))
            .and_then(|token| self.tokens.lock().expect("tokens").get(token).cloned())
    }

    /// Records the bytes of a rendered response and returns it.
    fn sent(&self, bytes: Vec<u8>) -> Response {
        self.sent.lock().expect("sent log").push(bytes.clone());
        Response { bytes }
    }

    fn income(&self, layout: &RecordLayout, authorization: Option<&str>) -> Response {
        let Some(account) = self.account_of(authorization) else {
            return Response::status(401, "Unauthorized");
        };
        let Some(record) = self.fixtures.incomes.iter().find(|r| r.account == account) else {
            return Response::status(404, "Not Found");
        };
        match layout.render_response(&account, &[&record.monthly_income]) {
            Ok(rendered) => self.sent(rendered.bytes),
            Err(_) => Response::status(500, "Internal Server Error"),
        }
    }

    fn tenancy(&self, layout: &RecordLayout, id: &str, authorization: Option<&str>) -> Response {
        let Some(account) = self.account_of(authorization) else {
            return Response::status(401, "Unauthorized");
        };
        let Some(notation) = self.fixtures.tenancies.iter().find(|n| n.id == id) else {
            return Response::status(404, "Not Found");
        };
        match layout.render_response(&account, &notation.values()) {
            Ok(rendered) => self.sent(rendered.bytes),
            Err(_) => Response::status(500, "Internal Server Error"),
        }
    }

    fn title(&self, property_id: &str, authorization: Option<&str>) -> Response {
        let Some(account) = self.account_of(authorization) else {
            return Response::status(401, "Unauthorized");
        };
        let Some(record) = self
            .fixtures
            .records
            .iter()
            .find(|r| r.property_id == property_id)
        else {
            return Response::status(404, "Not Found");
        };
        match self.layout.render_response(&account, record) {
            Ok(rendered) => self.sent(rendered.bytes),
            Err(_) => Response::status(500, "Internal Server Error"),
        }
    }

    fn route(&self, request: &Request) -> Response {
        let authorization = request.header("authorization");
        match (request.method.as_str(), request.target.as_str()) {
            ("POST", "/login") => self.login(&request.body),
            ("GET", target) => {
                if let Some(income) = &self.phases.income
                    && target == income.path("")
                {
                    return self.income(income, authorization);
                }
                if let Some(tenancy) = &self.phases.tenancy
                    && let Some(id) = target.strip_prefix(&tenancy.path_prefix)
                {
                    return self.tenancy(tenancy, id, authorization);
                }
                match target.strip_prefix(&self.layout.path_prefix) {
                    Some(property_id) => self.title(property_id, authorization),
                    None => Response::status(404, "Not Found"),
                }
            }
            _ => Response::status(405, "Method Not Allowed"),
        }
    }
}

struct Response {
    bytes: Vec<u8>,
}

impl Response {
    fn status(code: u16, reason: &str) -> Self {
        Self::json(code, reason, "{}")
    }

    fn json(code: u16, reason: &str, body: &str) -> Self {
        let bytes = format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        Self { bytes }
    }
}

struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Parses one HTTP/1.1 request from `buf`, returning `None` while it is incomplete.
    fn parse(buf: &[u8]) -> Result<Option<Self>> {
        let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            return Ok(None);
        };
        let head = std::str::from_utf8(&buf[..head_end]).context("request head is not UTF-8")?;
        let mut lines = head.split("\r\n");
        let mut request_line = lines.next().unwrap_or_default().split(' ');
        let (Some(method), Some(target), Some(version)) = (
            request_line.next(),
            request_line.next(),
            request_line.next(),
        ) else {
            bail!("malformed request line");
        };
        if version != "HTTP/1.1" {
            bail!("unsupported HTTP version {version}");
        }
        let headers = lines
            .filter(|l| !l.is_empty())
            .map(|l| {
                let (k, v) = l
                    .split_once(':')
                    .ok_or_else(|| anyhow!("malformed header {l:?}"))?;
                Ok((k.trim().to_string(), v.trim().to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        let content_length = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.parse::<usize>())
            .transpose()
            .context("invalid Content-Length")?
            .unwrap_or(0);
        let body_start = head_end + 4;
        if buf.len() < body_start + content_length {
            return Ok(None);
        }
        Ok(Some(Self {
            method: method.to_string(),
            target: target.to_string(),
            headers,
            body: buf[body_start..body_start + content_length].to_vec(),
        }))
    }
}

/// Serves one request per TLS connection until the listener is dropped.
pub async fn serve(
    registry: Arc<Registry>,
    listener: TcpListener,
    tls: Arc<ServerConfig>,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(tls);
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(registry, acceptor, tcp).await {
                tracing::debug!("connection ended with error: {e:#}");
            }
        });
    }
}

async fn handle(
    registry: Arc<Registry>,
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
) -> Result<()> {
    let mut tls = acceptor.accept(tcp).await?;
    let mut buf = Vec::new();
    let request = loop {
        let mut chunk = [0u8; 1024];
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before a complete request");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_REQUEST {
            bail!("request too large");
        }
        if let Some(request) = Request::parse(&buf)? {
            break request;
        }
    };
    let response = registry.route(&request);
    tls.write_all(&response.bytes).await?;
    tls.shutdown().await?;
    Ok(())
}

/// A registry running on a local port, for tests and the binary.
pub struct RunningRegistry {
    pub registry: Arc<Registry>,
    pub certs: Certs,
    pub addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl RunningRegistry {
    pub async fn start(layout: Layout, fixtures: Fixtures, bind: &str) -> Result<Self> {
        Self::start_with_phases(layout, PhaseLayouts::default(), fixtures, bind).await
    }

    /// A registry that also serves the Apply and Settle sources. Every layout must name the same
    /// server, which holds one certificate.
    pub async fn start_with_phases(
        layout: Layout,
        phases: PhaseLayouts,
        fixtures: Fixtures,
        bind: &str,
    ) -> Result<Self> {
        for other in phases.income.iter().chain(&phases.tenancy) {
            if other.server_name != layout.server_name {
                bail!(
                    "layout {} names server {}, the registry is {}",
                    other.id,
                    other.server_name,
                    layout.server_name
                );
            }
        }
        let certs = Certs::generate(&layout.server_name)?;
        let tls = tls_config(&certs)?;
        let registry = Arc::new(Registry::with_phases(layout, phases, fixtures)?);
        let listener = TcpListener::bind(bind).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(serve(registry.clone(), listener, tls));
        Ok(Self {
            registry,
            certs,
            addr,
            task,
        })
    }
}

impl Drop for RunningRegistry {
    fn drop(&mut self) {
        self.task.abort();
    }
}
