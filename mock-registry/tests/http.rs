//! Mock registry over real TLS connections: protocol and suite restriction, authentication, and the
//! fixed layout of every title response.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use mock_registry::{Fixtures, PhaseLayouts, RunningRegistry};
use pprev_types::{Layout, RecordLayout};
use rustls::crypto::ring as ring_provider;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

fn workspace_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(rel)
}

fn layout() -> Layout {
    Layout::load(workspace_path("policies/layouts/title-v1.json")).unwrap()
}

fn fixtures() -> Fixtures {
    Fixtures::load(workspace_path("mock-registry/fixtures/records.json")).unwrap()
}

async fn start() -> RunningRegistry {
    RunningRegistry::start(layout(), fixtures(), "127.0.0.1:0")
        .await
        .unwrap()
}

fn client_config(
    ca_der: &[u8],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec())).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(ring_provider::default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Sends one raw HTTP request and returns the full response with the negotiated TLS parameters.
async fn exchange(
    addr: SocketAddr,
    config: Arc<rustls::ClientConfig>,
    request: &str,
) -> std::io::Result<(Vec<u8>, rustls::ProtocolVersion, rustls::CipherSuite)> {
    let tcp = TcpStream::connect(addr).await?;
    let mut tls = TlsConnector::from(config)
        .connect(ServerName::try_from("registry.pprev.test").unwrap(), tcp)
        .await?;
    let (_, conn) = tls.get_ref();
    let version = conn.protocol_version().expect("version");
    let suite = conn.negotiated_cipher_suite().expect("suite").suite();
    tls.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    Ok((response, version, suite))
}

async fn login(registry: &RunningRegistry, account: &str, password: &str) -> String {
    let body = serde_json::json!({ "account": account, "password": password }).to_string();
    let request = format!(
        "POST /login HTTP/1.1\r\nHost: registry.pprev.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let config = client_config(&registry.certs.ca_der, &[&rustls::version::TLS12]);
    let (response, _, _) = exchange(registry.addr, config, &request).await.unwrap();
    let head_end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let json: serde_json::Value = serde_json::from_slice(&response[head_end + 4..]).unwrap();
    json["token"].as_str().unwrap().to_string()
}

fn title_request(property_id: &str, token: Option<&str>) -> String {
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    format!(
        "GET /title/{property_id} HTTP/1.1\r\nHost: registry.pprev.test\r\n{auth}Connection: close\r\n\r\n"
    )
}

#[tokio::test]
async fn serves_tls12_with_the_mpc_suite_only() {
    let registry = start().await;
    let config = client_config(
        &registry.certs.ca_der,
        &[&rustls::version::TLS12, &rustls::version::TLS13],
    );
    let (_, version, suite) = exchange(
        registry.addr,
        config,
        &title_request("TR-06-CANKAYA-000123", None),
    )
    .await
    .unwrap();
    assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);
    assert_eq!(
        suite,
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    );
}

#[tokio::test]
async fn rejects_a_tls13_only_client() {
    let registry = start().await;
    let config = client_config(&registry.certs.ca_der, &[&rustls::version::TLS13]);
    assert!(
        exchange(
            registry.addr,
            config,
            &title_request("TR-06-CANKAYA-000123", None)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn login_rejects_wrong_credentials() {
    let registry = start().await;
    let body = r#"{"account":"ACC-000000000001","password":"wrong"}"#;
    let request = format!(
        "POST /login HTTP/1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let config = client_config(&registry.certs.ca_der, &[&rustls::version::TLS12]);
    let (response, _, _) = exchange(registry.addr, config, &request).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 401 "));
}

#[tokio::test]
async fn title_requires_a_valid_token() {
    let registry = start().await;
    let config = client_config(&registry.certs.ca_der, &[&rustls::version::TLS12]);
    let (none, _, _) = exchange(
        registry.addr,
        config.clone(),
        &title_request("TR-06-CANKAYA-000123", None),
    )
    .await
    .unwrap();
    assert!(none.starts_with(b"HTTP/1.1 401 "));
    let (bad, _, _) = exchange(
        registry.addr,
        config,
        &title_request("TR-06-CANKAYA-000123", Some(&"0".repeat(64))),
    )
    .await
    .unwrap();
    assert!(bad.starts_with(b"HTTP/1.1 401 "));
    assert!(registry.registry.sent_log().is_empty());
}

#[tokio::test]
async fn unknown_property_is_not_found() {
    let registry = start().await;
    let token = login(&registry, "ACC-000000000001", "owner-one").await;
    let config = client_config(&registry.certs.ca_der, &[&rustls::version::TLS12]);
    let (response, _, _) = exchange(
        registry.addr,
        config,
        &title_request("TR-00-NOWHERE-000000", Some(&token)),
    )
    .await
    .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 404 "));
}

#[tokio::test]
async fn every_title_response_follows_the_layout() {
    let registry = start().await;
    let layout = layout();
    let ranges = layout.ranges().unwrap();
    let fixtures = fixtures();
    let config = client_config(&registry.certs.ca_der, &[&rustls::version::TLS12]);
    let mut expected_log = Vec::new();
    for account in &fixtures.accounts {
        let token = login(&registry, &account.id, &account.password).await;
        for record in &fixtures.records {
            let (response, _, _) = exchange(
                registry.addr,
                config.clone(),
                &title_request(&record.property_id, Some(&token)),
            )
            .await
            .unwrap();
            let expected = layout.render_response(&account.id, record).unwrap();
            assert_eq!(
                response, expected.bytes,
                "{} viewing {}",
                account.id, record.property_id
            );
            assert_eq!(response.len(), ranges.len);
            assert_eq!(&response[ranges.account.clone()], account.id.as_bytes());
            assert_eq!(
                &response[ranges.property_id.clone()],
                record.property_id.as_bytes()
            );
            expected_log.push(expected.bytes);
        }
    }
    assert_eq!(registry.registry.sent_log(), expected_log);
}

// Apply and Settle sources -------------------------------------------------------------------

fn record_layout(name: &str) -> RecordLayout {
    RecordLayout::load(workspace_path(&format!("policies/layouts/{name}.json"))).unwrap()
}

async fn start_with_phases() -> RunningRegistry {
    RunningRegistry::start_with_phases(
        layout(),
        PhaseLayouts {
            income: Some(record_layout("income-v1")),
            tenancy: Some(record_layout("tenancy-v1")),
        },
        fixtures(),
        "127.0.0.1:0",
    )
    .await
    .unwrap()
}

async fn get(registry: &RunningRegistry, target: &str, token: Option<&str>) -> Vec<u8> {
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: registry.pprev.test\r\n{auth}Connection: close\r\n\r\n"
    );
    let config = client_config(&registry.certs.ca_der, &[&rustls::version::TLS12]);
    exchange(registry.addr, config, &request).await.unwrap().0
}

#[tokio::test]
async fn income_is_the_record_of_the_logged_in_account() {
    let registry = start_with_phases().await;
    let income = record_layout("income-v1");
    assert!(
        get(&registry, "/income", None)
            .await
            .starts_with(b"HTTP/1.1 401 ")
    );
    let token = login(&registry, "ACC-000000000003", "tenant").await;
    let response = get(&registry, "/income", Some(&token)).await;
    let expected = income
        .render_response("ACC-000000000003", &["03500000000000000000"])
        .unwrap();
    assert_eq!(response, expected.bytes);
    // An account without an eligibility record.
    let token = login(&registry, "ACC-000000000001", "owner-one").await;
    assert!(
        get(&registry, "/income", Some(&token))
            .await
            .starts_with(b"HTTP/1.1 404 ")
    );
}

#[tokio::test]
async fn tenancy_notations_follow_the_layout_for_any_account() {
    let registry = start_with_phases().await;
    let tenancy = record_layout("tenancy-v1");
    let token = login(&registry, "ACC-000000000001", "owner-one").await;
    let response = get(&registry, "/tenancy/N-0003", Some(&token)).await;
    let expected = tenancy
        .render_response(
            "ACC-000000000001",
            &["TR-34-KADIKOY-004567", "ACC-000000000003", "2026-10-21"],
        )
        .unwrap();
    assert_eq!(response, expected.bytes);
    assert_eq!(response.len(), tenancy.ranges().unwrap().len);
    assert!(
        get(&registry, "/tenancy/N-9999", Some(&token))
            .await
            .starts_with(b"HTTP/1.1 404 ")
    );
    assert!(
        get(&registry, "/tenancy/N-0001", None)
            .await
            .starts_with(b"HTTP/1.1 401 ")
    );
    // The title route is unchanged.
    let title = get(&registry, "/title/TR-06-CANKAYA-000123", Some(&token)).await;
    assert!(title.starts_with(b"HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn without_phase_layouts_the_phase_routes_are_not_served() {
    let registry = start().await;
    let token = login(&registry, "ACC-000000000003", "tenant").await;
    assert!(
        get(&registry, "/income", Some(&token))
            .await
            .starts_with(b"HTTP/1.1 404 ")
    );
    assert!(
        get(&registry, "/tenancy/N-0001", Some(&token))
            .await
            .starts_with(b"HTTP/1.1 404 ")
    );
}

#[tokio::test]
async fn phase_layouts_must_name_the_registry_server() {
    let mut other = record_layout("income-v1");
    other.server_name = "payroll.pprev.test".into();
    let result = RunningRegistry::start_with_phases(
        layout(),
        PhaseLayouts {
            income: Some(other),
            tenancy: None,
        },
        fixtures(),
        "127.0.0.1:0",
    )
    .await;
    assert!(result.is_err());
}
