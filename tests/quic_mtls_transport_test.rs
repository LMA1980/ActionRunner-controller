// SPDX-License-Identifier: AGPL-3.0-only
//! End-to-end integration test verifying HTTP/3 (QUIC / h3) control-plane transport,
//! Step-CA mTLS validation, and Alt-Svc advertisement (#151–#154).

use bytes::Buf;
use futures_util::future;
use http::{Request, StatusCode};
use mu_ci_controller::app::create_router;
use mu_ci_controller::cluster::ClusterRegistry;
use mu_ci_controller::config::Config;
use mu_ci_controller::console::{ConsoleConfig, ConsoleState};
use mu_ci_controller::job::JobStore;
use mu_ci_controller::quic::{
    bind_quic_endpoint, make_quic_client_config, make_quic_server_config, run_quic_server,
};
use mu_ci_controller::tls::build_mtls_server_config;
use mu_ci_controller::webhook::AppState;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

struct TestPki {
    ca_der: Vec<u8>,
    server_cert_der: Vec<u8>,
    server_key_pkcs8: Vec<u8>,
    client_cert_der: Vec<u8>,
    client_key_pkcs8: Vec<u8>,
}

fn generate_test_pki() -> TestPki {
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::new(vec!["ca.ci.internal".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Step-CA Local Root CA");
    ca_params.distinguished_name = ca_dn;
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let srv_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut srv_params = CertificateParams::new(vec![
        "controller.ci.internal".to_string(),
        "localhost".to_string(),
    ])
    .unwrap();
    let mut srv_dn = DistinguishedName::new();
    srv_dn.push(DnType::CommonName, "controller.ci.internal");
    srv_params.distinguished_name = srv_dn;
    let srv_cert = srv_params.signed_by(&srv_key, &issuer).unwrap();

    let cli_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut cli_params = CertificateParams::new(vec!["worker-1.ci.internal".to_string()]).unwrap();
    let mut cli_dn = DistinguishedName::new();
    cli_dn.push(DnType::CommonName, "worker-1.ci.internal");
    cli_params.distinguished_name = cli_dn;
    let cli_cert = cli_params.signed_by(&cli_key, &issuer).unwrap();

    TestPki {
        ca_der: ca_cert.der().to_vec(),
        server_cert_der: srv_cert.der().to_vec(),
        server_key_pkcs8: srv_key.serialize_der(),
        client_cert_der: cli_cert.der().to_vec(),
        client_key_pkcs8: cli_key.serialize_der(),
    }
}

fn make_test_state(workspace: std::path::PathBuf, alt_svc_port: Option<u16>) -> Arc<AppState> {
    let (tx, _rx) = tokio::sync::mpsc::channel(32);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);

    let config = Config {
        bind_addr: "127.0.0.1:0".to_string(),
        workspace_dir: workspace,
        allowed_repositories: vec!["LMA1980/*".to_string()],
        allowed_actors: vec!["*".to_string()],
        allow_fork_prs: false,
        allowed_pr_authors: vec!["OWNER".to_string()],
        log_api_key: None,
        webhook_secret: None,
        cluster_token: "test_token".to_string(),
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 2,
        github_token: None,
        node_id: "node-a".to_string(),
        quic_alt_svc_port: alt_svc_port,
        quic_alt_svc_max_age: Some(86400),
        ..Config::default()
    };

    let job_store = JobStore::from_config(100, &config);
    let cluster = ClusterRegistry::new();
    let console = ConsoleState::new(ConsoleConfig::from_config(&config));

    Arc::new(AppState {
        config,
        job_store,
        cluster,
        tx,
        log_broadcaster,
        console,
    })
}

#[tokio::test]
async fn test_alt_svc_header_advertised_on_tcp_when_quic_configured() {
    let ws_dir = tempdir().unwrap();
    let state = make_test_state(ws_dir.path().to_path_buf(), Some(8443));
    let app = create_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://{}/health", local_addr))
        .send()
        .await
        .expect("TCP request to /health must succeed");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let alt_svc = resp
        .headers()
        .get("alt-svc")
        .expect("Alt-Svc header must be present on TCP responses when QUIC is configured");
    assert_eq!(alt_svc.to_str().unwrap(), "h3=\":8443\"; ma=86400");

    server_handle.abort();
}

#[tokio::test]
async fn test_quic_http3_health_probe_with_valid_mtls() {
    let pki = generate_test_pki();
    let ws_dir = tempdir().unwrap();
    let state = make_test_state(ws_dir.path().to_path_buf(), None);
    let app = create_router(state);

    // Build Server TLS & QUIC config
    let mut server_roots = RootCertStore::empty();
    server_roots
        .add(CertificateDer::from(pki.ca_der.clone()))
        .unwrap();

    let server_cert_chain = vec![CertificateDer::from(pki.server_cert_der.clone())];
    let server_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.server_key_pkcs8.clone()));

    let server_tls = build_mtls_server_config(server_cert_chain, server_key, server_roots).unwrap();
    let quic_server_cfg = make_quic_server_config(server_tls).unwrap();

    let quic_endpoint =
        bind_quic_endpoint("127.0.0.1:0".parse().unwrap(), quic_server_cfg).unwrap();
    let quic_server_addr = quic_endpoint.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let _ = run_quic_server(quic_endpoint, app).await;
    });

    // Build Client TLS & QUIC config with mTLS client auth
    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(CertificateDer::from(pki.ca_der.clone()))
        .unwrap();

    let client_cert_chain = vec![CertificateDer::from(pki.client_cert_der.clone())];
    let client_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.client_key_pkcs8.clone()));

    let quic_client_cfg =
        make_quic_client_config(client_cert_chain, client_key, client_roots).unwrap();

    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(quic_client_cfg);

    // Connect to QUIC server using domain name verified by Step-CA PKI
    let connecting = client_endpoint
        .connect(quic_server_addr, "controller.ci.internal")
        .expect("QUIC connect initiation");
    let quinn_conn = connecting.await.expect("QUIC connection established");

    let h3_quinn_conn = h3_quinn::Connection::new(quinn_conn);
    let (mut driver, mut send_request) = h3::client::builder()
        .build::<_, _, bytes::Bytes>(h3_quinn_conn)
        .await
        .expect("HTTP/3 handshake");

    let drive_task = tokio::spawn(async move {
        let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // Send HTTP/3 GET /health request
    let req = Request::builder()
        .method(http::Method::GET)
        .uri("https://controller.ci.internal/health")
        .header(http::header::HOST, "controller.ci.internal")
        .body(())
        .unwrap();

    let mut req_stream = send_request
        .send_request(req)
        .await
        .expect("send HTTP/3 request");
    req_stream.finish().await.expect("finish HTTP/3 request");

    let resp = req_stream
        .recv_response()
        .await
        .expect("receive HTTP/3 response");
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body_bytes = Vec::new();
    while let Some(chunk) = req_stream.recv_data().await.expect("recv body chunk") {
        body_bytes.extend_from_slice(chunk.chunk());
    }

    let body_str = String::from_utf8(body_bytes).expect("UTF-8 body");
    assert!(
        body_str.contains("\"status\":\"ok\"") || body_str.contains("\"status\": \"ok\""),
        "Body must contain status ok: {}",
        body_str
    );
    assert!(
        body_str.contains("ActionRunner-rs"),
        "Body must identify ActionRunner-rs service: {}",
        body_str
    );

    drive_task.abort();
    server_handle.abort();
}

#[tokio::test]
async fn test_quic_http3_rejects_untrusted_client_cert() {
    let pki = generate_test_pki();
    let ws_dir = tempdir().unwrap();
    let state = make_test_state(ws_dir.path().to_path_buf(), None);
    let app = create_router(state);

    // Server expects clients signed by pki.ca_der
    let mut server_roots = RootCertStore::empty();
    server_roots
        .add(CertificateDer::from(pki.ca_der.clone()))
        .unwrap();

    let server_cert_chain = vec![CertificateDer::from(pki.server_cert_der.clone())];
    let server_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.server_key_pkcs8.clone()));

    let server_tls = build_mtls_server_config(server_cert_chain, server_key, server_roots).unwrap();
    let quic_server_cfg = make_quic_server_config(server_tls).unwrap();

    let quic_endpoint =
        bind_quic_endpoint("127.0.0.1:0".parse().unwrap(), quic_server_cfg).unwrap();
    let quic_server_addr = quic_endpoint.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let _ = run_quic_server(quic_endpoint, app).await;
    });

    // Create an independent rogue CA that mimics the issuer DN but with an untrusted key
    let rogue_ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut rogue_ca_params = CertificateParams::new(vec!["ca.ci.internal".to_string()]).unwrap();
    rogue_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut rogue_ca_dn = DistinguishedName::new();
    rogue_ca_dn.push(DnType::CommonName, "Step-CA Local Root CA");
    rogue_ca_params.distinguished_name = rogue_ca_dn;
    let _rogue_ca_cert = rogue_ca_params.self_signed(&rogue_ca_key).unwrap();
    let rogue_issuer = Issuer::from_params(&rogue_ca_params, &rogue_ca_key);

    let rogue_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut rogue_params =
        CertificateParams::new(vec!["worker-attacker.ci.internal".to_string()]).unwrap();
    let mut rogue_dn = DistinguishedName::new();
    rogue_dn.push(DnType::CommonName, "worker-attacker.ci.internal");
    rogue_params.distinguished_name = rogue_dn;
    let rogue_cert = rogue_params.signed_by(&rogue_key, &rogue_issuer).unwrap();

    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(CertificateDer::from(pki.ca_der.clone()))
        .unwrap();

    let rogue_client_cert = vec![CertificateDer::from(rogue_cert.der().to_vec())];
    let rogue_client_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(rogue_key.serialize_der()));

    let quic_client_cfg =
        make_quic_client_config(rogue_client_cert, rogue_client_key, client_roots).unwrap();

    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(quic_client_cfg);

    // Connecting with untrusted client certificate must fail during handshake
    let connecting = client_endpoint
        .connect(quic_server_addr, "controller.ci.internal")
        .expect("QUIC connect call");

    let res = connecting.await;
    match res {
        Ok(conn) => {
            let h3_conn = h3_quinn::Connection::new(conn);
            if let Ok((mut driver, mut send_req)) = h3::client::builder()
                .build::<_, _, bytes::Bytes>(h3_conn)
                .await
            {
                let drive_task = tokio::spawn(async move {
                    let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
                });
                let req = Request::builder()
                    .method(http::Method::GET)
                    .uri("https://controller.ci.internal/health")
                    .header(http::header::HOST, "controller.ci.internal")
                    .body(())
                    .unwrap();
                if let Ok(mut stream) = send_req.send_request(req).await {
                    let _ = stream.finish().await;
                    let resp_res = stream.recv_response().await;
                    assert!(
                        resp_res.is_err(),
                        "Untrusted client response must be rejected by mTLS verification"
                    );
                }
                drive_task.abort();
            }
        }
        Err(_) => {
            // Handshake failed immediately at transport layer as expected
        }
    }

    server_handle.abort();
}
