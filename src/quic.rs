// SPDX-License-Identifier: AGPL-3.0-only
//! Dual-stack HTTP/3 over QUIC transport implementation for mu-ci-controller.
//! Supports ALPN `h3`, step-ca mTLS client validation, and Alt-Svc advertisement.

use axum::Router;
use bytes::Buf;
use http::{HeaderValue, Response};
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tower::ServiceExt;

#[derive(Debug, Error)]
pub enum QuicError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Rustls error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("Quinn crypto error: {0}")]
    QuinnCrypto(String),
    #[error("Quinn connection error: {0}")]
    QuinnConnection(#[from] quinn::ConnectionError),
    #[error("H3 connection error: {0}")]
    H3Connection(#[from] h3::error::ConnectionError),
    #[error("H3 stream error: {0}")]
    H3Stream(#[from] h3::error::StreamError),
    #[error("Axum body error: {0}")]
    Body(String),
}

/// Alt-Svc advertisement configuration for HTTP/3 over QUIC.
#[derive(Debug, Clone)]
pub struct AltSvcConfig {
    pub port: u16,
    pub max_age_secs: u64,
}

impl AltSvcConfig {
    #[must_use]
    pub fn new(port: u16) -> Self {
        Self {
            port,
            max_age_secs: 86400,
        }
    }

    #[must_use]
    pub fn with_max_age(mut self, max_age_secs: u64) -> Self {
        self.max_age_secs = max_age_secs;
        self
    }

    #[must_use]
    pub fn header_value(&self) -> HeaderValue {
        HeaderValue::from_str(&format!("h3=\":{}\"; ma={}", self.port, self.max_age_secs))
            .expect("Valid Alt-Svc header value")
    }
}

/// Layer an Axum `Router` to append the `Alt-Svc` header on all HTTP responses.
pub fn attach_alt_svc_header(router: Router, alt_svc: AltSvcConfig) -> Router {
    let val = alt_svc.header_value();
    router.layer(axum::middleware::map_response(
        move |mut resp: Response<axum::body::Body>| {
            let v = val.clone();
            async move {
                resp.headers_mut().insert(http::header::ALT_SVC, v);
                resp
            }
        },
    ))
}

/// Configure Quinn server using a rustls ServerConfig, pinning ALPN to `h3`.
pub fn make_quic_server_config(
    mut rustls_config: rustls::ServerConfig,
) -> Result<quinn::ServerConfig, QuicError> {
    rustls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .map_err(|e| QuicError::QuinnCrypto(e.to_string()))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(30)
            .try_into()
            .expect("30s is valid IdleTimeout"),
    ));
    server_config.transport_config(Arc::new(transport_config));
    Ok(server_config)
}

/// Configure Quinn client with mTLS certificates and root CA store, pinning ALPN to `h3`.
pub fn make_quic_client_config(
    client_cert: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    root_cert_store: RootCertStore,
) -> Result<quinn::ClientConfig, QuicError> {
    let mut rustls_client = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_client_auth_cert(client_cert, client_key)
        .map_err(QuicError::Rustls)?;
    rustls_client.alpn_protocols = vec![b"h3".to_vec()];
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client)
        .map_err(|e| QuicError::QuinnCrypto(e.to_string()))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_client)))
}

/// Bind a UDP socket and start a Quinn endpoint for HTTP/3.
pub fn bind_quic_endpoint(
    addr: SocketAddr,
    server_config: quinn::ServerConfig,
) -> Result<quinn::Endpoint, QuicError> {
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    Ok(endpoint)
}

/// Run the background HTTP/3 server loop accepting QUIC connections and dispatching to Axum Router.
pub async fn run_quic_server(endpoint: quinn::Endpoint, router: Router) -> Result<(), QuicError> {
    while let Some(incoming) = endpoint.accept().await {
        let router = router.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let h3_conn = h3_quinn::Connection::new(conn);
                    if let Err(e) = serve_h3_connection(h3_conn, router).await {
                        tracing::debug!("HTTP/3 connection closed: {e}");
                    }
                }
                Err(e) => {
                    tracing::warn!("QUIC incoming connection handshake failed: {e}");
                }
            }
        });
    }
    Ok(())
}

/// Handle a single HTTP/3 connection's requests.
pub async fn serve_h3_connection(
    h3_conn: h3_quinn::Connection,
    router: Router,
) -> Result<(), QuicError> {
    let mut h3_server = h3::server::builder().build(h3_conn).await?;
    while let Some(resolver) = h3_server.accept().await? {
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_h3_request(resolver, router).await {
                tracing::debug!("Error processing HTTP/3 request: {e}");
            }
        });
    }
    Ok(())
}

async fn handle_h3_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, bytes::Bytes>,
    router: Router,
) -> Result<(), QuicError> {
    let (req, mut stream) = resolver.resolve_request().await?;

    let mut body_bytes = bytes::BytesMut::new();
    while let Some(chunk) = stream.recv_data().await? {
        body_bytes.extend_from_slice(chunk.chunk());
    }

    let (parts, ()) = req.into_parts();
    let axum_req = http::Request::from_parts(parts, axum::body::Body::from(body_bytes.freeze()));

    let axum_resp = router
        .oneshot(axum_req)
        .await
        .unwrap_or_else(|e| match e {});

    let (resp_parts, body) = axum_resp.into_parts();
    let h3_resp = http::Response::from_parts(resp_parts, ());
    stream.send_response(h3_resp).await?;

    let resp_bytes = axum::body::to_bytes(body, 16 * 1024 * 1024)
        .await
        .map_err(|e| QuicError::Body(e.to_string()))?;
    if !resp_bytes.is_empty() {
        stream.send_data(resp_bytes).await?;
    }
    stream.finish().await?;
    Ok(())
}
