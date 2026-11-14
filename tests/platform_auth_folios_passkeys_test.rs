//! End-to-end integration tests for Platform Auth, Canonical Policy Folios, RBAC Roles,
//! Persistent WebAuthn Passkeys (1Password + FIDO2 counters), RoleLeases, `__Host-mu_elevated`,
//! Last-Admin Lockout Guard, Break-Glass Reset, and `GET /api/internal/auth/snapshot` (`#172`–`#180`).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use mu_ci_controller::app::create_router;
use mu_ci_controller::auth::execute_reset_passkeys_cli;
use mu_ci_controller::cluster::ClusterRegistry;
use mu_ci_controller::config::Config;
use mu_ci_controller::console::{ConsoleConfig, ConsoleState};
use mu_ci_controller::job::JobStore;
use mu_ci_controller::webhook::AppState;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde_cbor_2::Value as CborValue;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;
use webauthn_rs_core::proto::{
    AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

const API_KEY: &str = "platform-auth-api-key-test";
const PROXY_SECRET: &str = "trusted-proxy-secret-platform-test";
const INVITE_KEY: &str = "platform-auth-invite-hmac-key";
const CLUSTER_TOKEN: &str = "platform-auth-cluster-token";

async fn make_auth_test_state() -> (Arc<AppState>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("create temp workspace");
    let mut cfg = Config {
        bind_addr: "127.0.0.1:0".to_string(),
        workspace_dir: tmp.path().to_path_buf(),
        allowed_repositories: vec!["LMA1980/*".to_string()],
        allowed_actors: vec!["*".to_string()],
        allow_fork_prs: false,
        allowed_pr_authors: vec!["OWNER".to_string()],
        log_api_key: Some(API_KEY.to_string()),
        webhook_secret: None,
        cluster_token: CLUSTER_TOKEN.to_string(),
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 2,
        github_token: None,
        proxy_secret: Some(PROXY_SECRET.to_string()),
        invite_signing_key: Some(INVITE_KEY.to_string()),
        bootstrap_admins: vec!["LMA1980".to_string()],
        webauthn_rp_id: "console.example.org".to_string(),
        webauthn_rp_name: "MuConsole Platform".to_string(),
        webauthn_rp_origin: "https://console.example.org".to_string(),
        ..Config::default()
    };
    cfg.auth_state_file = Some(tmp.path().join("logs").join("platform_auth.json"));

    let job_store = JobStore::from_config(100, &cfg);
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);
    let console = ConsoleState::new(ConsoleConfig::default());
    let state = Arc::new(AppState {
        config: cfg,
        job_store,
        cluster: ClusterRegistry::new(),
        tx,
        log_broadcaster,
        console,
    });
    (state, tmp)
}

async fn req_full(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value, Option<String>, Option<String>) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req_body = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let resp = app
        .clone()
        .oneshot(builder.body(req_body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let cookie = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|raw| {
            let pair = raw.split(';').next()?.trim();
            pair.starts_with("__Host-mu_elevated=")
                .then(|| pair.to_string())
        });
    let etag = resp
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json_val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json_val, cookie, etag)
}

struct VirtualAuthenticator {
    rp_id: String,
    origin: String,
    cred_id: Vec<u8>,
    signing_key: P256SigningKey,
    pub_x: Vec<u8>,
    pub_y: Vec<u8>,
    backup_eligible: bool,
    backup_state: bool,
    sign_count: u32,
}

impl VirtualAuthenticator {
    fn new_synced(seed: u8, cred_id: &[u8]) -> Self {
        Self::with_flags(seed, cred_id, true, true, 0)
    }

    fn new_fido2(seed: u8, cred_id: &[u8], initial_count: u32) -> Self {
        Self::with_flags(seed, cred_id, false, false, initial_count)
    }

    fn with_flags(
        seed: u8,
        cred_id: &[u8],
        backup_eligible: bool,
        backup_state: bool,
        sign_count: u32,
    ) -> Self {
        let mut secret = [0u8; 32];
        for (i, byte) in secret.iter_mut().enumerate() {
            *byte = seed.wrapping_add((i as u8).wrapping_mul(29)).max(1);
        }
        let signing_key = P256SigningKey::from_slice(&secret).expect("valid P-256 key");
        let point = signing_key.verifying_key().to_sec1_point(false);
        Self {
            rp_id: "console.example.org".to_string(),
            origin: "https://console.example.org".to_string(),
            cred_id: cred_id.to_vec(),
            signing_key,
            pub_x: point.x().expect("x").to_vec(),
            pub_y: point.y().expect("y").to_vec(),
            backup_eligible,
            backup_state,
            sign_count,
        }
    }

    fn register_response(&self, challenge: &[u8]) -> RegisterPublicKeyCredential {
        let mut flags: u8 = 0x01 | 0x04 | 0x40;
        if self.backup_eligible {
            flags |= 0x08;
        }
        if self.backup_state {
            flags |= 0x10;
        }

        let rp_id_hash = Sha256::digest(self.rp_id.as_bytes());
        let mut cose = BTreeMap::new();
        cose.insert(CborValue::Integer(1), CborValue::Integer(2));
        cose.insert(CborValue::Integer(3), CborValue::Integer(-7));
        cose.insert(CborValue::Integer(-1), CborValue::Integer(1));
        cose.insert(CborValue::Integer(-2), CborValue::Bytes(self.pub_x.clone()));
        cose.insert(CborValue::Integer(-3), CborValue::Bytes(self.pub_y.clone()));
        let cose_bytes = serde_cbor_2::to_vec(&CborValue::Map(cose)).unwrap();

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&self.sign_count.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.cred_id);
        auth_data.extend_from_slice(&cose_bytes);

        let mut att_obj = BTreeMap::new();
        att_obj.insert(
            CborValue::Text("fmt".into()),
            CborValue::Text("none".into()),
        );
        att_obj.insert(
            CborValue::Text("attStmt".into()),
            CborValue::Map(BTreeMap::new()),
        );
        att_obj.insert(
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        );
        let attestation_object = serde_cbor_2::to_vec(&CborValue::Map(att_obj)).unwrap();

        let client_data_json = serde_json::to_vec(&json!({
            "type": "webauthn.create",
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "origin": self.origin,
            "crossOrigin": false,
        }))
        .unwrap();

        RegisterPublicKeyCredential {
            id: URL_SAFE_NO_PAD.encode(&self.cred_id),
            raw_id: self.cred_id.clone(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object,
                client_data_json,
                transports: None,
            },
            type_: "public-key".to_string(),
            extensions: Default::default(),
        }
    }

    fn assert_response(&self, challenge: &[u8], counter: u32) -> PublicKeyCredential {
        let mut flags: u8 = 0x01 | 0x04;
        if self.backup_eligible {
            flags |= 0x08;
        }
        if self.backup_state {
            flags |= 0x10;
        }

        let rp_id_hash = Sha256::digest(self.rp_id.as_bytes());
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&counter.to_be_bytes());

        let client_data_json = serde_json::to_vec(&json!({
            "type": "webauthn.get",
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "origin": self.origin,
            "crossOrigin": false,
        }))
        .unwrap();
        let client_hash = Sha256::digest(&client_data_json);
        let mut signed = Vec::with_capacity(auth_data.len() + client_hash.len());
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(&client_hash);

        let sig: P256Signature = self.signing_key.sign(&signed);
        PublicKeyCredential {
            id: URL_SAFE_NO_PAD.encode(&self.cred_id),
            raw_id: self.cred_id.clone(),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: auth_data,
                client_data_json,
                signature: sig.to_der().as_ref().to_vec(),
                user_handle: None,
            },
            extensions: Default::default(),
            type_: "public-key".to_string(),
        }
    }
}

async fn enroll_passkey(
    app: &Router,
    hdrs: &[(&str, &str)],
    auth: &VirtualAuthenticator,
    label: &str,
    step_up_proof_id: Option<&str>,
) -> String {
    let start_body = match step_up_proof_id {
        Some(pid) => json!({ "label": label, "step_up_proof_id": pid }),
        None => json!({ "label": label }),
    };
    let (st, start_j, _, _) = req_full(
        app,
        "POST",
        "/api/auth/passkeys/register/start",
        hdrs,
        Some(start_body),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "register/start failed: {start_j}");

    // Ensure 1Password/Chrome compatibility flags are preserved cleanly.
    let pk = &start_j["options"]["publicKey"];
    assert_eq!(pk["attestation"], "none");
    assert!(
        pk["authenticatorSelection"]
            .get("authenticatorAttachment")
            .is_none()
            || pk["authenticatorSelection"]["authenticatorAttachment"].is_null(),
        "must not restrict authenticatorAttachment"
    );
    assert_eq!(
        pk["authenticatorSelection"]["userVerification"],
        "preferred"
    );

    let challenge_id = start_j["challenge_id"].as_str().unwrap().to_string();
    let challenge = URL_SAFE_NO_PAD
        .decode(pk["challenge"].as_str().unwrap())
        .unwrap();
    let cred = auth.register_response(&challenge);

    let (st, fin_j, _, _) = req_full(
        app,
        "POST",
        "/api/auth/passkeys/register/finish",
        hdrs,
        Some(json!({
            "challenge_id": challenge_id,
            "credential": cred,
            "label": label,
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "register/finish failed: {fin_j}");
    fin_j["credential_id"].as_str().unwrap().to_string()
}

async fn assert_passkey_manage(
    app: &Router,
    hdrs: &[(&str, &str)],
    auth: &VirtualAuthenticator,
    counter: u32,
) -> (StatusCode, Value) {
    let (st, start_j, _, _) = req_full(
        app,
        "POST",
        "/api/auth/passkeys/assert/start",
        hdrs,
        Some(json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let challenge_id = start_j["challenge_id"].as_str().unwrap().to_string();
    let challenge = URL_SAFE_NO_PAD
        .decode(
            start_j["options"]["publicKey"]["challenge"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let cred = auth.assert_response(&challenge, counter);
    let (st, fin_j, _, _) = req_full(
        app,
        "POST",
        "/api/auth/passkeys/assert/finish",
        hdrs,
        Some(json!({
            "challenge_id": challenge_id,
            "credential": cred,
        })),
    )
    .await;
    (st, fin_j)
}

async fn elevate_role(
    app: &Router,
    hdrs: &[(&str, &str)],
    auth: &VirtualAuthenticator,
    counter: u32,
    role_id: &str,
) -> (StatusCode, Value, Option<String>) {
    let (st, start_j, _, _) = req_full(
        app,
        "POST",
        "/api/auth/elevate/start",
        hdrs,
        Some(json!({ "role_id": role_id })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let challenge_id = start_j["challenge_id"].as_str().unwrap().to_string();
    let challenge = URL_SAFE_NO_PAD
        .decode(
            start_j["options"]["publicKey"]["challenge"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let cred = auth.assert_response(&challenge, counter);
    let (st, fin_j, cookie, _) = req_full(
        app,
        "POST",
        "/api/auth/elevate/finish",
        hdrs,
        Some(json!({
            "challenge_id": challenge_id,
            "credential": cred,
            "role_id": role_id,
        })),
    )
    .await;
    (st, fin_j, cookie)
}

#[tokio::test]
async fn canonical_manifests_composite_folios_cycles_and_anonymous_lockdown() {
    let (state, _tmp) = make_auth_test_state().await;
    let app = create_router(state.clone());

    let admin_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
    ];
    let admin_auth = VirtualAuthenticator::new_synced(1, b"cred-admin-folios");
    enroll_passkey(&app, &admin_hdrs, &admin_auth, "Admin Passkey", None).await;
    let (st, _, cookie_opt) =
        elevate_role(&app, &admin_hdrs, &admin_auth, 0, "platform-admin").await;
    assert_eq!(st, StatusCode::OK);
    let admin_cookie = cookie_opt.unwrap();
    let elevated_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
        ("Cookie", admin_cookie.as_str()),
    ];

    // 1. Canonical manifests cover 8 subsystems and canonical folios are immutable (403 on overwrite/delete).
    let (st, folios_j, _, _) =
        req_full(&app, "GET", "/api/auth/folios", &elevated_hdrs, None).await;
    assert_eq!(st, StatusCode::OK);
    let folios = folios_j["folios"].as_array().unwrap();
    for canonical in [
        "folio:system:status",
        "folio:ci:anon-queue",
        "folio:cd:read",
        "folio:ab:read",
        "folio:reg:read",
        "folio:obs:logs",
        "folio:mr:read",
        "folio:platform:admin",
    ] {
        assert!(
            folios
                .iter()
                .any(|f| f["id"] == canonical && f["origin"] == "subsystem"),
            "missing canonical folio {canonical}"
        );
    }

    let (st_mod, _, _, _) = req_full(
        &app,
        "PUT",
        "/api/auth/folios/folio:platform:admin",
        &elevated_hdrs,
        Some(json!({
            "id": "folio:platform:admin",
            "display_name": "Tampered",
            "policies": []
        })),
    )
    .await;
    assert_eq!(st_mod, StatusCode::FORBIDDEN);

    let (st_in_use, _, _, _) = req_full(
        &app,
        "DELETE",
        "/api/auth/folios/folio:ci:operate",
        &elevated_hdrs,
        None,
    )
    .await;
    assert_eq!(st_in_use, StatusCode::CONFLICT);

    let (st_del, _, _, _) = req_full(
        &app,
        "DELETE",
        "/api/auth/folios/folio:ab:gate-logs",
        &elevated_hdrs,
        None,
    )
    .await;
    assert_eq!(st_del, StatusCode::FORBIDDEN);

    // 2. Create custom operator composite folios & reject DAG cycle (400 Bad Request).
    let (st_c1, c1_j, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/folios",
        &elevated_hdrs,
        Some(json!({
            "id": "folio:custom:ci-lead",
            "display_name": "Custom CI Lead",
            "description": "Composite CI lead access",
            "includes": ["folio:ci:operate"],
            "policies": ["ci:jobs.restart"]
        })),
    )
    .await;
    assert_eq!(st_c1, StatusCode::OK);
    assert_eq!(c1_j["origin"], "operator");

    let (st_c2, _, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/folios",
        &elevated_hdrs,
        Some(json!({
            "id": "folio:custom:cycle-b",
            "display_name": "Cycle Helper",
            "includes": ["folio:custom:ci-lead"],
            "policies": []
        })),
    )
    .await;
    assert_eq!(st_c2, StatusCode::OK);

    let (st_cycle, _, _, _) = req_full(
        &app,
        "PUT",
        "/api/auth/folios/folio:custom:ci-lead",
        &elevated_hdrs,
        Some(json!({
            "id": "folio:custom:ci-lead",
            "includes": ["folio:custom:cycle-b"],
            "policies": []
        })),
    )
    .await;
    assert_eq!(st_cycle, StatusCode::BAD_REQUEST);

    // 3. Before lockdown, anonymous caller can read /api/queue and /api/repos (public view).
    let (st_q0, _, _, _) = req_full(&app, "GET", "/api/queue", &[], None).await;
    assert_eq!(st_q0, StatusCode::OK);

    // 4. Setting anonymous = [] enables login-only lockdown: /api/queue and /api/repos return 401,
    //    while /api/health and /api/auth/session remain accessible.
    let (st_lock, lock_j, _, _) = req_full(
        &app,
        "PUT",
        "/api/auth/role-folio-index",
        &elevated_hdrs,
        Some(json!({ "anonymous": [] })),
    )
    .await;
    assert_eq!(st_lock, StatusCode::OK);
    assert_eq!(lock_j["anonymous_lockdown"], true);

    let (st_qlock, _, _, _) = req_full(&app, "GET", "/api/queue", &[], None).await;
    assert_eq!(st_qlock, StatusCode::UNAUTHORIZED);
    let (st_rlock, _, _, _) = req_full(&app, "GET", "/api/repos", &[], None).await;
    assert_eq!(st_rlock, StatusCode::UNAUTHORIZED);

    let (st_health, _, _, _) = req_full(&app, "GET", "/api/health", &[], None).await;
    assert_eq!(st_health, StatusCode::OK);
    let (st_sess, sess_anon, _, _) = req_full(&app, "GET", "/api/auth/session", &[], None).await;
    assert_eq!(st_sess, StatusCode::OK);
    assert_eq!(sess_anon["anonymous_login_only"], true);

    // 5. Invites reject privilege escalation via role/roles injection on both create and redeem.
    let (st_inv_bad, _, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/invites",
        &elevated_hdrs,
        Some(json!({ "role": "platform-admin", "note": "forbidden" })),
    )
    .await;
    assert_eq!(st_inv_bad, StatusCode::BAD_REQUEST);

    let (st_inv_ok, inv_ok, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/invites",
        &elevated_hdrs,
        Some(json!({ "note": "valid baseline" })),
    )
    .await;
    assert_eq!(st_inv_ok, StatusCode::CREATED);
    let tok = inv_ok["invite_token"].as_str().unwrap();

    let (st_red_bad, _, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/redeem",
        &[
            ("X-Proxy-Secret", PROXY_SECRET),
            ("X-Forwarded-User", "Invited-User"),
        ],
        Some(json!({ "invite_token": tok, "roles": ["platform-admin"] })),
    )
    .await;
    assert_eq!(st_red_bad, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn profile_preferences_case_insensitive_logins_and_last_admin_lockout_guard() {
    let (state, _tmp) = make_auth_test_state().await;
    let app = create_router(state.clone());

    // Authenticate with lowercase version of bootstrap admin "LMA1980" -> resolves original casing.
    let lma_lower_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "lma1980"),
    ];
    let admin_auth = VirtualAuthenticator::new_synced(2, b"cred-admin-guard");
    enroll_passkey(&app, &lma_lower_hdrs, &admin_auth, "Admin Passkey", None).await;

    let (st_prof0, prof0, _, _) =
        req_full(&app, "GET", "/api/auth/profile", &lma_lower_hdrs, None).await;
    assert_eq!(st_prof0, StatusCode::OK);
    assert_eq!(prof0["github_login"], "LMA1980");
    assert_eq!(prof0["preferences"]["skin"], "html");
    assert_eq!(prof0["preferences"]["font"], "Hurmit");

    let (st_upd, prof1, _, _) = req_full(
        &app,
        "PATCH",
        "/api/auth/profile",
        &lma_lower_hdrs,
        Some(json!({
            "display_name": "Lead Operator",
            "skin": "wireframe",
            "font": "OpenDyslexic"
        })),
    )
    .await;
    assert_eq!(st_upd, StatusCode::OK);
    assert_eq!(prof1["display_name"], "Lead Operator");
    assert_eq!(prof1["preferences"]["skin"], "wireframe");
    assert_eq!(prof1["preferences"]["font"], "OpenDyslexic");

    let (_, _, cookie_opt) =
        elevate_role(&app, &lma_lower_hdrs, &admin_auth, 0, "platform-admin").await;
    let cookie = cookie_opt.unwrap();
    let elevated_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
        ("Cookie", cookie.as_str()),
    ];

    // Invite & bind mixed-case user "Alice-Mixed", verify lowercase header preserves "Alice-Mixed".
    let (st_inv, inv_j, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/invites",
        &elevated_hdrs,
        Some(json!({ "note": "mixed case" })),
    )
    .await;
    assert_eq!(st_inv, StatusCode::CREATED);
    let (st_red, _, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/redeem",
        &[
            ("X-Proxy-Secret", PROXY_SECRET),
            ("X-Forwarded-User", "Alice-Mixed"),
        ],
        Some(json!({ "invite_token": inv_j["invite_token"] })),
    )
    .await;
    assert_eq!(st_red, StatusCode::OK);
    let (st_asess, asess, _, _) = req_full(
        &app,
        "GET",
        "/api/auth/session",
        &[
            ("X-Proxy-Secret", PROXY_SECRET),
            ("X-Forwarded-User", "alice-mixed"),
        ],
        None,
    )
    .await;
    assert_eq!(st_asess, StatusCode::OK);
    assert_eq!(asess["github_login"], "Alice-Mixed");

    // Last-admin lockout guard (409 Conflict) across all mutation surfaces:
    // a) Revoking final active admin user
    let (st_rev, _, _, _) = req_full(
        &app,
        "DELETE",
        "/api/auth/users/LMA1980",
        &elevated_hdrs,
        None,
    )
    .await;
    assert_eq!(st_rev, StatusCode::CONFLICT);

    // b) Demoting final admin off platform-admin
    let (st_demote, _, _, _) = req_full(
        &app,
        "PUT",
        "/api/auth/users/LMA1980/roles",
        &elevated_hdrs,
        Some(json!({ "bound_roles": ["operator"] })),
    )
    .await;
    assert_eq!(st_demote, StatusCode::CONFLICT);

    // c) Deleting platform-admin role
    let (st_delrole, _, _, _) = req_full(
        &app,
        "DELETE",
        "/api/auth/roles/platform-admin",
        &elevated_hdrs,
        None,
    )
    .await;
    assert_eq!(st_delrole, StatusCode::CONFLICT);

    // d) Removing folio:platform:admin from platform-admin in RoleFolioIndex
    let (st_rfi, _, _, _) = req_full(
        &app,
        "PUT",
        "/api/auth/role-folio-index",
        &elevated_hdrs,
        Some(json!({ "role_folios": { "platform-admin": [] } })),
    )
    .await;
    assert_eq!(st_rfi, StatusCode::CONFLICT);
}

#[tokio::test]
async fn passkey_counters_clone_detection_management_step_up_and_resets() {
    let (state, tmp) = make_auth_test_state().await;
    let app = create_router(state.clone());

    let admin_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
    ];
    let admin_1p = VirtualAuthenticator::new_synced(10, b"cred-admin-1p");
    let cred1_id = enroll_passkey(&app, &admin_hdrs, &admin_1p, "Admin 1P", None).await;

    // 1Password repeated sign_count == 0 -> 0 stays allowed across assertions!
    let (st_1p_a, a1_j) = assert_passkey_manage(&app, &admin_hdrs, &admin_1p, 0).await;
    assert_eq!(st_1p_a, StatusCode::OK);
    assert_eq!(a1_j["sign_count"], 0);
    let proof_for_2nd = a1_j["step_up_proof_id"].as_str().unwrap().to_string();

    // Attempting to add a 2nd Passkey when passkey_count > 0 WITHOUT existing Passkey assertion fails (403).
    let (st_no_stepup, _, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/passkeys/register/start",
        &admin_hdrs,
        Some(json!({ "label": "Hardware Key" })),
    )
    .await;
    assert_eq!(st_no_stepup, StatusCode::FORBIDDEN);

    // Adding a 2nd Passkey (FIDO2 hardware token initialized at count=5) WITH existing assertion succeeds!
    let fido2 = VirtualAuthenticator::new_fido2(20, b"cred-admin-fido2", 5);
    let cred2_id =
        enroll_passkey(&app, &admin_hdrs, &fido2, "FIDO2 Key", Some(&proof_for_2nd)).await;

    // FIDO2 monotonic increment (5 -> 6 -> 7) accepted; regression (7 -> 6) rejected as cloned (403).
    let (st_f1, f1_j) = assert_passkey_manage(&app, &admin_hdrs, &fido2, 6).await;
    assert_eq!(st_f1, StatusCode::OK);
    assert_eq!(f1_j["sign_count"], 6);

    let (st_f2, f2_j) = assert_passkey_manage(&app, &admin_hdrs, &fido2, 7).await;
    assert_eq!(st_f2, StatusCode::OK);
    assert_eq!(f2_j["sign_count"], 7);

    let (st_clone, clone_j) = assert_passkey_manage(&app, &admin_hdrs, &fido2, 6).await;
    assert_eq!(st_clone, StatusCode::FORBIDDEN);
    assert_eq!(clone_j["reason_code"], "authorization_denied");

    // Deleting a Passkey without step-up proof fails (403), with step-up proof succeeds.
    let (st_del_no, _, _, _) = req_full(
        &app,
        "DELETE",
        &format!("/api/auth/passkeys/{cred1_id}"),
        &admin_hdrs,
        None,
    )
    .await;
    assert_eq!(st_del_no, StatusCode::FORBIDDEN);

    let proof_del = f2_j["step_up_proof_id"].as_str().unwrap();
    let (st_del_ok, del_j, _, _) = req_full(
        &app,
        "DELETE",
        &format!("/api/auth/passkeys/{cred1_id}"),
        &admin_hdrs,
        Some(json!({ "step_up_proof_id": proof_del })),
    )
    .await;
    assert_eq!(st_del_ok, StatusCode::OK);
    assert_eq!(del_j["passkey_count"], 1);
    let _ = cred2_id;

    // Elevate to platform-admin to capture cookie before testing host CLI break-glass reset.
    let (st_elev, _, cookie_opt) =
        elevate_role(&app, &admin_hdrs, &fido2, 8, "platform-admin").await;
    assert_eq!(st_elev, StatusCode::OK);
    let cookie = cookie_opt.unwrap();
    let elevated_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
        ("Cookie", cookie.as_str()),
    ];

    // Admin resets Passkeys for an invited operator.
    let (st_inv, inv_j, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/invites",
        &elevated_hdrs,
        Some(json!({ "note": "reset test" })),
    )
    .await;
    assert_eq!(st_inv, StatusCode::CREATED);
    let op_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "ResetTarget"),
    ];
    req_full(
        &app,
        "POST",
        "/api/auth/redeem",
        &op_hdrs,
        Some(json!({ "invite_token": inv_j["invite_token"] })),
    )
    .await;
    let op_auth = VirtualAuthenticator::new_synced(30, b"cred-reset-target");
    enroll_passkey(&app, &op_hdrs, &op_auth, "Target Key", None).await;

    let (st_adm_rst, adm_rst_j, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/users/ResetTarget/passkeys/reset",
        &elevated_hdrs,
        None,
    )
    .await;
    assert_eq!(st_adm_rst, StatusCode::OK);
    assert_eq!(adm_rst_j["reset"], true);
    assert_eq!(adm_rst_j["removed_count"], 1);
    assert_eq!(adm_rst_j["passkey_enrollment_required"], true);

    let (st_op_gate, op_gate_j, _, _) = req_full(&app, "GET", "/api/repos", &op_hdrs, None).await;
    assert_eq!(st_op_gate, StatusCode::FORBIDDEN);
    assert_eq!(op_gate_j["reason_code"], "passkey_enrollment_required");

    let (st_op_sess, op_sess_j, _, _) =
        req_full(&app, "GET", "/api/auth/session", &op_hdrs, None).await;
    assert_eq!(st_op_sess, StatusCode::OK);
    assert_eq!(op_sess_j["passkey_count"], 0);
    assert_eq!(op_sess_j["passkey_enrollment_required"], true);

    // Break-glass host CLI reset clears LMA1980's Passkeys back to 0 and voids active elevated access.
    let cli_args = vec![
        "mu-ci-controller".to_string(),
        "reset-passkeys".to_string(),
        "LMA1980".to_string(),
        "--workspace".to_string(),
        PathBuf::from(tmp.path()).display().to_string(),
    ];
    let cli_res = execute_reset_passkeys_cli(&cli_args).expect("CLI subcommand matched");
    assert!(cli_res.is_ok(), "CLI reset-passkeys failed: {cli_res:?}");

    let (st_post_cli, post_cli_j, _, _) =
        req_full(&app, "GET", "/api/auth/session", &elevated_hdrs, None).await;
    assert_eq!(st_post_cli, StatusCode::OK);
    assert_eq!(post_cli_j["passkey_count"], 0);
    assert_eq!(post_cli_j["passkey_enrollment_required"], true);
    assert_eq!(post_cli_j["role"], Value::Null);
}

#[tokio::test]
async fn role_leases_cookie_tamper_activity_ttl_rejection_and_internal_snapshot_etag() {
    let (state, _tmp) = make_auth_test_state().await;
    let app = create_router(state.clone());

    let admin_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
    ];
    let admin_auth = VirtualAuthenticator::new_synced(40, b"cred-admin-leases");
    enroll_passkey(&app, &admin_hdrs, &admin_auth, "Admin Leases Passkey", None).await;

    // 1. Disabling canonical PinnedBaseline "operator" must fail with 403 pinned_baseline_immutable.
    let (st_dis, dis_j, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/roles/operator/disable",
        &admin_hdrs,
        None,
    )
    .await;
    assert_eq!(st_dis, StatusCode::FORBIDDEN);
    assert_eq!(dis_j["reason_code"], "pinned_baseline_immutable");

    // 2. Reject client-supplied TTL override fields on elevate/start, elevate/finish, and /activity.
    for ttl_field in [
        "hard_ttl_secs",
        "idle_ttl_secs",
        "expires_at_ms",
        "ttl_seconds",
    ] {
        let (st_rej, _, _, _) = req_full(
            &app,
            "POST",
            "/api/auth/elevate/start",
            &admin_hdrs,
            Some(json!({ "role_id": "platform-admin", ttl_field: 999999 })),
        )
        .await;
        assert_eq!(st_rej, StatusCode::BAD_REQUEST);

        let (st_act_rej, _, _, _) = req_full(
            &app,
            "POST",
            "/api/auth/activity",
            &admin_hdrs,
            Some(json!({ ttl_field: 999999 })),
        )
        .await;
        assert_eq!(st_act_rej, StatusCode::BAD_REQUEST);
    }

    // 3. Elevate to platform-admin -> valid cookie accepted; tampered cookie strips elevated rights;
    //    POST /api/auth/activity never increases hard_expires_at_ms.
    let (st_el, el_j, cookie_opt) =
        elevate_role(&app, &admin_hdrs, &admin_auth, 0, "platform-admin").await;
    assert_eq!(st_el, StatusCode::OK);
    let cookie = cookie_opt.unwrap();
    let hard_exp_initial = el_j["session"]["leases"][0]["hard_expires_at_ms"]
        .as_u64()
        .unwrap();

    let elevated_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
        ("Cookie", cookie.as_str()),
    ];

    // 3a. Omitting Cookie header must NOT inherit Timed elevation (#193):
    //     session stays at baseline "operator" with empty leases, and /api/auth/invites fails 403.
    let (st_no_cookie_sess, no_cookie_sess, _, _) =
        req_full(&app, "GET", "/api/auth/session", &admin_hdrs, None).await;
    assert_eq!(st_no_cookie_sess, StatusCode::OK);
    assert_eq!(no_cookie_sess["role"], "operator");
    assert_eq!(no_cookie_sess["leases"].as_array().unwrap().len(), 0);
    let (st_no_cookie_inv, _, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/invites",
        &admin_hdrs,
        Some(json!({ "note": "missing-cookie-bypass" })),
    )
    .await;
    assert_eq!(st_no_cookie_inv, StatusCode::FORBIDDEN);

    // 3b. Elective StepUpRequirement::None role ("ci-operator") stays active without __Host-mu_elevated cookie (#193).
    let (st_grant_ci, _, _, _) = req_full(
        &app,
        "PUT",
        "/api/auth/users/LMA1980/roles",
        &elevated_hdrs,
        Some(json!({ "roles": ["operator", "ci-operator", "platform-admin"] })),
    )
    .await;
    assert_eq!(st_grant_ci, StatusCode::OK);
    let (st_en_ci, en_ci_j, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/roles/ci-operator/enable",
        &admin_hdrs,
        Some(json!({})),
    )
    .await;
    assert_eq!(st_en_ci, StatusCode::OK);
    assert_eq!(en_ci_j["leases"].as_array().unwrap().len(), 0);
    assert!(en_ci_j["active_policies"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p == "ci:jobs.restart"));
    let (st_ci_sess, ci_sess_j, _, _) =
        req_full(&app, "GET", "/api/auth/session", &admin_hdrs, None).await;
    assert_eq!(st_ci_sess, StatusCode::OK);
    assert!(ci_sess_j["active_policies"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p == "ci:jobs.restart"));
    assert_eq!(ci_sess_j["leases"].as_array().unwrap().len(), 0);

    // 3c. Invalid role_id in elevate/start and elevate/finish returns 400 Bad Request, never panics (#193).
    let (st_bad_start, _, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/elevate/start",
        &admin_hdrs,
        Some(json!({ "role_id": "Invalid Role!" })),
    )
    .await;
    assert_eq!(st_bad_start, StatusCode::BAD_REQUEST);

    let (st_good_start, good_start_j, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/elevate/start",
        &admin_hdrs,
        Some(json!({ "role_id": "platform-admin" })),
    )
    .await;
    assert_eq!(st_good_start, StatusCode::OK);
    let bad_fin_cid = good_start_j["challenge_id"].as_str().unwrap().to_string();
    let bad_fin_chal = URL_SAFE_NO_PAD
        .decode(
            good_start_j["options"]["publicKey"]["challenge"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    let bad_fin_cred = admin_auth.assert_response(&bad_fin_chal, 0);
    let (st_bad_fin, _, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/elevate/finish",
        &admin_hdrs,
        Some(json!({
            "challenge_id": bad_fin_cid,
            "credential": bad_fin_cred,
            "role_id": "Invalid Role!",
        })),
    )
    .await;
    assert_eq!(st_bad_fin, StatusCode::BAD_REQUEST);

    // 3d. Default invite fallback URL uses canonical public domain, never `.local` (#194).
    let (st_inv_default, inv_default_j, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/invites",
        &elevated_hdrs,
        Some(json!({ "note": "default-url-check" })),
    )
    .await;
    assert_eq!(st_inv_default, StatusCode::CREATED);
    let default_inv_url = inv_default_j["invite_url"].as_str().unwrap();
    assert!(
        default_inv_url.starts_with("https://console.lma1980.duckdns.org/#redeem="),
        "unexpected invite fallback URL: {default_inv_url}"
    );
    assert!(!default_inv_url.contains(".local"));

    let (st_admin_snap, _, _, _) = req_full(
        &app,
        "GET",
        "/api/internal/auth/snapshot",
        &elevated_hdrs,
        None,
    )
    .await;
    assert_eq!(st_admin_snap, StatusCode::OK);

    let (st_act, act_j, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/activity",
        &elevated_hdrs,
        Some(json!({})),
    )
    .await;
    assert_eq!(st_act, StatusCode::OK);
    let hard_exp_after = act_j["leases"][0]["hard_expires_at_ms"].as_u64().unwrap();
    assert_eq!(hard_exp_after, hard_exp_initial);
    assert!(act_j["leases"][0]["seconds_remaining"].as_u64().unwrap() <= 900);
    assert!(act_j["leases"][0]["idle_timer"].as_u64().unwrap() <= 300);

    // Tampered cookie -> platform-admin is NOT granted on /api/auth/invites (403).
    let tampered_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
        ("Cookie", "__Host-mu_elevated=tampered.0000"),
    ];
    let (st_tamp, _, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/invites",
        &tampered_hdrs,
        Some(json!({ "note": "tampered" })),
    )
    .await;
    assert_eq!(st_tamp, StatusCode::FORBIDDEN);

    // lock-all revokes timed leases & bumps elevation_epoch so previous valid cookie becomes stale (403).
    let (st_lock, _, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/elevate/lock-all",
        &elevated_hdrs,
        None,
    )
    .await;
    assert_eq!(st_lock, StatusCode::OK);
    let (st_stale, _, _, _) = req_full(
        &app,
        "POST",
        "/api/auth/invites",
        &elevated_hdrs,
        Some(json!({ "note": "stale cookie" })),
    )
    .await;
    assert_eq!(st_stale, StatusCode::FORBIDDEN);

    // 4. GET /api/internal/auth/snapshot rejects anonymous & proxy-secret-only requests (#194),
    //    accepts AdminApiKey (or elevated platform-admin), serves ETag, and returns 304 on If-None-Match.
    let (st_unauth, _, _, _) =
        req_full(&app, "GET", "/api/internal/auth/snapshot", &[], None).await;
    assert_eq!(st_unauth, StatusCode::UNAUTHORIZED);

    let (st_proxy_only, _, _, _) = req_full(
        &app,
        "GET",
        "/api/internal/auth/snapshot",
        &[("X-Proxy-Secret", PROXY_SECRET)],
        None,
    )
    .await;
    assert_eq!(st_proxy_only, StatusCode::UNAUTHORIZED);

    let (st_non_elev, _, _, _) = req_full(
        &app,
        "GET",
        "/api/internal/auth/snapshot",
        &admin_hdrs,
        None,
    )
    .await;
    assert_eq!(st_non_elev, StatusCode::FORBIDDEN);

    let bearer = format!("Bearer {API_KEY}");
    let internal_hdrs = [("Authorization", bearer.as_str())];
    let (st_snap, snap_j, _, etag_opt) = req_full(
        &app,
        "GET",
        "/api/internal/auth/snapshot",
        &internal_hdrs,
        None,
    )
    .await;
    assert_eq!(st_snap, StatusCode::OK);
    let etag = etag_opt.expect("ETag header required");
    assert_eq!(snap_j["baseline_role"], "operator");

    let (st_304, _, _, etag_304) = req_full(
        &app,
        "GET",
        "/api/internal/auth/snapshot",
        &[
            ("Authorization", bearer.as_str()),
            ("If-None-Match", etag.as_str()),
        ],
        None,
    )
    .await;
    assert_eq!(st_304, StatusCode::NOT_MODIFIED);
    assert_eq!(etag_304.as_deref(), Some(etag.as_str()));
}
