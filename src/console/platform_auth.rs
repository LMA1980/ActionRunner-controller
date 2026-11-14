//! Platform RBAC, Policy Folio, WebAuthn Passkey, and Timed Role Elevation HTTP handlers
//! for Epic `#172` (`#173`–`#180`) integrating `mu-auth`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::header::{self, CACHE_CONTROL, ETAG, IF_NONE_MATCH, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration as ChronoDuration, Utc};
use mu_auth::{
    AuthError, FolioError, FolioId, FolioOrigin, GithubLogin, Policy, PolicyFolio, Principal,
    RoleActivation, RoleId, RoleSpec, StepUpRequirement, SubsystemId,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use webauthn_rs_core::proto::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::auth::{
    activate_server_role_lease, authenticate_edge_github_login, build_webauthn_service,
    current_epoch_ms, datetime_to_epoch_ms, format_elevated_clear_cookie,
    format_elevated_set_cookie, normalize_login, payload_has_forbidden_ttl_fields,
    sign_baseline_invite_token, sign_elevated_cookie, verify_baseline_invite_token,
    verify_elevated_cookie, AuthReasonCodeDto, AuthSessionDto, ConsoleSkinDto, CrtFontDto,
    ElevatedCookieClaims, PendingAuthenticationState, PendingRegistrationState, PlatformAuthState,
    PlatformInviteRecord, StepUpPurpose, StoredPasskeyRecord, VerifiedStepUpProof,
    ELEVATED_COOKIE_NAME, STEP_UP_PROOF_TTL_MS,
};
use crate::config::Config;
use crate::console::api::parse_invite_token;
use crate::job::JobStore;
use crate::webhook::AppState;

const DEFAULT_INVITE_TTL_SECS: u64 = 86_400;
const MAX_INVITE_TTL_SECS: u64 = 30 * 86_400;

/// Full per-request authentication and `mu-auth` policy evaluation context.
#[derive(Debug, Clone)]
pub struct EvaluatedRequestAuth {
    /// Caller matched `Config::log_api_key`.
    pub is_admin_api_key: bool,
    /// Validated GitHub login (original casing if bound, or header casing if uninvited).
    pub login: Option<String>,
    /// Lowercase key for state lookups.
    pub login_key: Option<String>,
    /// True when bound to an active non-revoked account.
    pub invite_bound: bool,
    /// True when edge GitHub identity was authenticated but account is uninvited or revoked.
    pub is_uninvited: bool,
    /// True when edge headers failed trust verification (missing/invalid `X-Proxy-Secret` while claiming identity).
    pub bad_edge_auth: bool,
    /// True when `RoleFolioIndex["anonymous"]` is empty (`#174` / `#176`).
    pub anonymous_lockdown: bool,
    /// True when controller authentication or anonymous lockdown is active.
    pub auth_configured: bool,
    /// True when bound account currently holds zero enrolled Passkeys (`#177` / `#178`).
    pub passkey_enrollment_required: bool,
    /// Enrolled Passkey count (`0` for uninvited or unauthenticated).
    pub passkey_count: u32,
    /// Effective evaluated `PolicyId` strings granted to this request.
    pub active_policies: BTreeSet<String>,
    /// Whether `__Host-mu_elevated` cookie was valid (or omitted by non-cookie API caller).
    pub cookie_valid_for_elevated: bool,
    /// Sanitized `AuthSessionDto` payload returned by `GET /api/auth/session`.
    pub session_dto: AuthSessionDto,
}

impl EvaluatedRequestAuth {
    /// Evaluates incoming HTTP headers and optional query key against `Config` and `PlatformAuthState`.
    #[must_use]
    pub fn evaluate(
        config: &Config,
        job_store: &JobStore,
        headers: &HeaderMap,
        query_key: Option<&str>,
    ) -> Self {
        if !config.bootstrap_admins.is_empty() {
            let needs_seed = job_store
                .read_platform_auth(|st| {
                    config
                        .bootstrap_admins
                        .iter()
                        .filter_map(|raw| normalize_login(raw))
                        .any(|key| !st.bootstrap_seeded.contains(&key))
                })
                .unwrap_or(false);
            if needs_seed {
                job_store.seed_bootstrap_admins(&config.bootstrap_admins);
            }
        }

        if has_valid_admin_api_key(config, headers, query_key) {
            return Self::admin_api_key(config, job_store);
        }

        let header_secret = headers.get("x-proxy-secret").and_then(|v| v.to_str().ok());
        let forwarded_user = headers
            .get("x-forwarded-user")
            .and_then(|v| v.to_str().ok());
        let raw_login = authenticate_edge_github_login(
            config.proxy_secret.as_deref(),
            header_secret,
            forwarded_user,
        );
        let has_proxy_headers = header_secret.is_some() || forwarded_user.is_some();
        let bad_edge_auth = raw_login.is_none() && has_proxy_headers;
        let raw_cookie = extract_elevated_cookie(headers);

        let now_ms = current_epoch_ms();
        let signing_key = config.elevation_signing_key();

        let (
            anonymous_lockdown,
            invite_bound,
            is_uninvited,
            passkey_enrollment_required,
            passkey_count,
            active_policies,
            cookie_valid_for_elevated,
            session_dto,
            canonical_login,
            login_key,
        ) = job_store
            .read_platform_auth(|st| {
                let anon_lockdown = st.is_anonymous_lockdown();
                let normalized_key = raw_login.as_deref().and_then(normalize_login);
                let active_user = normalized_key
                    .as_deref()
                    .and_then(|k| st.users.get(k).filter(|u| !u.revoked));

                let cookie_ok = match (
                    active_user,
                    normalized_key.as_deref(),
                    raw_cookie.as_deref(),
                ) {
                    (Some(user), Some(key), Some(cookie_token)) => verify_elevated_cookie(
                        &signing_key,
                        cookie_token,
                        key,
                        user.elevation_epoch,
                        now_ms,
                    )
                    .is_some(),
                    _ => false,
                };

                let (principal, leases, eval) =
                    st.evaluate_principal(raw_login.as_deref(), cookie_ok, now_ms);
                let mut dto =
                    st.build_session_dto(normalized_key.as_deref(), &leases, &eval, now_ms);

                match (&raw_login, &principal) {
                    (Some(presented), Principal::Anonymous) => {
                        // Uninvited or revoked caller: generic AuthorizationDenied with zero invite hints
                        // and zero inherited policies on protected routes.
                        dto.github_login = Some(presented.clone());
                        dto.reason_code = Some(AuthReasonCodeDto::AuthorizationDenied);
                        dto.active_folios.clear();
                        dto.active_policies.clear();
                        (
                            anon_lockdown,
                            false,
                            true,
                            false,
                            0,
                            BTreeSet::new(),
                            false,
                            dto,
                            Some(presented.clone()),
                            normalized_key,
                        )
                    }
                    (Some(_), Principal::Authenticated { login, .. }) => {
                        let policies: BTreeSet<String> =
                            eval.policies.iter().map(ToString::to_string).collect();
                        let pcount =
                            st.passkey_count_for(normalized_key.as_deref().unwrap_or_default());
                        let enrolled_req = eval.passkey_enrollment_required || pcount == 0;
                        (
                            anon_lockdown,
                            true,
                            false,
                            enrolled_req,
                            pcount,
                            if enrolled_req {
                                BTreeSet::new()
                            } else {
                                policies
                            },
                            cookie_ok,
                            dto,
                            Some(login.clone()),
                            normalized_key,
                        )
                    }
                    (None, _) => {
                        let policies: BTreeSet<String> =
                            eval.policies.iter().map(ToString::to_string).collect();
                        if anon_lockdown {
                            dto.reason_code = Some(AuthReasonCodeDto::AuthenticationRequired);
                        }
                        (
                            anon_lockdown,
                            false,
                            false,
                            false,
                            0,
                            policies,
                            false,
                            dto,
                            None,
                            None,
                        )
                    }
                }
            })
            .unwrap_or_else(|| {
                (
                    true,
                    false,
                    false,
                    false,
                    0,
                    BTreeSet::new(),
                    false,
                    AuthSessionDto {
                        authenticated: false,
                        github_login: None,
                        invite_bound: false,
                        role: None,
                        reason_code: Some(AuthReasonCodeDto::AuthenticationRequired),
                        passkey_count: 0,
                        passkey_enrollment_required: false,
                        anonymous_lockdown: true,
                        anonymous_login_only: true,
                        baseline_role: Some(crate::auth::BASELINE_ROLE_ID.to_string()),
                        bound_roles: Vec::new(),
                        active_roles: Vec::new(),
                        leases: Vec::new(),
                        active_folios: Vec::new(),
                        active_policies: Vec::new(),
                        preferences: None,
                        display_name: None,
                    },
                    None,
                    None,
                )
            });

        let auth_configured = config.log_api_key.is_some()
            || config.proxy_secret.is_some()
            || anonymous_lockdown
            || has_proxy_headers;

        Self {
            is_admin_api_key: false,
            login: canonical_login,
            login_key,
            invite_bound,
            is_uninvited,
            bad_edge_auth,
            anonymous_lockdown,
            auth_configured,
            passkey_enrollment_required,
            passkey_count,
            active_policies,
            cookie_valid_for_elevated,
            session_dto,
        }
    }

    fn admin_api_key(config: &Config, job_store: &JobStore) -> Self {
        let (anon_lockdown, baseline, all_policies, all_folios, roles) = job_store
            .read_platform_auth(|st| {
                let policies: Vec<String> = st
                    .folio_catalog
                    .policies()
                    .map(|p| p.id.to_string())
                    .collect();
                let folios: Vec<String> = st
                    .folio_catalog
                    .folios()
                    .map(|f| f.id.to_string())
                    .collect();
                let roles: Vec<RoleSpec> = st.role_catalog.iter().cloned().collect();
                (
                    st.is_anonymous_lockdown(),
                    st.baseline_role_id().to_string(),
                    policies,
                    folios,
                    roles,
                )
            })
            .unwrap_or_else(|| {
                (
                    false,
                    crate::auth::BASELINE_ROLE_ID.to_string(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
            });
        let policy_set: BTreeSet<String> = all_policies.iter().cloned().collect();
        let dto = AuthSessionDto {
            authenticated: true,
            github_login: None,
            invite_bound: true,
            role: Some("admin".to_string()),
            reason_code: None,
            passkey_count: 1,
            passkey_enrollment_required: false,
            anonymous_lockdown: anon_lockdown,
            anonymous_login_only: anon_lockdown,
            baseline_role: Some(baseline),
            bound_roles: vec!["admin".to_string()],
            active_roles: roles,
            leases: Vec::new(),
            active_folios: all_folios,
            active_policies: all_policies,
            preferences: None,
            display_name: None,
        };
        let auth_configured =
            config.log_api_key.is_some() || config.proxy_secret.is_some() || anon_lockdown;
        Self {
            is_admin_api_key: true,
            login: None,
            login_key: None,
            invite_bound: true,
            is_uninvited: false,
            bad_edge_auth: false,
            anonymous_lockdown: anon_lockdown,
            auth_configured,
            passkey_enrollment_required: false,
            passkey_count: 1,
            active_policies: policy_set,
            cookie_valid_for_elevated: true,
            session_dto: dto,
        }
    }

    /// True when the caller is authenticated with console read/operate eligibility (`passkey_count > 0` or API key).
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.is_admin_api_key || (self.invite_bound && !self.passkey_enrollment_required)
    }

    /// True if caller possesses the canonical `policy` string.
    #[must_use]
    pub fn has_policy(&self, policy: &str) -> bool {
        self.is_admin_api_key
            || (self.invite_bound
                && !self.passkey_enrollment_required
                && self.active_policies.contains(policy))
    }

    /// True when caller holds full `folio:platform:admin` rights (`AdminApiKey` or bound+enrolled admin).
    #[must_use]
    pub fn is_platform_admin(&self) -> bool {
        self.is_admin_api_key
            || (self.has_policy("platform:users.write")
                && self.has_policy("platform:roles.write")
                && self.has_policy("platform:folios.write")
                && self.has_policy("platform:invites.write"))
    }

    /// Policy gate for protected operator/admin operations.
    ///
    /// Returns `None` when allowed, or a structured JSON error `Response` (`401`/`403`) on denial.
    pub fn gate_policy(&self, policy: &str) -> Option<Response> {
        if self.is_admin_api_key {
            return None;
        }
        if self.is_uninvited {
            return Some(authorization_denied_response());
        }
        if self.passkey_enrollment_required {
            return Some(passkey_enrollment_required_response());
        }
        if self.invite_bound {
            if self.active_policies.contains(policy) {
                return None;
            }
            return Some(authorization_denied_response());
        }
        if self.auth_configured || self.anonymous_lockdown {
            if !self.anonymous_lockdown && self.active_policies.contains(policy) {
                return None;
            }
            return Some(authentication_required_response());
        }
        None
    }

    /// Policy gate for console/CI read endpoints that allow sanitized anonymous views unless
    /// `anonymous_lockdown` (`anonymous = []`) is enabled or the caller is uninvited/0-Passkey.
    pub fn gate_public_read(&self, policy: &str) -> Option<Response> {
        if self.is_admin_api_key {
            return None;
        }
        if self.is_uninvited {
            return Some(authorization_denied_response());
        }
        if self.passkey_enrollment_required {
            return Some(passkey_enrollment_required_response());
        }
        if self.invite_bound {
            if self.active_policies.contains(policy) {
                return None;
            }
            return Some(authorization_denied_response());
        }
        if self.anonymous_lockdown {
            return Some(authentication_required_response());
        }
        if self.bad_edge_auth {
            return Some(authentication_required_response());
        }
        if policy == "ci:queue.read"
            && self.auth_configured
            && !self.active_policies.contains("ci:queue.read")
        {
            return Some(authentication_required_response());
        }
        None
    }

    /// Requires a bound GitHub user (never `Anonymous` or `AdminApiKey`); optionally requires
    /// at least one enrolled Passkey.
    fn require_bound_user(&self, require_passkey: bool) -> AuthResult<(String, String)> {
        if self.is_uninvited {
            return err_resp(authorization_denied_response());
        }
        if !self.invite_bound {
            if self.is_admin_api_key {
                return err_resp(bad_request_response(
                    "Operation requires an interactive GitHub user identity",
                ));
            }
            return err_resp(authentication_required_response());
        }
        if require_passkey && self.passkey_enrollment_required {
            return err_resp(passkey_enrollment_required_response());
        }
        match (self.login.as_ref(), self.login_key.as_ref()) {
            (Some(login), Some(key)) => Ok((login.clone(), key.clone())),
            _ => err_resp(authentication_required_response()),
        }
    }
}

/// Checks bearer token, `X-Api-Key`, or `?key=` against `Config::log_api_key` in constant time.
pub(crate) fn has_valid_admin_api_key(
    config: &Config,
    headers: &HeaderMap,
    query_key: Option<&str>,
) -> bool {
    let Some(expected) = config.log_api_key.as_deref() else {
        return false;
    };
    if let Some(provided) = extract_api_key_candidate(headers, query_key) {
        return constant_time_eq(provided.as_bytes(), expected.as_bytes());
    }
    false
}

fn extract_api_key_candidate<'a>(
    headers: &'a HeaderMap,
    query_key: Option<&'a str>,
) -> Option<&'a str> {
    if let Some(val) = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return Some(val);
    }
    if let Some(val) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .and_then(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return Some(val);
    }
    query_key.map(str::trim).filter(|v| !v.is_empty())
}

fn extract_elevated_cookie(headers: &HeaderMap) -> Option<String> {
    for val in headers.get_all(header::COOKIE) {
        let Ok(raw) = val.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            let trimmed = pair.trim();
            if let Some((name, cookie_val)) = trimmed.split_once('=') {
                if name.trim() == ELEVATED_COOKIE_NAME {
                    let v = cookie_val.trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

type AuthResult<T> = Result<T, Box<Response>>;

fn err_resp<T>(resp: Response) -> AuthResult<T> {
    Err(Box::new(resp))
}

fn read_auth<R>(job_store: &JobStore, f: impl FnOnce(&PlatformAuthState) -> R) -> AuthResult<R> {
    job_store.read_platform_auth(f).ok_or_else(|| {
        Box::new(json_status(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({ "error": "Platform auth catalog storage is unavailable" }),
        ))
    })
}

fn mutate_auth<R>(
    job_store: &JobStore,
    f: impl FnOnce(&mut PlatformAuthState) -> AuthResult<R>,
) -> AuthResult<R> {
    job_store.mutate_platform_auth(f).unwrap_or_else(|| {
        err_resp(json_status(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({ "error": "Platform auth catalog storage is unavailable" }),
        ))
    })
}

fn json_status<T: Serialize>(status: StatusCode, val: &T) -> Response {
    let body = serde_json::to_string(val).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub(crate) fn json_status_with_cookie<T: Serialize>(
    status: StatusCode,
    val: &T,
    cookie_header: Option<&str>,
) -> Response {
    let body = serde_json::to_string(val).unwrap_or_else(|_| "{}".to_string());
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store");
    if let Some(cookie) = cookie_header {
        builder = builder.header(SET_COOKIE, cookie);
    }
    builder
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub(crate) fn auth_error_response(
    status: StatusCode,
    code: AuthReasonCodeDto,
    message: &str,
) -> Response {
    json_status(
        status,
        &json!({
            "error": message,
            "reason_code": code,
        }),
    )
}

/// Generic 403 `AuthorizationDenied` omitting invite existence details (`#176`).
pub(crate) fn authorization_denied_response() -> Response {
    auth_error_response(
        StatusCode::FORBIDDEN,
        AuthReasonCodeDto::AuthorizationDenied,
        "Forbidden: authorization denied",
    )
}

pub(crate) fn authentication_required_response() -> Response {
    auth_error_response(
        StatusCode::UNAUTHORIZED,
        AuthReasonCodeDto::AuthenticationRequired,
        "Unauthorized: valid operator session or API key required",
    )
}

pub(crate) fn passkey_enrollment_required_response() -> Response {
    json_status(
        StatusCode::FORBIDDEN,
        &json!({
            "error": "Passkey enrollment required before console access is permitted",
            "reason_code": AuthReasonCodeDto::PasskeyEnrollmentRequired,
            "passkey_enrollment_required": true,
        }),
    )
}

fn step_up_required_response(message: &str) -> Response {
    json_status(
        StatusCode::FORBIDDEN,
        &json!({
            "error": message,
            "reason_code": AuthReasonCodeDto::StepUpRequired,
            "step_up_required": true,
        }),
    )
}

fn bad_request_response(message: &str) -> Response {
    json_status(StatusCode::BAD_REQUEST, &json!({ "error": message }))
}

fn conflict_response(message: &str) -> Response {
    json_status(StatusCode::CONFLICT, &json!({ "error": message }))
}

fn not_found_response(message: &str) -> Response {
    json_status(StatusCode::NOT_FOUND, &json!({ "error": message }))
}

fn forbidden_ttl_override_response() -> Response {
    auth_error_response(
        StatusCode::BAD_REQUEST,
        AuthReasonCodeDto::CeilingExceeded,
        "Client-supplied TTL overrides are forbidden; role lifetimes are server-derived",
    )
}

fn map_folio_error(err: &FolioError) -> Response {
    match err {
        FolioError::CannotDeactivatePinnedBaseline(_) => auth_error_response(
            StatusCode::FORBIDDEN,
            AuthReasonCodeDto::PinnedBaselineImmutable,
            &err.to_string(),
        ),
        FolioError::StepUpRequired { .. } => step_up_required_response(&err.to_string()),
        FolioError::PasskeyEnrollmentRequired => passkey_enrollment_required_response(),
        FolioError::AuthorizationDenied | FolioError::UnauthorizedActivation { .. } => {
            authorization_denied_response()
        }
        FolioError::TtlExceedsCeiling { .. } => auth_error_response(
            StatusCode::BAD_REQUEST,
            AuthReasonCodeDto::CeilingExceeded,
            &err.to_string(),
        ),
        FolioError::ImmutableSubsystemFolio(_) => auth_error_response(
            StatusCode::FORBIDDEN,
            AuthReasonCodeDto::AuthorizationDenied,
            &err.to_string(),
        ),
        other => bad_request_response(&other.to_string()),
    }
}

fn webauthn_user_unique_id(login_key: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"mu-console-webauthn-user:");
    hasher.update(login_key.as_bytes());
    hasher.finalize()[..16].to_vec()
}

fn encode_credential_id(id: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(id)
}

fn extract_step_up_proof_id(
    headers: &HeaderMap,
    query_proof_id: Option<&str>,
    body: Option<&Value>,
) -> Option<String> {
    if let Some(v) = body
        .and_then(|b| b.get("step_up_proof_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(v.to_string());
    }
    if let Some(v) = query_proof_id.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(v.to_string());
    }
    headers
        .get("x-step-up-proof")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

/// Consumes either an existing valid single-use `VerifiedStepUpProof` or verifies an inline
/// WebAuthn assertion payload (`step_up_challenge_id` + `step_up_credential`, or `challenge_id` + `credential`)
/// inside `mutate_auth`.
#[allow(clippy::too_many_arguments)]
fn verify_and_consume_passkey_assertion_inline(
    st: &mut PlatformAuthState,
    config: &Config,
    login: &GithubLogin,
    login_key: &str,
    proof_id: Option<&str>,
    inline_challenge_id: Option<&str>,
    inline_credential: Option<PublicKeyCredential>,
    required_purpose: StepUpPurpose,
    now_ms: u64,
) -> AuthResult<u32> {
    st.prune_challenges(now_ms);

    if let (Some(cid), Some(cred)) = (inline_challenge_id, inline_credential) {
        let Some(pending) = st.pending_authentications.remove(cid) else {
            return err_resp(auth_error_response(
                StatusCode::UNAUTHORIZED,
                AuthReasonCodeDto::AuthenticationRequired,
                "Passkey challenge not found or expired",
            ));
        };
        if pending.login_key != login_key || now_ms >= pending.expires_at_ms {
            return err_resp(auth_error_response(
                StatusCode::UNAUTHORIZED,
                AuthReasonCodeDto::AuthenticationRequired,
                "Passkey challenge expired or belongs to another operator",
            ));
        }
        let svc = build_webauthn_service(config).map_err(|e| {
            Box::new(json_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({ "error": e }),
            ))
        })?;
        let existing_creds: Vec<_> = st
            .passkeys
            .get(login_key)
            .map(|rows| rows.iter().map(|r| r.record.clone()).collect())
            .unwrap_or_default();
        let outcome = svc
            .complete_authentication(login, &existing_creds, &pending.pending, &cred, now_ms)
            .map_err(|err| Box::new(map_webauthn_failure(st, login_key, &err, now_ms)))?;

        update_stored_passkey_after_auth(st, login_key, &outcome, now_ms);
        return Ok(outcome.new_sign_count);
    }

    if let Some(pid) = proof_id {
        if let Some(proof) = st.verified_step_up_proofs.remove(pid) {
            if proof.login_key == login_key
                && now_ms < proof.expires_at_ms
                && (proof.purpose == required_purpose
                    || required_purpose == StepUpPurpose::PasskeyManage)
            {
                return Ok(0);
            }
        }
        return err_resp(step_up_required_response(
            "Step-up proof is missing, expired, or already consumed",
        ));
    }

    err_resp(step_up_required_response(
        "Existing Passkey assertion is required to complete this operation",
    ))
}

fn map_webauthn_failure(
    st: &mut PlatformAuthState,
    login_key: &str,
    err: &AuthError,
    now_ms: u64,
) -> Response {
    match err {
        AuthError::CloneDetected => {
            st.record_audit(
                login_key,
                "passkey.clone_detected",
                None,
                "rejected",
                now_ms,
            );
            st.snapshot_revision = st.snapshot_revision.saturating_add(1);
            auth_error_response(
                StatusCode::FORBIDDEN,
                AuthReasonCodeDto::AuthorizationDenied,
                "WebAuthn authenticator clone detected (signature counter regression)",
            )
        }
        AuthError::BackupEligibilityDowngrade => {
            st.record_audit(
                login_key,
                "passkey.backup_downgrade",
                None,
                "rejected",
                now_ms,
            );
            auth_error_response(
                StatusCode::FORBIDDEN,
                AuthReasonCodeDto::AuthorizationDenied,
                "WebAuthn credential backup eligibility downgrade rejected",
            )
        }
        other => {
            st.record_audit(login_key, "passkey.assertion", None, "failed", now_ms);
            auth_error_response(
                StatusCode::UNAUTHORIZED,
                AuthReasonCodeDto::AuthenticationRequired,
                &format!("Passkey verification failed: {other}"),
            )
        }
    }
}

fn update_stored_passkey_after_auth(
    st: &mut PlatformAuthState,
    login_key: &str,
    outcome: &mu_auth::AuthenticationOutcome,
    now_ms: u64,
) {
    let target_id = encode_credential_id(outcome.credential_id.as_ref());
    if let Some(list) = st.passkeys.get_mut(login_key) {
        if let Some(entry) = list.iter_mut().find(|item| {
            item.credential_id == target_id
                || item.record.credential_id.as_slice() == outcome.credential_id.as_slice()
        }) {
            entry.record = outcome.updated_credential.clone();
            entry.last_used_at_ms = Some(now_ms);
        }
    }
    if let Some(u) = st.users.get_mut(login_key) {
        u.last_seen_ms = Some(now_ms);
    }
    st.snapshot_revision = st.snapshot_revision.saturating_add(1);
}

// =========================================================================
// Session, Invite Redemption & Self-Service Profile
// =========================================================================

/// `GET /api/auth/session`
pub async fn auth_session(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    json_status(StatusCode::OK, &eval.session_dto)
}

#[derive(Debug, Default, Deserialize)]
pub struct RedeemInviteRequest {
    #[serde(default)]
    pub invite_token: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

impl RedeemInviteRequest {
    #[must_use]
    pub fn effective_token(&self) -> Option<&str> {
        self.invite_token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                self.token
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            })
    }
}

/// `POST /api/auth/redeem`
///
/// Always binds a validated onboarding token strictly to canonical `PinnedBaseline` (`"operator"`).
pub async fn redeem_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(raw_body): Json<Value>,
) -> Response {
    if let Some(obj) = raw_body.as_object() {
        if obj.contains_key("role") || obj.contains_key("roles") || obj.contains_key("roles_json") {
            return bad_request_response(
                "Invite redemption binds exclusively to canonical PinnedBaseline role",
            );
        }
    }
    let payload: RedeemInviteRequest = match serde_json::from_value(raw_body) {
        Ok(p) => p,
        Err(e) => return bad_request_response(&format!("Invalid JSON payload: {e}")),
    };

    let header_secret = headers.get("x-proxy-secret").and_then(|v| v.to_str().ok());
    let forwarded_user = headers
        .get("x-forwarded-user")
        .and_then(|v| v.to_str().ok());
    let Some(github_login) = authenticate_edge_github_login(
        state.config.proxy_secret.as_deref(),
        header_secret,
        forwarded_user,
    ) else {
        return json_status(
            StatusCode::UNAUTHORIZED,
            &json!({
                "error": "Unauthorized: valid X-Proxy-Secret and X-Forwarded-User headers required",
                "reason_code": AuthReasonCodeDto::AuthenticationRequired,
            }),
        );
    };
    let Some(login_key) = normalize_login(&github_login) else {
        return json_status(
            StatusCode::UNAUTHORIZED,
            &json!({
                "error": "Unauthorized: valid X-Proxy-Secret and X-Forwarded-User headers required",
                "reason_code": AuthReasonCodeDto::AuthenticationRequired,
            }),
        );
    };

    let Some(raw_token) = payload.effective_token() else {
        return json_status(
            StatusCode::UNPROCESSABLE_ENTITY,
            &json!({ "error": "Missing invite token: expected 'invite_token' or 'token' field" }),
        );
    };

    let Some(signing_key) = state
        .config
        .invite_signing_key
        .as_deref()
        .filter(|s| !s.is_empty())
    else {
        return json_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({ "error": "Invite signing key is not configured" }),
        );
    };

    let Some((invite_id, presented_hmac)) = parse_invite_token(raw_token) else {
        return auth_error_response(
            StatusCode::UNAUTHORIZED,
            AuthReasonCodeDto::AuthenticationRequired,
            "Invalid or tampered invite token",
        );
    };

    let now = Utc::now();
    let now_ms = datetime_to_epoch_ms(now);

    let outcome = mutate_auth(&state.job_store, |st| {
        let Some(existing_inv) = st.invites.get(invite_id).cloned() else {
            return err_resp(auth_error_response(
                StatusCode::UNAUTHORIZED,
                AuthReasonCodeDto::AuthenticationRequired,
                "Invalid or tampered invite token",
            ));
        };
        if !verify_baseline_invite_token(
            signing_key,
            invite_id,
            existing_inv.expires_at_ms,
            presented_hmac,
            &st.role_catalog,
        ) {
            return err_resp(auth_error_response(
                StatusCode::UNAUTHORIZED,
                AuthReasonCodeDto::AuthenticationRequired,
                "Invalid or tampered invite token",
            ));
        }
        if existing_inv.revoked {
            return err_resp(json_status(
                StatusCode::GONE,
                &json!({ "error": "Invite has been revoked" }),
            ));
        }
        if existing_inv.used_by_github_login.is_some() {
            return err_resp(json_status(
                StatusCode::CONFLICT,
                &json!({ "error": "Invite token has already been used" }),
            ));
        }
        if now_ms >= existing_inv.expires_at_ms {
            return err_resp(json_status(
                StatusCode::GONE,
                &json!({ "error": "Invite token has expired" }),
            ));
        }
        if let Some(inv) = st.invites.get_mut(invite_id) {
            inv.used_by_github_login = Some(github_login.clone());
            inv.used_at = Some(now.to_rfc3339());
            inv.used_at_ms = Some(now_ms);
        }
        st.bind_baseline_user(
            &github_login,
            &existing_inv.created_by,
            Some(invite_id),
            now,
        );
        let (_, leases, eval) = st.evaluate_principal(Some(&github_login), false, now_ms);
        Ok(st.build_session_dto(Some(&login_key), &leases, &eval, now_ms))
    });

    match outcome {
        Ok(dto) => json_status(StatusCode::OK, &dto),
        Err(resp) => *resp,
    }
}

/// `GET /api/auth/profile`
pub async fn get_profile(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (_, login_key) = match eval.require_bound_user(true) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    match read_auth(&state.job_store, |st| st.build_profile_dto(&login_key)) {
        Ok(Some(dto)) => json_status(StatusCode::OK, &dto),
        Ok(None) => authorization_denied_response(),
        Err(resp) => *resp,
    }
}

#[derive(Debug, Deserialize)]
struct UpdatePreferencesNested {
    #[serde(default)]
    skin: Option<String>,
    #[serde(default)]
    font: Option<String>,
}

/// `PUT|PATCH /api/auth/profile`
pub async fn update_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(raw_body): Json<Value>,
) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (_, login_key) = match eval.require_bound_user(true) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    let Some(obj) = raw_body.as_object() else {
        return bad_request_response("JSON object payload required");
    };

    let display_name_update: Option<Option<String>> = match obj.get("display_name") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::String(s)) => Some(Some(s.clone())),
        Some(_) => return bad_request_response("display_name must be a string or null"),
    };

    let prefs_nested: Option<UpdatePreferencesNested> = match obj.get("preferences") {
        Some(v) => match serde_json::from_value(v.clone()) {
            Ok(p) => Some(p),
            Err(e) => return bad_request_response(&format!("Invalid preferences object: {e}")),
        },
        None => None,
    };

    let raw_skin = obj
        .get("skin")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| prefs_nested.as_ref().and_then(|p| p.skin.clone()));
    let skin = match raw_skin {
        None => None,
        Some(s) => match parse_skin_str(&s) {
            Some(parsed) => Some(parsed),
            None => return bad_request_response(&format!("Unsupported console skin '{s}'")),
        },
    };

    let raw_font = obj
        .get("font")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| prefs_nested.as_ref().and_then(|p| p.font.clone()));
    let font = match raw_font {
        None => None,
        Some(f) => match parse_font_str(&f) {
            Some(parsed) => Some(parsed),
            None => return bad_request_response(&format!("Unsupported CRT font '{f}'")),
        },
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        let name_ref = display_name_update.as_ref().map(|opt| opt.as_deref());
        st.update_user_profile(&login_key, name_ref, skin, font, now_ms)
            .map_err(|msg| Box::new(bad_request_response(&msg)))
    });

    match res {
        Ok(dto) => json_status(StatusCode::OK, &dto),
        Err(resp) => *resp,
    }
}

fn parse_skin_str(raw: &str) -> Option<ConsoleSkinDto> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "html" => Some(ConsoleSkinDto::Html),
        "wireframe" => Some(ConsoleSkinDto::Wireframe),
        _ => None,
    }
}

fn parse_font_str(raw: &str) -> Option<CrtFontDto> {
    match raw.trim() {
        "Hurmit" | "hurmit" => Some(CrtFontDto::Hurmit),
        "OpenDyslexic" | "opendyslexic" | "open_dyslexic" => Some(CrtFontDto::OpenDyslexic),
        _ => None,
    }
}

// =========================================================================
// WebAuthn Passkey Management & Mandatory Enrollment (`#177`–`#179`)
// =========================================================================

/// `GET /api/auth/passkeys`
pub async fn list_passkeys(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (_, login_key) = match eval.require_bound_user(false) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    let profile = match read_auth(&state.job_store, |st| st.build_profile_dto(&login_key)) {
        Ok(Some(p)) => p,
        Ok(None) => return authorization_denied_response(),
        Err(resp) => return *resp,
    };

    json_status(
        StatusCode::OK,
        &json!({
            "github_login": profile.github_login,
            "passkey_count": profile.passkey_count,
            "passkey_enrollment_required": profile.passkey_count == 0,
            "passkeys": profile.passkeys,
        }),
    )
}

#[derive(Debug, Default, Deserialize)]
struct PasskeyRegisterStartPayload {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    step_up_proof_id: Option<String>,
    #[serde(default)]
    step_up_challenge_id: Option<String>,
    #[serde(default)]
    step_up_credential: Option<PublicKeyCredential>,
}

/// `POST /api/auth/passkeys/register/start` (and `/challenge`)
///
/// Free when `passkey_count == 0` (initial post-login gate); requires an existing Passkey
/// assertion (`step_up_proof_id` or inline `step_up_challenge_id` + `step_up_credential`)
/// whenever `passkey_count > 0` (`#178`).
pub async fn passkey_register_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Option<Json<Value>>,
) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (login, login_key) = match eval.require_bound_user(false) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    let raw_val = raw_body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let payload: PasskeyRegisterStartPayload = match serde_json::from_value(raw_val.clone()) {
        Ok(p) => p,
        Err(e) => return bad_request_response(&format!("Invalid JSON payload: {e}")),
    };
    let proof_id = payload
        .step_up_proof_id
        .or_else(|| extract_step_up_proof_id(&headers, None, Some(&raw_val)));

    let Ok(gh_login) = GithubLogin::new(login) else {
        return authorization_denied_response();
    };
    let svc = match build_webauthn_service(&state.config) {
        Ok(s) => s,
        Err(e) => return json_status(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "error": e })),
    };

    let now_ms = current_epoch_ms();
    let unique_id = webauthn_user_unique_id(&login_key);

    let outcome = mutate_auth(&state.job_store, |st| {
        st.prune_challenges(now_ms);
        if st.passkey_count_for(&login_key) > 0 {
            verify_and_consume_passkey_assertion_inline(
                st,
                &state.config,
                &gh_login,
                &login_key,
                proof_id.as_deref(),
                payload.step_up_challenge_id.as_deref(),
                payload.step_up_credential,
                StepUpPurpose::PasskeyManage,
                now_ms,
            )?;
        }

        let existing: Vec<_> = st
            .passkeys
            .get(&login_key)
            .map(|list| list.iter().map(|p| p.record.clone()).collect())
            .unwrap_or_default();

        let (challenge, pending) = svc
            .prepare_registration(&gh_login, &unique_id, &existing, now_ms)
            .map_err(|e| {
                Box::new(bad_request_response(&format!(
                    "Failed to prepare registration: {e}"
                )))
            })?;

        st.pending_registrations.insert(
            challenge.challenge_id.clone(),
            PendingRegistrationState {
                login_key: login_key.clone(),
                label: payload
                    .label
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string),
                expires_at_ms: challenge.expires_at_ms,
                pending,
            },
        );
        Ok(challenge)
    });

    match outcome {
        Ok(challenge) => json_status(StatusCode::OK, &challenge),
        Err(resp) => *resp,
    }
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterFinishPayload {
    challenge_id: String,
    #[serde(alias = "response", alias = "attestation")]
    credential: RegisterPublicKeyCredential,
    #[serde(default)]
    label: Option<String>,
}

/// `POST /api/auth/passkeys/register/finish` (and `/verify`)
pub async fn passkey_register_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyRegisterFinishPayload>,
) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (login, login_key) = match eval.require_bound_user(false) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    let Ok(gh_login) = GithubLogin::new(login.clone()) else {
        return authorization_denied_response();
    };
    let svc = match build_webauthn_service(&state.config) {
        Ok(s) => s,
        Err(e) => return json_status(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "error": e })),
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        st.prune_challenges(now_ms);
        let Some(pending) = st.pending_registrations.remove(&payload.challenge_id) else {
            return err_resp(auth_error_response(
                StatusCode::BAD_REQUEST,
                AuthReasonCodeDto::AuthenticationRequired,
                "Registration challenge not found or expired",
            ));
        };
        if pending.login_key != login_key || now_ms >= pending.expires_at_ms {
            return err_resp(auth_error_response(
                StatusCode::BAD_REQUEST,
                AuthReasonCodeDto::AuthenticationRequired,
                "Registration challenge expired or belongs to another operator",
            ));
        }
        let chosen_label = payload
            .label
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .or(pending.label);

        let record = svc
            .complete_registration(
                &gh_login,
                &pending.pending,
                &payload.credential,
                chosen_label.as_deref(),
                now_ms,
            )
            .map_err(|e| {
                Box::new(auth_error_response(
                    StatusCode::BAD_REQUEST,
                    AuthReasonCodeDto::AuthenticationRequired,
                    &format!("Passkey enrollment failed: {e}"),
                ))
            })?;

        let cred_id_b64 = encode_credential_id(record.credential_id.as_ref());
        let stored = StoredPasskeyRecord {
            credential_id: cred_id_b64.clone(),
            record,
            label: chosen_label,
            created_at_ms: now_ms,
            last_used_at_ms: None,
        };

        let list = st.passkeys.entry(login_key.clone()).or_default();
        if list
            .iter()
            .any(|existing| existing.credential_id == cred_id_b64)
        {
            return err_resp(conflict_response("Credential ID is already enrolled"));
        }
        list.push(stored);

        if let Some(u) = st.users.get_mut(&login_key) {
            u.last_seen_ms = Some(now_ms);
        }
        st.record_audit(
            &login,
            "passkey.enroll",
            Some(cred_id_b64.clone()),
            "ok",
            now_ms,
        );
        st.snapshot_revision = st.snapshot_revision.saturating_add(1);

        let cookie_ok = eval.cookie_valid_for_elevated;
        let (_, leases, eval) = st.evaluate_principal(Some(&login), cookie_ok, now_ms);
        let session = st.build_session_dto(Some(&login_key), &leases, &eval, now_ms);
        let passkey_count = st.passkey_count_for(&login_key);
        Ok((cred_id_b64, passkey_count, session))
    });

    match res {
        Ok((credential_id, passkey_count, session)) => json_status(
            StatusCode::OK,
            &json!({
                "enrolled": true,
                "credential_id": credential_id,
                "passkey_count": passkey_count,
                "passkey_enrollment_required": passkey_count == 0,
                "session": session,
            }),
        ),
        Err(resp) => *resp,
    }
}

/// `POST /api/auth/passkeys/assert/start` (and `/challenge`, `/manage/start`)
///
/// Issues a `PasskeyManage` assertion challenge so an enrolled user can verify an existing
/// Passkey before adding or deleting Passkeys (`#178`).
pub async fn passkey_assert_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (login, login_key) = match eval.require_bound_user(true) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };
    issue_step_up_challenge(
        &state,
        &login,
        &login_key,
        StepUpPurpose::PasskeyManage,
        None,
    )
}

#[derive(Debug, Deserialize)]
pub struct PasskeyAssertFinishPayload {
    challenge_id: String,
    #[serde(alias = "response", alias = "assertion")]
    credential: PublicKeyCredential,
}

/// `POST /api/auth/passkeys/assert/finish` (and `/manage/finish`)
pub async fn passkey_assert_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<PasskeyAssertFinishPayload>,
) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (login, login_key) = match eval.require_bound_user(true) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };
    let Ok(gh_login) = GithubLogin::new(login.clone()) else {
        return authorization_denied_response();
    };
    let svc = match build_webauthn_service(&state.config) {
        Ok(s) => s,
        Err(e) => return json_status(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "error": e })),
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        st.prune_challenges(now_ms);
        let Some(pending) = st.pending_authentications.remove(&payload.challenge_id) else {
            return err_resp(auth_error_response(
                StatusCode::UNAUTHORIZED,
                AuthReasonCodeDto::AuthenticationRequired,
                "Passkey challenge not found or expired",
            ));
        };
        if pending.login_key != login_key || now_ms >= pending.expires_at_ms {
            return err_resp(auth_error_response(
                StatusCode::UNAUTHORIZED,
                AuthReasonCodeDto::AuthenticationRequired,
                "Passkey challenge expired or belongs to another operator",
            ));
        }

        let creds: Vec<_> = st
            .passkeys
            .get(&login_key)
            .map(|rows| rows.iter().map(|r| r.record.clone()).collect())
            .unwrap_or_default();
        let outcome = svc
            .complete_authentication(
                &gh_login,
                &creds,
                &pending.pending,
                &payload.credential,
                now_ms,
            )
            .map_err(|err| Box::new(map_webauthn_failure(st, &login_key, &err, now_ms)))?;

        update_stored_passkey_after_auth(st, &login_key, &outcome, now_ms);

        let proof_id = Uuid::new_v4().to_string();
        let expires_at_ms = now_ms.saturating_add(STEP_UP_PROOF_TTL_MS);
        st.verified_step_up_proofs.insert(
            proof_id.clone(),
            VerifiedStepUpProof {
                login_key: login_key.clone(),
                purpose: pending.purpose,
                expires_at_ms,
            },
        );
        st.record_audit(&login, "passkey.assert", None, "ok", now_ms);

        Ok((proof_id, outcome.new_sign_count, expires_at_ms))
    });

    match res {
        Ok((step_up_proof_id, sign_count, expires_at_ms)) => json_status(
            StatusCode::OK,
            &json!({
                "verified": true,
                "step_up_proof_id": step_up_proof_id,
                "sign_count": sign_count,
                "expires_at_ms": expires_at_ms,
            }),
        ),
        Err(resp) => *resp,
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct DeletePasskeyQuery {
    #[serde(default)]
    pub step_up_proof_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct DeletePasskeyPayload {
    #[serde(default)]
    step_up_proof_id: Option<String>,
    #[serde(default, alias = "step_up_challenge_id")]
    challenge_id: Option<String>,
    #[serde(default, alias = "step_up_credential", alias = "response")]
    credential: Option<PublicKeyCredential>,
}

/// `DELETE /api/auth/passkeys/{credential_id}` and `POST /api/auth/passkeys/{credential_id}/delete`
///
/// Requires an existing Passkey assertion (`#178`). If deleting the final Passkey reduces count to `0`,
/// locks active elevated leases and immediately re-engages `passkey_enrollment_required`.
pub async fn delete_passkey(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(credential_id): Path<String>,
    Query(query): Query<DeletePasskeyQuery>,
    raw_body: Option<Json<Value>>,
) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (login, login_key) = match eval.require_bound_user(true) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    let raw_val = raw_body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let payload: DeletePasskeyPayload = match serde_json::from_value(raw_val.clone()) {
        Ok(p) => p,
        Err(e) => return bad_request_response(&format!("Invalid JSON payload: {e}")),
    };
    let proof_id = payload.step_up_proof_id.or_else(|| {
        extract_step_up_proof_id(&headers, query.step_up_proof_id.as_deref(), Some(&raw_val))
    });
    let Ok(gh_login) = GithubLogin::new(login.clone()) else {
        return authorization_denied_response();
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        verify_and_consume_passkey_assertion_inline(
            st,
            &state.config,
            &gh_login,
            &login_key,
            proof_id.as_deref(),
            payload.challenge_id.as_deref(),
            payload.credential,
            StepUpPurpose::PasskeyManage,
            now_ms,
        )?;

        let Some(list) = st.passkeys.get_mut(&login_key) else {
            return err_resp(not_found_response("Passkey credential not found"));
        };
        let Some(pos) = list.iter().position(|item| {
            item.credential_id == credential_id
                || encode_credential_id(item.record.credential_id.as_ref()) == credential_id
        }) else {
            return err_resp(not_found_response("Passkey credential not found"));
        };

        list.remove(pos);
        let remaining = u32::try_from(list.len()).unwrap_or(u32::MAX);
        if remaining == 0 {
            if let Some(leases) = st.role_leases.get_mut(&login_key) {
                leases.timed_leases.clear();
                leases.elective_roles.clear();
            }
            if let Some(u) = st.users.get_mut(&login_key) {
                u.elevation_epoch = u.elevation_epoch.saturating_add(1);
            }
        }
        st.record_audit(
            &login,
            "passkey.delete",
            Some(credential_id.clone()),
            "ok",
            now_ms,
        );
        st.snapshot_revision = st.snapshot_revision.saturating_add(1);
        Ok(remaining)
    });

    match res {
        Ok(remaining) => {
            let cookie = (remaining == 0).then(format_elevated_clear_cookie);
            json_status_with_cookie(
                StatusCode::OK,
                &json!({
                    "deleted": true,
                    "credential_id": credential_id,
                    "passkey_count": remaining,
                    "passkey_enrollment_required": remaining == 0,
                }),
                cookie.as_deref(),
            )
        }
        Err(resp) => *resp,
    }
}

// =========================================================================
// Elective & Timed Role Elevation, Step-Up, Lock-All & Activity (`#180`)
// =========================================================================

fn issue_step_up_challenge(
    state: &AppState,
    login: &str,
    login_key: &str,
    purpose: StepUpPurpose,
    role_id: Option<String>,
) -> Response {
    let Ok(gh_login) = GithubLogin::new(login) else {
        return authorization_denied_response();
    };
    let svc = match build_webauthn_service(&state.config) {
        Ok(s) => s,
        Err(e) => return json_status(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "error": e })),
    };

    if purpose == StepUpPurpose::ElevateRole {
        let target_role = role_id
            .as_deref()
            .unwrap_or(crate::auth::ADMIN_TIMED_ROLE_ID);
        if RoleId::new(target_role).is_err() {
            return bad_request_response("Invalid role_id");
        }
    }

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        st.prune_challenges(now_ms);
        if purpose == StepUpPurpose::ElevateRole {
            let target_role = role_id
                .as_deref()
                .unwrap_or(crate::auth::ADMIN_TIMED_ROLE_ID);
            let Ok(parsed_rid) = RoleId::new(target_role) else {
                return err_resp(bad_request_response("Invalid role_id"));
            };
            if st.role_catalog.get(&parsed_rid).is_none() {
                return err_resp(not_found_response(&format!("Unknown role '{target_role}'")));
            }
            let bound = st
                .user_roles
                .get(login_key)
                .is_some_and(|set| set.contains(&parsed_rid));
            if !bound {
                return err_resp(authorization_denied_response());
            }
        }

        let creds: Vec<_> = st
            .passkeys
            .get(login_key)
            .map(|list| list.iter().map(|p| p.record.clone()).collect())
            .unwrap_or_default();
        let (challenge, pending) = svc
            .prepare_authentication(&gh_login, &creds, now_ms)
            .map_err(|e| {
                Box::new(match e {
                    AuthError::Folio(fe) => map_folio_error(&fe),
                    other => bad_request_response(&format!("Failed to prepare challenge: {other}")),
                })
            })?;

        st.pending_authentications.insert(
            challenge.challenge_id.clone(),
            PendingAuthenticationState {
                login_key: login_key.to_string(),
                role_id,
                purpose,
                pending,
                expires_at_ms: challenge.expires_at_ms,
            },
        );
        Ok(challenge)
    });

    match res {
        Ok(challenge) => json_status(StatusCode::OK, &challenge),
        Err(resp) => *resp,
    }
}

/// `POST /api/auth/roles/{role_id}/enable`
pub async fn enable_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(role_id_raw): Path<String>,
    raw_body: Option<Json<Value>>,
) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (login, login_key) = match eval.require_bound_user(true) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    let raw_val = raw_body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    if payload_has_forbidden_ttl_fields(&raw_val) {
        return forbidden_ttl_override_response();
    }

    let Ok(parsed_rid) = RoleId::new(role_id_raw.trim()) else {
        return bad_request_response("Invalid role_id");
    };
    let proof_id = extract_step_up_proof_id(&headers, None, Some(&raw_val));
    let inline_challenge = raw_val
        .get("challenge_id")
        .or_else(|| raw_val.get("step_up_challenge_id"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let inline_cred: Option<PublicKeyCredential> = raw_val
        .get("credential")
        .or_else(|| raw_val.get("step_up_credential"))
        .or_else(|| raw_val.get("response"))
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    let Ok(gh_login) = GithubLogin::new(login.clone()) else {
        return authorization_denied_response();
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        st.prune_challenges(now_ms);
        let Some(spec) = st.role_catalog.get(&parsed_rid).cloned() else {
            return err_resp(not_found_response(&format!("Unknown role '{parsed_rid}'")));
        };
        if !st
            .user_roles
            .get(&login_key)
            .is_some_and(|set| set.contains(&parsed_rid))
        {
            return err_resp(authorization_denied_response());
        }

        let requires_step_up = matches!(spec.activation, RoleActivation::Timed { .. })
            || spec.step_up == StepUpRequirement::Passkey;

        let step_up_verified = if requires_step_up {
            verify_and_consume_passkey_assertion_inline(
                st,
                &state.config,
                &gh_login,
                &login_key,
                proof_id.as_deref(),
                inline_challenge.as_deref(),
                inline_cred,
                StepUpPurpose::ElevateRole,
                now_ms,
            )?;
            true
        } else {
            false
        };

        let (_, maybe_lease) =
            activate_server_role_lease(st, &login_key, &parsed_rid, step_up_verified, now_ms)
                .map_err(|(code, msg)| {
                    Box::new(auth_error_response(StatusCode::FORBIDDEN, code, &msg))
                })?;

        st.record_audit(
            &login,
            "role.enable",
            Some(parsed_rid.to_string()),
            "ok",
            now_ms,
        );
        st.snapshot_revision = st.snapshot_revision.saturating_add(1);

        let set_cookie = if let Some(lease) = maybe_lease {
            let epoch = st
                .users
                .get(&login_key)
                .map(|u| u.elevation_epoch)
                .unwrap_or(1);
            let max_exp =
                max_timed_expiry_for_user(st, &login_key).unwrap_or(lease.hard_expires_at_ms);
            let claims = ElevatedCookieClaims {
                login_key: login_key.clone(),
                epoch,
                issued_at_ms: now_ms,
                expires_at_ms: max_exp,
            };
            let token = sign_elevated_cookie(&state.config.elevation_signing_key(), &claims)
                .map_err(|e| {
                    Box::new(json_status(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &json!({ "error": e }),
                    ))
                })?;
            let max_age_secs = (max_exp.saturating_sub(now_ms) / 1000).max(1);
            Some(format_elevated_set_cookie(&token, max_age_secs))
        } else {
            None
        };

        let cookie_ok_after = set_cookie.is_some() || eval.cookie_valid_for_elevated;
        let (_, leases, eval_after) = st.evaluate_principal(Some(&login), cookie_ok_after, now_ms);
        let session = st.build_session_dto(Some(&login_key), &leases, &eval_after, now_ms);
        Ok((session, set_cookie))
    });

    match res {
        Ok((session, cookie)) => {
            json_status_with_cookie(StatusCode::OK, &session, cookie.as_deref())
        }
        Err(resp) => *resp,
    }
}

/// `POST /api/auth/roles/{role_id}/disable`
///
/// Rejects disabling any `PinnedBaseline` role (`403 pinned_baseline_immutable`, `#180`).
pub async fn disable_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(role_id_raw): Path<String>,
) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (login, login_key) = match eval.require_bound_user(true) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    let Ok(parsed_rid) = RoleId::new(role_id_raw.trim()) else {
        return bad_request_response("Invalid role_id");
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        let Some(spec) = st.role_catalog.get(&parsed_rid).cloned() else {
            return err_resp(not_found_response(&format!("Unknown role '{parsed_rid}'")));
        };
        if matches!(spec.activation, RoleActivation::PinnedBaseline) {
            return err_resp(auth_error_response(
                StatusCode::FORBIDDEN,
                AuthReasonCodeDto::PinnedBaselineImmutable,
                "Canonical PinnedBaseline role cannot be disabled",
            ));
        }
        let mut clear_cookie = false;
        let role_catalog = st.role_catalog.clone();
        if let Some(leases) = st.role_leases.get_mut(&login_key) {
            let _ = leases.disable_role(&role_catalog, &parsed_rid);
            if leases.timed_leases.is_empty() {
                if let Some(u) = st.users.get_mut(&login_key) {
                    u.elevation_epoch = u.elevation_epoch.saturating_add(1);
                }
                clear_cookie = true;
            }
        }
        st.record_audit(
            &login,
            "role.disable",
            Some(parsed_rid.to_string()),
            "ok",
            now_ms,
        );
        st.snapshot_revision = st.snapshot_revision.saturating_add(1);

        let cookie_ok_after = if clear_cookie {
            false
        } else {
            eval.cookie_valid_for_elevated
        };
        let (_, leases, eval_after) = st.evaluate_principal(Some(&login), cookie_ok_after, now_ms);
        let session = st.build_session_dto(Some(&login_key), &leases, &eval_after, now_ms);
        Ok((session, clear_cookie))
    });

    match res {
        Ok((session, clear_cookie)) => {
            let cookie = clear_cookie.then(format_elevated_clear_cookie);
            json_status_with_cookie(StatusCode::OK, &session, cookie.as_deref())
        }
        Err(resp) => *resp,
    }
}

#[derive(Debug, Default, Deserialize)]
struct ElevateStartPayload {
    #[serde(default)]
    role_id: Option<String>,
    #[serde(default)]
    purpose: Option<String>,
}

/// `POST /api/auth/elevate/start` (and `/challenge`)
pub async fn elevate_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Option<Json<Value>>,
) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (login, login_key) = match eval.require_bound_user(true) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    let raw_val = raw_body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    if payload_has_forbidden_ttl_fields(&raw_val) {
        return forbidden_ttl_override_response();
    }

    let payload: ElevateStartPayload = match serde_json::from_value(raw_val) {
        Ok(p) => p,
        Err(e) => return bad_request_response(&format!("Invalid JSON payload: {e}")),
    };
    let purpose = match payload.purpose.as_deref().map(str::trim) {
        Some("passkey_manage") => StepUpPurpose::PasskeyManage,
        _ => StepUpPurpose::ElevateRole,
    };
    let role_id = if purpose == StepUpPurpose::ElevateRole {
        Some(
            payload
                .role_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(crate::auth::ADMIN_TIMED_ROLE_ID)
                .to_string(),
        )
    } else {
        None
    };

    issue_step_up_challenge(&state, &login, &login_key, purpose, role_id)
}

#[derive(Debug, Deserialize)]
struct ElevateFinishPayload {
    challenge_id: String,
    #[serde(alias = "response", alias = "assertion")]
    credential: PublicKeyCredential,
    #[serde(default)]
    role_id: Option<String>,
}

/// `POST /api/auth/elevate/finish` (and `/verify`)
///
/// Verifies WebAuthn Passkey assertion (including 1Password `0 -> 0` and FIDO2 monotonic
/// `sign_count` clone detection), strictly rejects client-supplied TTL overrides, activates
/// the server-derived `RoleLease`, and mints a `__Host-mu_elevated` HMAC cookie (`#180`).
pub async fn elevate_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(raw_body): Json<Value>,
) -> Response {
    if payload_has_forbidden_ttl_fields(&raw_body) {
        return forbidden_ttl_override_response();
    }
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (login, login_key) = match eval.require_bound_user(true) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    let payload: ElevateFinishPayload = match serde_json::from_value(raw_body) {
        Ok(p) => p,
        Err(e) => return bad_request_response(&format!("Invalid JSON payload: {e}")),
    };
    if let Some(req_role) = payload
        .role_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if RoleId::new(req_role).is_err() {
            return bad_request_response("Invalid role_id");
        }
    }
    let Ok(gh_login) = GithubLogin::new(login.clone()) else {
        return authorization_denied_response();
    };
    let svc = match build_webauthn_service(&state.config) {
        Ok(s) => s,
        Err(e) => return json_status(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "error": e })),
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        st.prune_challenges(now_ms);
        let Some(pending) = st.pending_authentications.remove(&payload.challenge_id) else {
            return err_resp(auth_error_response(
                StatusCode::UNAUTHORIZED,
                AuthReasonCodeDto::AuthenticationRequired,
                "Step-up challenge not found or expired",
            ));
        };
        if pending.login_key != login_key || now_ms >= pending.expires_at_ms {
            return err_resp(auth_error_response(
                StatusCode::UNAUTHORIZED,
                AuthReasonCodeDto::AuthenticationRequired,
                "Step-up challenge expired or belongs to another operator",
            ));
        }

        let creds: Vec<_> = st
            .passkeys
            .get(&login_key)
            .map(|rows| rows.iter().map(|r| r.record.clone()).collect())
            .unwrap_or_default();

        let outcome = svc
            .complete_authentication(
                &gh_login,
                &creds,
                &pending.pending,
                &payload.credential,
                now_ms,
            )
            .map_err(|err| Box::new(map_webauthn_failure(st, &login_key, &err, now_ms)))?;

        update_stored_passkey_after_auth(st, &login_key, &outcome, now_ms);

        if pending.purpose == StepUpPurpose::PasskeyManage {
            let proof_id = Uuid::new_v4().to_string();
            let expires_at_ms = now_ms.saturating_add(STEP_UP_PROOF_TTL_MS);
            st.verified_step_up_proofs.insert(
                proof_id.clone(),
                VerifiedStepUpProof {
                    login_key: login_key.clone(),
                    purpose: StepUpPurpose::PasskeyManage,
                    expires_at_ms,
                },
            );
            st.record_audit(&login, "passkey.step_up.manage", None, "ok", now_ms);
            let (_, leases, eval_after) =
                st.evaluate_principal(Some(&login), eval.cookie_valid_for_elevated, now_ms);
            let session = st.build_session_dto(Some(&login_key), &leases, &eval_after, now_ms);
            return Ok((
                json!({
                    "verified": true,
                    "step_up_proof_id": proof_id,
                    "sign_count": outcome.new_sign_count,
                    "expires_at_ms": expires_at_ms,
                    "session": session,
                }),
                None,
            ));
        }

        let target_role_str = payload
            .role_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or(pending.role_id.as_deref())
            .unwrap_or(crate::auth::ADMIN_TIMED_ROLE_ID);

        let Ok(target_rid) = RoleId::new(target_role_str) else {
            return err_resp(bad_request_response("Invalid role_id"));
        };
        if let Some(pending_role) = pending.role_id.as_deref() {
            if pending_role != target_role_str {
                return err_resp(authorization_denied_response());
            }
        }
        let (_, maybe_lease) =
            activate_server_role_lease(st, &login_key, &target_rid, true, now_ms).map_err(
                |(code, msg)| Box::new(auth_error_response(StatusCode::FORBIDDEN, code, &msg)),
            )?;

        st.record_audit(
            &login,
            "role.elevate",
            Some(target_rid.to_string()),
            "ok",
            now_ms,
        );
        st.snapshot_revision = st.snapshot_revision.saturating_add(1);

        let epoch = st
            .users
            .get(&login_key)
            .map(|u| u.elevation_epoch)
            .unwrap_or(1);
        let max_exp = max_timed_expiry_for_user(st, &login_key)
            .or_else(|| maybe_lease.as_ref().map(|l| l.hard_expires_at_ms))
            .unwrap_or_else(|| now_ms.saturating_add(900_000));
        let claims = ElevatedCookieClaims {
            login_key: login_key.clone(),
            epoch,
            issued_at_ms: now_ms,
            expires_at_ms: max_exp,
        };
        let token =
            sign_elevated_cookie(&state.config.elevation_signing_key(), &claims).map_err(|e| {
                Box::new(json_status(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({ "error": e }),
                ))
            })?;
        let max_age_secs = (max_exp.saturating_sub(now_ms) / 1000).max(1);
        let set_cookie = format_elevated_set_cookie(&token, max_age_secs);

        let (_, leases, eval_after) = st.evaluate_principal(Some(&login), true, now_ms);
        let session = st.build_session_dto(Some(&login_key), &leases, &eval_after, now_ms);

        Ok((
            json!({
                "elevated": true,
                "role_id": target_rid.as_str(),
                "sign_count": outcome.new_sign_count,
                "leases": session.leases,
                "session": session,
            }),
            Some(set_cookie),
        ))
    });

    match res {
        Ok((body, cookie)) => json_status_with_cookie(StatusCode::OK, &body, cookie.as_deref()),
        Err(resp) => *resp,
    }
}

fn max_timed_expiry_for_user(st: &PlatformAuthState, login_key: &str) -> Option<u64> {
    st.role_leases.get(login_key).and_then(|leases| {
        leases
            .timed_leases
            .values()
            .map(|l| l.hard_expires_at_ms)
            .max()
    })
}

/// `POST /api/auth/elevate/lock-all` and `POST /api/auth/roles/lock`
///
/// Clears all active `Timed` leases on the caller's session, increments `elevation_epoch`
/// so all previously issued `__Host-mu_elevated` cookies immediately fail closed, and clears
/// the cookie (`Max-Age=0`).
pub async fn elevate_lock_all(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (login, login_key) = match eval.require_bound_user(true) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        if let Some(leases) = st.role_leases.get_mut(&login_key) {
            leases.timed_leases.clear();
        }
        if let Some(user) = st.users.get_mut(&login_key) {
            user.elevation_epoch = user.elevation_epoch.saturating_add(1);
        }
        st.record_audit(&login, "roles.lock_all", None, "ok", now_ms);
        st.snapshot_revision = st.snapshot_revision.saturating_add(1);
        let (_, leases, eval_after) = st.evaluate_principal(Some(&login), false, now_ms);
        Ok(st.build_session_dto(Some(&login_key), &leases, &eval_after, now_ms))
    });

    match res {
        Ok(session) => {
            let clear_cookie = format_elevated_clear_cookie();
            json_status_with_cookie(StatusCode::OK, &session, Some(&clear_cookie))
        }
        Err(resp) => *resp,
    }
}

/// `POST /api/auth/activity`
///
/// Records explicit operator interaction to reset active `Timed` role `idle_expires_at_ms`
/// (`min(hard_expires_at_ms, now_ms + idle_ttl_secs * 1000)`) without extending `hard_expires_at_ms`
/// or accepting client TTL parameters (`#180`).
pub async fn record_activity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Option<Json<Value>>,
) -> Response {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, &headers, None);
    let (login, login_key) = match eval.require_bound_user(true) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    if let Some(Json(val)) = raw_body {
        if payload_has_forbidden_ttl_fields(&val) {
            return forbidden_ttl_override_response();
        }
    }

    let now_ms = current_epoch_ms();
    let cookie_ok = eval.cookie_valid_for_elevated;
    let res = mutate_auth(&state.job_store, |st| {
        st.prune_user_leases(&login_key, now_ms);
        if cookie_ok {
            if let Some(leases) = st.role_leases.get_mut(&login_key) {
                let _ = leases.record_activity(now_ms);
            }
        }
        if let Some(user) = st.users.get_mut(&login_key) {
            user.last_seen_ms = Some(now_ms);
        }
        let (_, leases, eval_after) = st.evaluate_principal(Some(&login), cookie_ok, now_ms);
        Ok(st.build_session_dto(Some(&login_key), &leases, &eval_after, now_ms))
    });

    match res {
        Ok(session) => json_status(StatusCode::OK, &session),
        Err(resp) => *resp,
    }
}

// =========================================================================
// `folio:platform:admin` RBAC Catalogs, Users, Resets & Invites (`#173`–`#176`, `#179`)
// =========================================================================

fn require_platform_policy(
    state: &AppState,
    headers: &HeaderMap,
    policy: &str,
) -> AuthResult<(String, EvaluatedRequestAuth)> {
    let eval = EvaluatedRequestAuth::evaluate(&state.config, &state.job_store, headers, None);
    if let Some(denied) = eval.gate_policy(policy) {
        return err_resp(denied);
    }
    let actor = eval.login.clone().unwrap_or_else(|| "admin".to_string());
    Ok((actor, eval))
}

/// `GET /api/auth/folios`
pub async fn list_folios(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(denied) = require_platform_policy(&state, &headers, "platform:folios.read") {
        return *denied;
    }
    let res = read_auth(&state.job_store, |st| {
        (
            st.folio_catalog
                .folios()
                .cloned()
                .collect::<Vec<PolicyFolio>>(),
            st.folio_catalog
                .policies()
                .cloned()
                .collect::<Vec<Policy>>(),
        )
    });
    match res {
        Ok((folios, policies)) => json_status(
            StatusCode::OK,
            &json!({
                "folios": folios,
                "policies": policies,
            }),
        ),
        Err(resp) => *resp,
    }
}

#[derive(Debug, Deserialize)]
struct UpsertFolioPayload {
    id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    origin: Option<FolioOrigin>,
    #[serde(default)]
    owner_subsystem: Option<SubsystemId>,
    #[serde(default)]
    includes: Vec<String>,
    #[serde(default)]
    policies: Vec<String>,
}

/// `POST|PUT /api/auth/folios`
pub async fn upsert_folio(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(raw): Json<Value>,
) -> Response {
    upsert_folio_inner(&state, &headers, None, raw)
}

/// `PUT /api/auth/folios/{folio_id}`
pub async fn upsert_folio_by_id(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(folio_id): Path<String>,
    Json(raw): Json<Value>,
) -> Response {
    upsert_folio_inner(&state, &headers, Some(folio_id), raw)
}

fn upsert_folio_inner(
    state: &AppState,
    headers: &HeaderMap,
    path_id: Option<String>,
    raw: Value,
) -> Response {
    let (actor, _) = match require_platform_policy(state, headers, "platform:folios.write") {
        Ok(ok) => ok,
        Err(denied) => return *denied,
    };

    let mut val = raw;
    if let (Some(pid), Some(obj)) = (path_id.as_deref(), val.as_object_mut()) {
        if !obj.contains_key("id") {
            obj.insert("id".to_string(), Value::String(pid.to_string()));
        }
    }
    let payload: UpsertFolioPayload = match serde_json::from_value(val) {
        Ok(p) => p,
        Err(e) => return bad_request_response(&format!("Invalid PolicyFolio payload: {e}")),
    };
    if let Some(pid) = path_id.as_deref() {
        if payload.id != pid {
            return bad_request_response("Path folio_id does not match body id");
        }
    }

    let Ok(folio_id) = FolioId::new(payload.id.trim()) else {
        return bad_request_response("Invalid folio id");
    };
    if matches!(payload.origin, Some(FolioOrigin::Subsystem)) {
        return auth_error_response(
            StatusCode::FORBIDDEN,
            AuthReasonCodeDto::AuthorizationDenied,
            "Canonical Subsystem manifest folios are immutable",
        );
    }

    let mut includes = BTreeSet::new();
    for inc in &payload.includes {
        let Ok(fid_val) = FolioId::new(inc.trim()) else {
            return bad_request_response(&format!("Invalid included folio id '{inc}'"));
        };
        includes.insert(fid_val);
    }
    let mut policies = BTreeSet::new();
    for pol in &payload.policies {
        let Ok(pid_val) = mu_auth::PolicyId::new(pol.trim()) else {
            return bad_request_response(&format!("Invalid policy id '{pol}'"));
        };
        policies.insert(pid_val);
    }

    let display_name = payload
        .display_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| folio_id.to_string());
    let folio = PolicyFolio {
        id: folio_id.clone(),
        display_name,
        description: payload.description,
        origin: FolioOrigin::Operator,
        owner_subsystem: payload.owner_subsystem,
        includes,
        policies,
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        let mut candidate = st.clone();
        candidate
            .folio_catalog
            .upsert_operator_folio(folio.clone())
            .map_err(|e| Box::new(map_folio_error(&e)))?;
        candidate
            .role_folio_index
            .validate(&candidate.folio_catalog, Some(&candidate.role_catalog))
            .map_err(|e| Box::new(map_folio_error(&e)))?;
        if !candidate.has_active_platform_admin() {
            return err_resp(conflict_response(
                "Last-admin lockout guard: change would eliminate active platform-admin capacity",
            ));
        }
        candidate.record_audit(
            &actor,
            "folio.upsert",
            Some(folio_id.to_string()),
            "ok",
            now_ms,
        );
        candidate.snapshot_revision = candidate.snapshot_revision.saturating_add(1);
        *st = candidate;
        Ok(folio)
    });

    match res {
        Ok(saved) => json_status(StatusCode::OK, &saved),
        Err(resp) => *resp,
    }
}

/// `DELETE /api/auth/folios/{folio_id}`
pub async fn delete_folio(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(folio_id_raw): Path<String>,
) -> Response {
    let (actor, _) = match require_platform_policy(&state, &headers, "platform:folios.write") {
        Ok(ok) => ok,
        Err(denied) => return *denied,
    };
    let Ok(folio_id) = FolioId::new(folio_id_raw.trim()) else {
        return bad_request_response("Invalid folio_id");
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        let mut candidate = st.clone();
        let referenced_in_index = candidate
            .role_folio_index
            .anonymous_folios()
            .contains(&folio_id)
            || candidate.role_catalog.iter().any(|r| {
                candidate
                    .role_folio_index
                    .folios_for_role(&r.id)
                    .is_some_and(|set| set.contains(&folio_id))
            });
        if referenced_in_index {
            return err_resp(conflict_response(
                "Cannot delete PolicyFolio while still referenced in RoleFolioIndex",
            ));
        }
        candidate
            .folio_catalog
            .remove_operator_folio(&folio_id)
            .map_err(|e| Box::new(map_folio_error(&e)))?;
        if !candidate.has_active_platform_admin() {
            return err_resp(conflict_response(
                "Last-admin lockout guard: change would eliminate active platform-admin capacity",
            ));
        }
        candidate.record_audit(
            &actor,
            "folio.delete",
            Some(folio_id.to_string()),
            "ok",
            now_ms,
        );
        candidate.snapshot_revision = candidate.snapshot_revision.saturating_add(1);
        *st = candidate;
        Ok(())
    });

    match res {
        Ok(()) => json_status(
            StatusCode::OK,
            &json!({ "deleted": true, "folio_id": folio_id_raw }),
        ),
        Err(resp) => *resp,
    }
}

/// `GET /api/auth/roles`
pub async fn list_roles(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(denied) = require_platform_policy(&state, &headers, "platform:roles.read") {
        return *denied;
    }
    match read_auth(&state.job_store, |st| {
        st.role_catalog.iter().cloned().collect::<Vec<RoleSpec>>()
    }) {
        Ok(roles) => json_status(StatusCode::OK, &json!({ "roles": roles })),
        Err(resp) => *resp,
    }
}

/// `POST|PUT /api/auth/roles`
pub async fn upsert_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(raw): Json<Value>,
) -> Response {
    upsert_role_inner(&state, &headers, None, raw)
}

/// `PUT /api/auth/roles/{role_id}`
pub async fn upsert_role_by_id(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(role_id): Path<String>,
    Json(raw): Json<Value>,
) -> Response {
    upsert_role_inner(&state, &headers, Some(role_id), raw)
}

fn upsert_role_inner(
    state: &AppState,
    headers: &HeaderMap,
    path_id: Option<String>,
    mut raw: Value,
) -> Response {
    let (actor, _) = match require_platform_policy(state, headers, "platform:roles.write") {
        Ok(ok) => ok,
        Err(denied) => return *denied,
    };

    if let (Some(pid), Some(obj)) = (path_id.as_deref(), raw.as_object_mut()) {
        if !obj.contains_key("id") {
            obj.insert("id".to_string(), Value::String(pid.to_string()));
        }
    }
    let spec: RoleSpec = match serde_json::from_value(raw) {
        Ok(s) => s,
        Err(e) => return bad_request_response(&format!("Invalid RoleSpec payload: {e}")),
    };
    if let Some(pid) = path_id.as_deref() {
        if spec.id.as_str() != pid {
            return bad_request_response("Path role_id does not match body id");
        }
    }

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        let mut candidate = st.clone();
        let existing_is_baseline = candidate
            .role_catalog
            .get(&spec.id)
            .is_some_and(|r| matches!(r.activation, RoleActivation::PinnedBaseline));
        if existing_is_baseline && !matches!(spec.activation, RoleActivation::PinnedBaseline) {
            return err_resp(auth_error_response(
                StatusCode::FORBIDDEN,
                AuthReasonCodeDto::PinnedBaselineImmutable,
                "Cannot change activation kind of canonical PinnedBaseline role",
            ));
        }
        candidate
            .role_catalog
            .upsert_role(spec.clone())
            .map_err(|e| Box::new(map_folio_error(&e)))?;
        candidate
            .role_folio_index
            .validate(&candidate.folio_catalog, Some(&candidate.role_catalog))
            .map_err(|e| Box::new(map_folio_error(&e)))?;
        if !candidate.has_active_platform_admin() {
            return err_resp(conflict_response(
                "Last-admin lockout guard: change would eliminate active platform-admin capacity",
            ));
        }
        candidate.record_audit(
            &actor,
            "role.upsert",
            Some(spec.id.to_string()),
            "ok",
            now_ms,
        );
        candidate.snapshot_revision = candidate.snapshot_revision.saturating_add(1);
        *st = candidate;
        Ok(spec)
    });

    match res {
        Ok(saved) => json_status(StatusCode::OK, &saved),
        Err(resp) => *resp,
    }
}

/// `DELETE /api/auth/roles/{role_id}`
pub async fn delete_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(role_id_raw): Path<String>,
) -> Response {
    let (actor, _) = match require_platform_policy(&state, &headers, "platform:roles.write") {
        Ok(ok) => ok,
        Err(denied) => return *denied,
    };
    let Ok(role_id) = RoleId::new(role_id_raw.trim()) else {
        return bad_request_response("Invalid role_id");
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        let mut candidate = st.clone();
        candidate
            .role_catalog
            .remove_role(&role_id)
            .map_err(|e| Box::new(map_folio_error(&e)))?;
        let _ = candidate.role_folio_index.clear_role(&role_id);
        for assigned in candidate.user_roles.values_mut() {
            assigned.remove(&role_id);
        }
        let catalog_snapshot = candidate.role_catalog.clone();
        for leases in candidate.role_leases.values_mut() {
            let _ = leases.disable_role(&catalog_snapshot, &role_id);
        }
        if !candidate.has_active_platform_admin() {
            return err_resp(conflict_response(
                "Last-admin lockout guard: deleting this role would eliminate platform-admin capacity",
            ));
        }
        candidate.record_audit(
            &actor,
            "role.delete",
            Some(role_id.to_string()),
            "ok",
            now_ms,
        );
        candidate.snapshot_revision = candidate.snapshot_revision.saturating_add(1);
        *st = candidate;
        Ok(())
    });

    match res {
        Ok(()) => json_status(
            StatusCode::OK,
            &json!({ "deleted": true, "role_id": role_id_raw }),
        ),
        Err(resp) => *resp,
    }
}

fn role_folio_index_json(index: &mu_auth::RoleFolioIndex, anon_lockdown: bool) -> Value {
    let mut val = serde_json::to_value(index).unwrap_or_else(|_| json!({}));
    if let Some(obj) = val.as_object_mut() {
        obj.insert("anonymous_lockdown".to_string(), Value::Bool(anon_lockdown));
        obj.insert(
            "anonymous_login_only".to_string(),
            Value::Bool(anon_lockdown),
        );
    }
    val
}

/// `GET /api/auth/role-folio-index`
pub async fn get_role_folio_index(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(denied) = require_platform_policy(&state, &headers, "platform:roles.read") {
        return *denied;
    }
    match read_auth(&state.job_store, |st| {
        role_folio_index_json(&st.role_folio_index, st.is_anonymous_lockdown())
    }) {
        Ok(val) => json_status(StatusCode::OK, &val),
        Err(resp) => *resp,
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct UpdateRoleFolioIndexPayload {
    #[serde(default)]
    anonymous: Option<Vec<String>>,
    #[serde(default)]
    role_folios: Option<BTreeMap<String, Vec<String>>>,
}

/// `PUT|POST /api/auth/role-folio-index`
///
/// Updates `anonymous` (e.g., `[]` to enable anonymous login-only lockdown) and/or role-to-folio
/// assignments atomically with last-admin lockout protection (`#174`, `#176`).
pub async fn put_role_folio_index(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<UpdateRoleFolioIndexPayload>,
) -> Response {
    let (actor, _) = match require_platform_policy(&state, &headers, "platform:roles.write") {
        Ok(ok) => ok,
        Err(denied) => return *denied,
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        let mut candidate = st.clone();

        if let Some(anon_list) = &payload.anonymous {
            let mut fids = BTreeSet::new();
            for raw_fid in anon_list {
                let parsed = FolioId::new(raw_fid.trim()).map_err(|e| {
                    Box::new(bad_request_response(&format!(
                        "Invalid folio id '{raw_fid}': {e}"
                    )))
                })?;
                fids.insert(parsed);
            }
            candidate
                .role_folio_index
                .set_anonymous_folios(fids, &candidate.folio_catalog)
                .map_err(|e| Box::new(map_folio_error(&e)))?;
        }

        if let Some(map) = &payload.role_folios {
            for (raw_rid, folio_list) in map {
                let role_id = RoleId::new(raw_rid.trim()).map_err(|e| {
                    Box::new(bad_request_response(&format!(
                        "Invalid role id '{raw_rid}': {e}"
                    )))
                })?;
                let mut fids = BTreeSet::new();
                for raw_fid in folio_list {
                    let parsed = FolioId::new(raw_fid.trim()).map_err(|e| {
                        Box::new(bad_request_response(&format!(
                            "Invalid folio id '{raw_fid}': {e}"
                        )))
                    })?;
                    fids.insert(parsed);
                }
                candidate
                    .role_folio_index
                    .set_role_folios(
                        role_id,
                        fids,
                        &candidate.folio_catalog,
                        &candidate.role_catalog,
                    )
                    .map_err(|e| Box::new(map_folio_error(&e)))?;
            }
        }

        if !candidate.has_active_platform_admin() {
            return err_resp(conflict_response(
                "Last-admin lockout guard: update would eliminate active platform-admin capacity",
            ));
        }

        candidate.record_audit(&actor, "role_folio_index.update", None, "ok", now_ms);
        candidate.snapshot_revision = candidate.snapshot_revision.saturating_add(1);
        *st = candidate;
        Ok(role_folio_index_json(
            &st.role_folio_index,
            st.is_anonymous_lockdown(),
        ))
    });

    match res {
        Ok(val) => json_status(StatusCode::OK, &val),
        Err(resp) => *resp,
    }
}

/// `GET /api/auth/users`
pub async fn list_users(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(denied) = require_platform_policy(&state, &headers, "platform:users.read") {
        return *denied;
    }
    match read_auth(&state.job_store, PlatformAuthState::build_platform_users) {
        Ok(users) => json_status(StatusCode::OK, &json!({ "users": users })),
        Err(resp) => *resp,
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct SetUserRolesPayload {
    #[serde(default, alias = "roles")]
    bound_roles: Vec<String>,
}

/// `PUT|POST /api/auth/users/{github_login}/roles`
///
/// Promotes or demotes a bound user's role bindings (`PinnedBaseline` must remain present;
/// last-admin lockout guard blocks removing the final active admin's `platform-admin` rights).
pub async fn set_user_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(github_login): Path<String>,
    Json(payload): Json<SetUserRolesPayload>,
) -> Response {
    let (actor, _) = match require_platform_policy(&state, &headers, "platform:users.write") {
        Ok(ok) => ok,
        Err(denied) => return *denied,
    };
    let Some(target_key) = normalize_login(&github_login) else {
        return bad_request_response("Invalid github_login");
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        let mut candidate = st.clone();
        if !candidate.users.get(&target_key).is_some_and(|u| !u.revoked) {
            return err_resp(not_found_response("Bound user not found or revoked"));
        }

        let baseline = candidate.baseline_role_id().clone();
        let mut requested = BTreeSet::new();
        for raw_rid in &payload.bound_roles {
            let role_id = RoleId::new(raw_rid.trim()).map_err(|e| {
                Box::new(bad_request_response(&format!(
                    "Invalid role_id '{raw_rid}': {e}"
                )))
            })?;
            if candidate.role_catalog.get(&role_id).is_none() {
                return err_resp(not_found_response(&format!("Unknown role '{role_id}'")));
            }
            requested.insert(role_id);
        }
        if !requested.contains(&baseline) {
            return err_resp(auth_error_response(
                StatusCode::FORBIDDEN,
                AuthReasonCodeDto::PinnedBaselineImmutable,
                "Canonical PinnedBaseline role binding cannot be removed",
            ));
        }

        candidate
            .user_roles
            .insert(target_key.clone(), requested.clone());
        if let Some(leases) = candidate.role_leases.get_mut(&target_key) {
            leases.elective_roles.retain(|r| requested.contains(r));
            leases.timed_leases.retain(|r, _| requested.contains(r));
        }
        if !candidate.has_active_platform_admin() {
            return err_resp(conflict_response(
                "Last-admin lockout guard: cannot remove platform-admin from the final active administrator",
            ));
        }
        candidate.record_audit(
            &actor,
            "user.roles.update",
            Some(target_key.clone()),
            "ok",
            now_ms,
        );
        candidate.snapshot_revision = candidate.snapshot_revision.saturating_add(1);
        *st = candidate;

        st.build_platform_users()
            .into_iter()
            .find(|u| u.github_login.eq_ignore_ascii_case(&target_key))
            .ok_or_else(|| Box::new(not_found_response("User missing after role update")))
    });

    match res {
        Ok(dto) => json_status(StatusCode::OK, &dto),
        Err(resp) => *resp,
    }
}

/// `DELETE /api/auth/users/{github_login}`
///
/// Revokes a bound user, subject to the `#175` last-admin lockout guard.
pub async fn revoke_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(github_login): Path<String>,
) -> Response {
    let (actor, _) = match require_platform_policy(&state, &headers, "platform:users.write") {
        Ok(ok) => ok,
        Err(denied) => return *denied,
    };
    let Some(target_key) = normalize_login(&github_login) else {
        return bad_request_response("Invalid github_login");
    };

    let now = Utc::now();
    let now_ms = datetime_to_epoch_ms(now);
    let res = mutate_auth(&state.job_store, |st| {
        let mut candidate = st.clone();
        let Some(user) = candidate.users.get_mut(&target_key) else {
            return err_resp(not_found_response("Bound user not found"));
        };
        if user.revoked {
            return Ok(user.github_login.clone());
        }
        let canonical = user.github_login.clone();
        user.revoked = true;
        user.revoked_at = Some(now.to_rfc3339());
        user.elevation_epoch = user.elevation_epoch.saturating_add(1);
        candidate.user_roles.remove(&target_key);
        candidate.role_leases.remove(&target_key);
        candidate.passkeys.remove(&target_key);

        if !candidate.has_active_platform_admin() {
            return err_resp(conflict_response(
                "Last-admin lockout guard: cannot revoke the final active platform administrator",
            ));
        }

        candidate.record_audit(&actor, "user.revoke", Some(canonical.clone()), "ok", now_ms);
        candidate.snapshot_revision = candidate.snapshot_revision.saturating_add(1);
        *st = candidate;
        Ok(canonical)
    });

    match res {
        Ok(login) => json_status(
            StatusCode::OK,
            &json!({
                "revoked": true,
                "github_login": login,
            }),
        ),
        Err(resp) => *resp,
    }
}

/// `DELETE /api/auth/users/{github_login}/passkeys` and `POST|DELETE /api/auth/users/{github_login}/passkeys/reset`
///
/// Clears all enrolled Passkeys for an account back to `0` (`#179`), invalidates active elevated
/// leases/cookies, and restores the mandatory post-login Passkey enrollment gate.
pub async fn admin_reset_user_passkeys(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(github_login): Path<String>,
) -> Response {
    let (actor, _) = match require_platform_policy(&state, &headers, "platform:users.write") {
        Ok(ok) => ok,
        Err(denied) => return *denied,
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        st.reset_user_passkeys(&github_login, &actor, now_ms)
            .map_err(|msg| Box::new(not_found_response(&msg)))
    });

    match res {
        Ok(removed_count) => json_status(
            StatusCode::OK,
            &json!({
                "reset": true,
                "github_login": github_login.trim(),
                "removed_count": removed_count,
                "passkey_count": 0,
                "passkey_enrollment_required": true,
            }),
        ),
        Err(resp) => *resp,
    }
}

#[derive(Debug, Default, Deserialize)]
struct CreateInvitePayload {
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
}

/// `POST /api/auth/invites`
///
/// Issues a single-use signed onboarding token granting exclusively `PinnedBaseline` (`"operator"`).
pub async fn create_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    raw_body: Option<Json<Value>>,
) -> Response {
    let (actor, _) = match require_platform_policy(&state, &headers, "platform:invites.write") {
        Ok(ok) => ok,
        Err(denied) => return *denied,
    };

    let raw_val = raw_body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    if let Some(obj) = raw_val.as_object() {
        if obj.contains_key("role")
            || obj.contains_key("roles")
            || obj.contains_key("roles_json")
            || obj.contains_key("granted_role")
        {
            return bad_request_response(
                "Invites bind exclusively to canonical PinnedBaseline role 'operator'; assign extra roles after enrollment",
            );
        }
    }
    let payload: CreateInvitePayload = match serde_json::from_value(raw_val) {
        Ok(p) => p,
        Err(e) => return bad_request_response(&format!("Invalid JSON payload: {e}")),
    };

    let Some(signing_key) = state
        .config
        .invite_signing_key
        .as_deref()
        .filter(|s| !s.is_empty())
    else {
        return json_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({ "error": "ACTION_RUNNER_INVITE_SIGNING_KEY is not configured" }),
        );
    };

    let ttl_secs = payload
        .ttl_seconds
        .unwrap_or(DEFAULT_INVITE_TTL_SECS)
        .min(MAX_INVITE_TTL_SECS);
    let invite_id = Uuid::new_v4().simple().to_string()[..16].to_string();

    let now = Utc::now();
    let expires_at = now + ChronoDuration::seconds(i64::try_from(ttl_secs).unwrap_or(86_400));
    let created_at_ms = datetime_to_epoch_ms(now);
    let expires_at_ms = datetime_to_epoch_ms(expires_at);
    let note = payload
        .note
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let sign_outcome = mutate_auth(&state.job_store, |st| {
        let (raw_token, token_hmac) =
            sign_baseline_invite_token(signing_key, &invite_id, expires_at_ms, &st.role_catalog)
                .map_err(|e| {
                    Box::new(json_status(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &json!({ "error": e }),
                    ))
                })?;

        st.invites.insert(
            invite_id.clone(),
            PlatformInviteRecord {
                invite_id: invite_id.clone(),
                token_hmac,
                created_by: actor.clone(),
                note: note.clone(),
                created_at: now.to_rfc3339(),
                created_at_ms,
                expires_at: expires_at.to_rfc3339(),
                expires_at_ms,
                used_by_github_login: None,
                used_at: None,
                used_at_ms: None,
                revoked: false,
            },
        );
        st.record_audit(
            &actor,
            "invite.create",
            Some(invite_id.clone()),
            "ok",
            created_at_ms,
        );
        st.snapshot_revision = st.snapshot_revision.saturating_add(1);
        Ok((raw_token, st.baseline_role_id().to_string()))
    });

    let (raw_token, baseline_role) = match sign_outcome {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    let base_url = payload
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("https://console.lma1980.duckdns.org");
    let invite_url = format!("{}/#redeem={}", base_url.trim_end_matches('/'), raw_token);

    json_status(
        StatusCode::CREATED,
        &json!({
            "invite_id": invite_id,
            "invite_token": raw_token,
            "token": raw_token,
            "invite_url": invite_url,
            "url": invite_url,
            "granted_role": baseline_role,
            "note": note,
            "created_by": actor,
            "expires_at": expires_at.to_rfc3339(),
            "expires_at_ms": expires_at_ms,
        }),
    )
}

/// `GET /api/auth/invites`
pub async fn list_invites(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(denied) = require_platform_policy(&state, &headers, "platform:invites.read") {
        return *denied;
    }

    let res = read_auth(&state.job_store, |st| {
        let baseline = st.baseline_role_id().to_string();
        let invs: Vec<Value> = st
            .invites
            .values()
            .map(|inv| {
                json!({
                    "invite_id": inv.invite_id,
                    "granted_role": baseline,
                    "created_by": inv.created_by,
                    "note": inv.note,
                    "created_at": inv.created_at,
                    "created_at_ms": inv.created_at_ms,
                    "expires_at": inv.expires_at,
                    "expires_at_ms": inv.expires_at_ms,
                    "used_by_github_login": inv.used_by_github_login,
                    "redeemed_by": inv.used_by_github_login,
                    "used_at": inv.used_at,
                    "redeemed_at_ms": inv.used_at_ms,
                    "revoked": inv.revoked,
                })
            })
            .collect();
        let users = st.build_platform_users();
        (invs, users)
    });

    match res {
        Ok((invites, users)) => json_status(
            StatusCode::OK,
            &json!({
                "invites": invites,
                "users": users,
            }),
        ),
        Err(resp) => *resp,
    }
}

/// `DELETE /api/auth/invites/{invite_id}`
pub async fn revoke_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(invite_id): Path<String>,
) -> Response {
    let (actor, _) = match require_platform_policy(&state, &headers, "platform:invites.write") {
        Ok(ok) => ok,
        Err(denied) => return *denied,
    };

    let now_ms = current_epoch_ms();
    let res = mutate_auth(&state.job_store, |st| {
        let Some(inv) = st.invites.get_mut(&invite_id) else {
            return err_resp(not_found_response("Invite not found"));
        };
        inv.revoked = true;
        st.record_audit(
            &actor,
            "invite.revoke",
            Some(invite_id.clone()),
            "ok",
            now_ms,
        );
        st.snapshot_revision = st.snapshot_revision.saturating_add(1);
        Ok(())
    });

    match res {
        Ok(()) => json_status(
            StatusCode::OK,
            &json!({ "revoked": true, "invite_id": invite_id }),
        ),
        Err(resp) => *resp,
    }
}

// =========================================================================
// Internal Auth Snapshot Feed for Sibling Daemons (`#176`)
// =========================================================================

fn is_authorized_internal_snapshot_caller(
    config: &Config,
    job_store: &JobStore,
    headers: &HeaderMap,
) -> AuthResult<()> {
    if has_valid_admin_api_key(config, headers, None) {
        return Ok(());
    }
    let eval = EvaluatedRequestAuth::evaluate(config, job_store, headers, None);
    if eval.is_platform_admin() {
        return Ok(());
    }
    if eval.is_uninvited {
        return err_resp(authorization_denied_response());
    }
    if eval.passkey_enrollment_required {
        return err_resp(passkey_enrollment_required_response());
    }
    if eval.invite_bound {
        return err_resp(authorization_denied_response());
    }
    err_resp(authentication_required_response())
}

/// `GET /api/internal/auth/snapshot`
///
/// Serves canonical RBAC snapshot with `ETag` (`"rev-{N}"`) and `304 Not Modified` on matching
/// `If-None-Match` for downstream daemons (`mu-cd-controller`, `mu-ab-controller`, `mu-regist`).
pub async fn internal_auth_snapshot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(denied) =
        is_authorized_internal_snapshot_caller(&state.config, &state.job_store, &headers)
    {
        return *denied;
    }

    let (etag, snapshot_json) = match read_auth(&state.job_store, |st| {
        (st.etag(), st.build_internal_snapshot_json())
    }) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };

    if let Some(inm) = headers
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
    {
        let matched = inm == etag || inm.trim_matches('"') == etag.trim_matches('"');
        if matched {
            return Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(ETAG, etag)
                .header(CACHE_CONTROL, "no-cache")
                .body(axum::body::Body::empty())
                .unwrap_or_else(|_| StatusCode::NOT_MODIFIED.into_response());
        }
    }

    let body = serde_json::to_string(&snapshot_json).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(ETAG, etag)
        .header(CACHE_CONTROL, "no-cache")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
