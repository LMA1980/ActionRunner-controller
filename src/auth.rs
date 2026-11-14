//! Platform Auth Authority backed by `mu-auth`: folio catalog, canonical single
//! `PinnedBaseline` role model, operator composite folios, single-`PinnedBaseline`
//! invites, persistent WebAuthn Passkeys, user preferences, timed role leases,
//! HMAC-signed `__Host-mu_elevated` cookies, and last-admin lockout protection.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use mu_auth::{
    evaluate_session, validate_display_name, EdgeAuthConfig, FolioCatalog, FolioId,
    GithubEdgeAuthAdapter, GithubLogin, InviteCodec, PasskeyRecord, PendingAuthentication,
    PendingRegistration, Policy, PolicyFolio, Principal, RoleActivation, RoleCatalog,
    RoleFolioIndex, RoleId, RoleLeases, RoleSpec, SessionEvaluation, StepUpRequirement,
    WebauthnConfig, WebauthnPasskeyService, DEFAULT_WEBAUTHN_CHALLENGE_TTL_SECS,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub const BASELINE_ROLE_ID: &str = "operator";
pub const ELECTIVE_CI_ROLE_ID: &str = "ci-operator";
pub const ADMIN_TIMED_ROLE_ID: &str = "platform-admin";
pub const DEFAULT_ADMIN_HARD_TTL_SECS: u64 = 900;
pub const DEFAULT_ADMIN_IDLE_TTL_SECS: u64 = 300;
pub const ELEVATED_COOKIE_NAME: &str = "__Host-mu_elevated";
pub const STEP_UP_PROOF_TTL_MS: u64 = 120_000;
pub const MAX_AUDIT_ENTRIES: usize = 256;

/// Default canonical anonymous folios seeded once on fresh initialization (`#173`).
pub const DEFAULT_ANONYMOUS_FOLIOS: [&str; 2] = ["folio:system:status", "folio:ci:anon-queue"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleSkinDto {
    #[default]
    Html,
    Wireframe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CrtFontDto {
    #[default]
    Hurmit,
    OpenDyslexic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UserPreferencesDto {
    #[serde(default)]
    pub skin: ConsoleSkinDto,
    #[serde(default)]
    pub font: CrtFontDto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthReasonCodeDto {
    AuthenticationRequired,
    AuthorizationDenied,
    PasskeyEnrollmentRequired,
    StepUpRequired,
    LeaseExpired,
    SubsystemDisabled,
    PinnedBaselineImmutable,
    CeilingExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleLeaseViewDto {
    pub role_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub activated_at_ms: u64,
    pub last_activity_at_ms: u64,
    pub hard_expires_at_ms: u64,
    pub idle_expires_at_ms: u64,
    pub hard_ttl_secs: u64,
    pub idle_ttl_secs: u64,
    pub seconds_remaining: u64,
    pub idle_timer: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeySummaryDto {
    pub credential_id: String,
    #[serde(default)]
    pub label: Option<String>,
    pub sign_count: u32,
    pub created_at_ms: u64,
    #[serde(default)]
    pub last_used_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserProfileDto {
    pub github_login: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub preferences: UserPreferencesDto,
    pub bound_roles: Vec<String>,
    pub passkeys: Vec<PasskeySummaryDto>,
    pub passkey_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformUserDto {
    pub github_login: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub bound_roles: Vec<String>,
    pub passkey_count: u32,
    #[serde(default)]
    pub last_seen_ms: Option<u64>,
    pub is_platform_admin: bool,
    pub invited_by: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditActivityEntryDto {
    pub timestamp_ms: u64,
    pub actor: String,
    pub action: String,
    #[serde(default)]
    pub target: Option<String>,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSessionDto {
    pub authenticated: bool,
    #[serde(default)]
    pub github_login: Option<String>,
    pub invite_bound: bool,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub reason_code: Option<AuthReasonCodeDto>,
    pub passkey_count: u32,
    pub passkey_enrollment_required: bool,
    pub anonymous_lockdown: bool,
    pub anonymous_login_only: bool,
    #[serde(default)]
    pub baseline_role: Option<String>,
    pub bound_roles: Vec<String>,
    pub active_roles: Vec<RoleSpec>,
    pub leases: Vec<RoleLeaseViewDto>,
    pub active_folios: Vec<String>,
    pub active_policies: Vec<String>,
    #[serde(default)]
    pub preferences: Option<UserPreferencesDto>,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Persisted bound user row in `auth_users`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformUserRecord {
    pub github_login: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub invited_by: String,
    #[serde(default)]
    pub invite_id: Option<String>,
    pub bound_at: String,
    #[serde(default)]
    pub bound_at_ms: u64,
    #[serde(default)]
    pub last_seen_ms: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub elevation_epoch: u64,
}

/// Persisted WebAuthn Passkey row in `auth_passkeys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPasskeyRecord {
    pub credential_id: String,
    pub record: PasskeyRecord,
    #[serde(default)]
    pub label: Option<String>,
    pub created_at_ms: u64,
    #[serde(default)]
    pub last_used_at_ms: Option<u64>,
}

/// Persisted single-`PinnedBaseline` invite row in `auth_invites`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformInviteRecord {
    pub invite_id: String,
    pub token_hmac: String,
    pub created_by: String,
    #[serde(default)]
    pub note: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub created_at_ms: u64,
    pub expires_at: String,
    #[serde(default)]
    pub expires_at_ms: u64,
    #[serde(default)]
    pub used_by_github_login: Option<String>,
    #[serde(default)]
    pub used_at: Option<String>,
    #[serde(default)]
    pub used_at_ms: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpPurpose {
    ElevateRole,
    PasskeyManage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRegistrationState {
    pub login_key: String,
    pub label: Option<String>,
    pub pending: PendingRegistration,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAuthenticationState {
    pub login_key: String,
    pub role_id: Option<String>,
    pub purpose: StepUpPurpose,
    pub pending: PendingAuthentication,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedStepUpProof {
    pub login_key: String,
    pub purpose: StepUpPurpose,
    pub expires_at_ms: u64,
}

/// Persistent Platform Auth & Policy Folio authority state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformAuthState {
    pub initialized: bool,
    pub folio_catalog: FolioCatalog,
    pub role_catalog: RoleCatalog,
    pub role_folio_index: RoleFolioIndex,
    pub users: BTreeMap<String, PlatformUserRecord>,
    pub user_roles: BTreeMap<String, BTreeSet<RoleId>>,
    pub user_prefs: BTreeMap<String, UserPreferencesDto>,
    pub invites: BTreeMap<String, PlatformInviteRecord>,
    pub passkeys: BTreeMap<String, Vec<StoredPasskeyRecord>>,
    pub role_leases: BTreeMap<String, RoleLeases>,
    pub bootstrap_seeded: BTreeSet<String>,
    pub audit_activity: Vec<AuditActivityEntryDto>,
    pub snapshot_revision: u64,
    #[serde(skip)]
    pub pending_registrations: HashMap<String, PendingRegistrationState>,
    #[serde(skip)]
    pub pending_authentications: HashMap<String, PendingAuthenticationState>,
    #[serde(skip)]
    pub verified_step_up_proofs: HashMap<String, VerifiedStepUpProof>,
}

impl Default for PlatformAuthState {
    fn default() -> Self {
        Self::seeded_default()
    }
}

impl PlatformAuthState {
    /// Constructs a freshly seeded `PlatformAuthState` matching canonical defaults (`#173`, `#175`).
    #[must_use]
    pub fn seeded_default() -> Self {
        let folio_catalog = FolioCatalog::with_canonical_manifests();

        let baseline = RoleSpec::pinned_baseline(
            rid(BASELINE_ROLE_ID),
            Some("Baseline Operator"),
            "Canonical baseline console operator access; always active after passkey enrollment.",
        )
        .expect("canonical baseline role valid");
        let ci_op = RoleSpec::elective(
            rid(ELECTIVE_CI_ROLE_ID),
            Some("CI Operator"),
            "Elective role granting CI queue control and HA failover actions.",
            StepUpRequirement::None,
        )
        .expect("canonical ci-operator role valid");
        let platform_admin = RoleSpec::timed(
            rid(ADMIN_TIMED_ROLE_ID),
            Some("Platform Administrator"),
            "Short-lived step-up role for platform RBAC, folios, invites, and resets.",
            DEFAULT_ADMIN_HARD_TTL_SECS,
            DEFAULT_ADMIN_IDLE_TTL_SECS,
        )
        .expect("canonical platform-admin role valid");

        let role_catalog = RoleCatalog::from_roles([baseline, ci_op, platform_admin])
            .expect("canonical default role catalog valid");

        let mut role_folio_index = RoleFolioIndex::new();
        role_folio_index
            .set_anonymous_folios(
                DEFAULT_ANONYMOUS_FOLIOS.iter().map(|s| fid(s)).collect(),
                &folio_catalog,
            )
            .expect("canonical anonymous folios valid");
        role_folio_index
            .set_role_folios(
                rid(BASELINE_ROLE_ID),
                [
                    "folio:system:dashboard",
                    "folio:ci:read",
                    "folio:cd:read",
                    "folio:ab:read",
                    "folio:reg:read",
                    "folio:obs:read",
                    "folio:mr:read",
                ]
                .into_iter()
                .map(fid)
                .collect(),
                &folio_catalog,
                &role_catalog,
            )
            .expect("canonical baseline folios valid");
        role_folio_index
            .set_role_folios(
                rid(ELECTIVE_CI_ROLE_ID),
                BTreeSet::from([fid("folio:ci:operate")]),
                &folio_catalog,
                &role_catalog,
            )
            .expect("canonical elective folios valid");
        role_folio_index
            .set_role_folios(
                rid(ADMIN_TIMED_ROLE_ID),
                [
                    "folio:ci:operate",
                    "folio:ab:operate",
                    "folio:reg:operate",
                    "folio:obs:ingress-admin",
                    "folio:mr:connect",
                    "folio:platform:admin",
                ]
                .into_iter()
                .map(fid)
                .collect(),
                &folio_catalog,
                &role_catalog,
            )
            .expect("canonical platform-admin folios valid");

        role_folio_index
            .validate(&folio_catalog, Some(&role_catalog))
            .expect("canonical role-folio index consistent");

        Self {
            initialized: true,
            folio_catalog,
            role_catalog,
            role_folio_index,
            users: BTreeMap::new(),
            user_roles: BTreeMap::new(),
            user_prefs: BTreeMap::new(),
            invites: BTreeMap::new(),
            passkeys: BTreeMap::new(),
            role_leases: BTreeMap::new(),
            bootstrap_seeded: BTreeSet::new(),
            audit_activity: Vec::new(),
            snapshot_revision: 1,
            pending_registrations: HashMap::new(),
            pending_authentications: HashMap::new(),
            verified_step_up_proofs: HashMap::new(),
        }
    }

    /// Re-registers immutable canonical subsystem manifests on deserialized state
    /// without overwriting custom operator folios, roles, or `RoleFolioIndex` mappings.
    pub fn reconcile_after_load(&mut self) {
        if !self.initialized {
            *self = Self::seeded_default();
            return;
        }
        for m in mu_auth::canonical_manifests() {
            let _ = self.folio_catalog.register_manifest(m);
        }
    }

    #[must_use]
    pub fn is_anonymous_lockdown(&self) -> bool {
        self.role_folio_index.anonymous_folios().is_empty()
    }

    #[must_use]
    pub fn baseline_role_id(&self) -> &RoleId {
        &self.role_catalog.pinned_baseline().id
    }

    #[must_use]
    pub fn passkey_count_for(&self, login_key: &str) -> u32 {
        self.passkeys
            .get(login_key)
            .map(|v| u32::try_from(v.len()).unwrap_or(u32::MAX))
            .unwrap_or(0)
    }

    /// Returns `true` if `user` is bound (non-revoked).
    #[must_use]
    pub fn is_bound_user(&self, login: &str) -> Option<&PlatformUserRecord> {
        let key = login.trim().to_ascii_lowercase();
        self.users.get(&key).filter(|u| !u.revoked)
    }

    /// Seeds bootstrap admins once per login lifecycle without reviving explicitly revoked admins.
    pub fn seed_bootstrap_admins(&mut self, admins: &[String], now: DateTime<Utc>) -> bool {
        let baseline = self.baseline_role_id().clone();
        let now_str = now.to_rfc3339();
        let now_ms = datetime_to_epoch_ms(now);
        let mut changed = false;

        for raw in admins {
            let clean = raw.trim();
            if clean.is_empty() {
                continue;
            }
            let key = clean.to_ascii_lowercase();
            if !self.bootstrap_seeded.insert(key.clone()) {
                continue;
            }
            if let Some(existing) = self.users.get(&key) {
                if existing.revoked {
                    continue;
                }
            } else {
                self.users.insert(
                    key.clone(),
                    PlatformUserRecord {
                        github_login: clean.to_string(),
                        display_name: None,
                        invited_by: "bootstrap".to_string(),
                        invite_id: None,
                        bound_at: now_str.clone(),
                        bound_at_ms: now_ms,
                        last_seen_ms: None,
                        revoked: false,
                        revoked_at: None,
                        elevation_epoch: 1,
                    },
                );
                changed = true;
            }

            let roles = self.user_roles.entry(key.clone()).or_default();
            if roles.insert(baseline.clone()) {
                changed = true;
            }
            if let Some(admin_role) = self.role_catalog.get(&rid(ADMIN_TIMED_ROLE_ID)) {
                if roles.insert(admin_role.id.clone()) {
                    changed = true;
                }
            }
            self.user_prefs.entry(key).or_default();
        }
        if changed {
            self.snapshot_revision = self.snapshot_revision.saturating_add(1);
        }
        changed
    }

    /// Binds an invited or migrated user permanently to `PinnedBaseline`.
    pub fn bind_baseline_user(
        &mut self,
        github_login: &str,
        invited_by: &str,
        invite_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> PlatformUserRecord {
        let clean = github_login.trim();
        let key = clean.to_ascii_lowercase();
        let now_str = now.to_rfc3339();
        let now_ms = datetime_to_epoch_ms(now);
        let baseline = self.baseline_role_id().clone();

        let rec = PlatformUserRecord {
            github_login: clean.to_string(),
            display_name: self.users.get(&key).and_then(|u| u.display_name.clone()),
            invited_by: invited_by.to_string(),
            invite_id: invite_id.map(ToString::to_string),
            bound_at: now_str,
            bound_at_ms: now_ms,
            last_seen_ms: Some(now_ms),
            revoked: false,
            revoked_at: None,
            elevation_epoch: self
                .users
                .get(&key)
                .map(|u| u.elevation_epoch.saturating_add(1))
                .unwrap_or(1),
        };
        self.users.insert(key.clone(), rec.clone());
        let roles = self.user_roles.entry(key.clone()).or_default();
        roles.clear();
        roles.insert(baseline);
        self.user_prefs.entry(key).or_default();
        self.record_audit(
            clean,
            "invite.redeem",
            invite_id.map(ToString::to_string),
            "ok",
            now_ms,
        );
        self.snapshot_revision = self.snapshot_revision.saturating_add(1);
        rec
    }

    /// Evaluates current effective policies, roles, folios, and active leases for a caller.
    #[must_use]
    pub fn evaluate_principal(
        &self,
        login: Option<&str>,
        cookie_valid_for_elevated: bool,
        now_ms: u64,
    ) -> (Principal, RoleLeases, SessionEvaluation) {
        let Some(raw_login) = login.map(str::trim).filter(|s| !s.is_empty()) else {
            let leases = RoleLeases::new();
            let eval = evaluate_session(
                &self.folio_catalog,
                &self.role_catalog,
                &self.role_folio_index,
                &Principal::Anonymous,
                &leases,
                now_ms,
            )
            .expect("canonical anonymous evaluation valid");
            return (Principal::Anonymous, leases, eval);
        };

        let key = raw_login.to_ascii_lowercase();
        let Some(user) = self.users.get(&key).filter(|u| !u.revoked) else {
            let leases = RoleLeases::new();
            let eval = evaluate_session(
                &self.folio_catalog,
                &self.role_catalog,
                &self.role_folio_index,
                &Principal::Anonymous,
                &leases,
                now_ms,
            )
            .expect("canonical uninvited anonymous evaluation valid");
            return (Principal::Anonymous, leases, eval);
        };

        let bound_roles = self
            .user_roles
            .get(&key)
            .cloned()
            .unwrap_or_else(|| BTreeSet::from([self.baseline_role_id().clone()]));
        let passkey_count = self.passkey_count_for(&key) as usize;
        let principal = Principal::Authenticated {
            login: user.github_login.clone(),
            bound_roles,
            passkey_count,
        };

        let mut leases = if cookie_valid_for_elevated && passkey_count > 0 {
            self.role_leases
                .get(&key)
                .cloned()
                .unwrap_or_else(|| RoleLeases::for_login(&self.role_catalog, &principal))
        } else {
            RoleLeases::for_login(&self.role_catalog, &principal)
        };
        let _ = leases.prune_expired(now_ms);
        if passkey_count > 0 {
            let baseline = self.baseline_role_id().clone();
            if leases.baseline_role.as_ref() != Some(&baseline) {
                leases.baseline_role = Some(baseline);
            }
        }

        let eval = evaluate_session(
            &self.folio_catalog,
            &self.role_catalog,
            &self.role_folio_index,
            &principal,
            &leases,
            now_ms,
        )
        .expect("canonical authenticated evaluation valid");
        (principal, leases, eval)
    }

    /// Prunes expired leases cleanly for a user and records audit entries if any expired.
    pub fn prune_user_leases(&mut self, login_key: &str, now_ms: u64) -> Vec<RoleId> {
        let Some(leases) = self.role_leases.get_mut(login_key) else {
            return Vec::new();
        };
        let expired = leases.prune_expired(now_ms);
        if !expired.is_empty() {
            for role in &expired {
                self.record_audit(
                    login_key,
                    "role.lease.expired",
                    Some(role.to_string()),
                    "expired",
                    now_ms,
                );
            }
        }
        expired
    }

    /// Checks the last-admin lockout guard (`#175`): at least one non-revoked user
    /// must remain bound to a role whose transitive folio graph includes full platform admin rights.
    #[must_use]
    pub fn has_active_platform_admin(&self) -> bool {
        self.users
            .iter()
            .any(|(key, user)| !user.revoked && self.user_has_platform_admin_binding(key))
    }

    #[must_use]
    pub fn user_has_platform_admin_binding(&self, login_key: &str) -> bool {
        let Some(roles) = self.user_roles.get(login_key) else {
            return false;
        };
        let mut combined_folios = Vec::new();
        for role_id in roles {
            if self.role_catalog.get(role_id).is_none() {
                continue;
            }
            if let Some(folios) = self.role_folio_index.folios_for_role(role_id) {
                combined_folios.extend(folios.iter());
            }
        }
        let Ok(policies) = self.folio_catalog.resolve_folios(combined_folios) else {
            return false;
        };
        policies.contains_str("platform:users.write")
            && policies.contains_str("platform:roles.write")
            && policies.contains_str("platform:folios.write")
            && policies.contains_str("platform:invites.write")
    }

    /// Resets all Passkeys for `login` back to `0` (`#179`) and clears active leases.
    pub fn reset_user_passkeys(
        &mut self,
        github_login: &str,
        actor: &str,
        now_ms: u64,
    ) -> Result<u32, String> {
        let key = github_login.trim().to_ascii_lowercase();
        let Some(user) = self.users.get_mut(&key) else {
            return Err(format!("User '{}' not found", github_login.trim()));
        };
        if user.revoked {
            return Err(format!("User '{}' is revoked", user.github_login));
        }
        let canonical_login = user.github_login.clone();
        user.elevation_epoch = user.elevation_epoch.saturating_add(1);
        let removed = self
            .passkeys
            .remove(&key)
            .map(|v| u32::try_from(v.len()).unwrap_or(u32::MAX))
            .unwrap_or(0);
        self.role_leases.remove(&key);
        self.pending_registrations.retain(|_, p| p.login_key != key);
        self.pending_authentications
            .retain(|_, p| p.login_key != key);
        self.verified_step_up_proofs
            .retain(|_, p| p.login_key != key);
        self.record_audit(
            actor,
            "user.passkeys.reset",
            Some(canonical_login),
            "ok",
            now_ms,
        );
        self.snapshot_revision = self.snapshot_revision.saturating_add(1);
        Ok(removed)
    }

    /// Prunes expired transient WebAuthn challenges & step-up tokens.
    pub fn prune_challenges(&mut self, now_ms: u64) {
        self.pending_registrations
            .retain(|_, p| p.expires_at_ms > now_ms);
        self.pending_authentications
            .retain(|_, p| p.expires_at_ms > now_ms);
        self.verified_step_up_proofs
            .retain(|_, p| p.expires_at_ms > now_ms);
    }

    /// Appends a bounded audit entry (most recent last, trimmed to `MAX_AUDIT_ENTRIES`).
    pub fn record_audit(
        &mut self,
        actor: &str,
        action: &str,
        target: Option<String>,
        outcome: &str,
        timestamp_ms: u64,
    ) {
        self.audit_activity.push(AuditActivityEntryDto {
            timestamp_ms,
            actor: actor.to_string(),
            action: action.to_string(),
            target,
            outcome: outcome.to_string(),
        });
        if self.audit_activity.len() > MAX_AUDIT_ENTRIES {
            let overflow = self.audit_activity.len() - MAX_AUDIT_ENTRIES;
            self.audit_activity.drain(0..overflow);
        }
    }

    /// Builds `RoleLeaseViewDto` entries for every active `Timed` lease on `leases`.
    #[must_use]
    pub fn build_lease_views(&self, leases: &RoleLeases, now_ms: u64) -> Vec<RoleLeaseViewDto> {
        let mut views = Vec::new();
        for (role_id, lease) in &leases.timed_leases {
            let Some(spec) = self.role_catalog.get(role_id) else {
                continue;
            };
            let RoleActivation::Timed {
                hard_ttl_secs,
                idle_ttl_secs,
            } = spec.activation
            else {
                continue;
            };
            if !lease.is_active(now_ms) {
                continue;
            }
            views.push(RoleLeaseViewDto {
                role_id: role_id.to_string(),
                display_name: spec.display_name.clone(),
                activated_at_ms: lease.activated_at_ms,
                last_activity_at_ms: lease.last_activity_at_ms,
                hard_expires_at_ms: lease.hard_expires_at_ms,
                idle_expires_at_ms: lease.idle_expires_at_ms,
                hard_ttl_secs,
                idle_ttl_secs,
                seconds_remaining: lease.seconds_remaining(now_ms),
                idle_timer: lease.idle_remaining_secs(now_ms),
            });
        }
        views
    }

    /// Converts an active session evaluation into the wire [`AuthSessionDto`].
    #[must_use]
    pub fn build_session_dto(
        &self,
        login_key: Option<&str>,
        leases: &RoleLeases,
        eval: &SessionEvaluation,
        now_ms: u64,
    ) -> AuthSessionDto {
        let anon_lockdown = self.is_anonymous_lockdown();
        let baseline_id = self.baseline_role_id().to_string();

        let Some(key) = login_key else {
            return AuthSessionDto {
                authenticated: false,
                github_login: None,
                invite_bound: false,
                role: None,
                reason_code: None,
                passkey_count: 0,
                passkey_enrollment_required: false,
                anonymous_lockdown: anon_lockdown,
                anonymous_login_only: anon_lockdown,
                baseline_role: Some(baseline_id),
                bound_roles: Vec::new(),
                active_roles: Vec::new(),
                leases: Vec::new(),
                active_folios: eval.active_folios.iter().map(ToString::to_string).collect(),
                active_policies: eval.policies.iter().map(ToString::to_string).collect(),
                preferences: None,
                display_name: None,
            };
        };

        let Some(user) = self.users.get(key).filter(|u| !u.revoked) else {
            return AuthSessionDto {
                authenticated: false,
                github_login: Some(key.to_string()),
                invite_bound: false,
                role: None,
                reason_code: Some(AuthReasonCodeDto::AuthorizationDenied),
                passkey_count: 0,
                passkey_enrollment_required: false,
                anonymous_lockdown: anon_lockdown,
                anonymous_login_only: anon_lockdown,
                baseline_role: Some(baseline_id),
                bound_roles: Vec::new(),
                active_roles: Vec::new(),
                leases: Vec::new(),
                active_folios: eval.active_folios.iter().map(ToString::to_string).collect(),
                active_policies: eval.policies.iter().map(ToString::to_string).collect(),
                preferences: None,
                display_name: None,
            };
        };

        let passkey_count = self.passkey_count_for(key);
        let bound_roles = self
            .user_roles
            .get(key)
            .map(|r| r.iter().map(ToString::to_string).collect::<Vec<_>>())
            .unwrap_or_else(|| vec![baseline_id.clone()]);
        let prefs = self.user_prefs.get(key).copied().unwrap_or_default();

        if eval.passkey_enrollment_required || passkey_count == 0 {
            return AuthSessionDto {
                authenticated: true,
                github_login: Some(user.github_login.clone()),
                invite_bound: true,
                role: None,
                reason_code: Some(AuthReasonCodeDto::PasskeyEnrollmentRequired),
                passkey_count: 0,
                passkey_enrollment_required: true,
                anonymous_lockdown: anon_lockdown,
                anonymous_login_only: anon_lockdown,
                baseline_role: Some(baseline_id),
                bound_roles,
                active_roles: Vec::new(),
                leases: Vec::new(),
                active_folios: Vec::new(),
                active_policies: Vec::new(),
                preferences: Some(prefs),
                display_name: user.display_name.clone(),
            };
        }

        let active_roles: Vec<RoleSpec> = eval
            .active_roles
            .iter()
            .filter_map(|id| self.role_catalog.get(id).cloned())
            .collect();
        let active_role_label = if eval.policies.contains_str("platform:users.write") {
            Some(ADMIN_TIMED_ROLE_ID.to_string())
        } else {
            Some(baseline_id.clone())
        };

        AuthSessionDto {
            authenticated: true,
            github_login: Some(user.github_login.clone()),
            invite_bound: true,
            role: active_role_label,
            reason_code: None,
            passkey_count,
            passkey_enrollment_required: false,
            anonymous_lockdown: anon_lockdown,
            anonymous_login_only: anon_lockdown,
            baseline_role: Some(baseline_id),
            bound_roles,
            active_roles,
            leases: self.build_lease_views(leases, now_ms),
            active_folios: eval.active_folios.iter().map(ToString::to_string).collect(),
            active_policies: eval.policies.iter().map(ToString::to_string).collect(),
            preferences: Some(prefs),
            display_name: user.display_name.clone(),
        }
    }

    /// Builds sanitized [`UserProfileDto`] for `@user`.
    #[must_use]
    pub fn build_profile_dto(&self, login_key: &str) -> Option<UserProfileDto> {
        let user = self.users.get(login_key).filter(|u| !u.revoked)?;
        let prefs = self.user_prefs.get(login_key).copied().unwrap_or_default();
        let bound_roles = self
            .user_roles
            .get(login_key)
            .map(|r| r.iter().map(ToString::to_string).collect::<Vec<_>>())
            .unwrap_or_else(|| vec![self.baseline_role_id().to_string()]);
        let passkeys = self
            .passkeys
            .get(login_key)
            .map(|list| {
                list.iter()
                    .map(|p| PasskeySummaryDto {
                        credential_id: p.credential_id.clone(),
                        label: p.label.clone(),
                        sign_count: p.record.sign_count,
                        created_at_ms: p.created_at_ms,
                        last_used_at_ms: p.last_used_at_ms,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let passkey_count = u32::try_from(passkeys.len()).unwrap_or(u32::MAX);
        Some(UserProfileDto {
            github_login: user.github_login.clone(),
            display_name: user.display_name.clone(),
            preferences: prefs,
            bound_roles,
            passkeys,
            passkey_count,
        })
    }

    /// Builds sanitized user directory rows (`Platform > Users & Invites`).
    #[must_use]
    pub fn build_platform_users(&self) -> Vec<PlatformUserDto> {
        self.users
            .iter()
            .map(|(key, u)| PlatformUserDto {
                github_login: u.github_login.clone(),
                display_name: u.display_name.clone(),
                bound_roles: self
                    .user_roles
                    .get(key)
                    .map(|r| r.iter().map(ToString::to_string).collect())
                    .unwrap_or_default(),
                passkey_count: self.passkey_count_for(key),
                last_seen_ms: u.last_seen_ms,
                is_platform_admin: !u.revoked && self.user_has_platform_admin_binding(key),
                invited_by: u.invited_by.clone(),
                revoked: u.revoked,
            })
            .collect()
    }

    /// Builds the `GET /api/internal/auth/snapshot` JSON payload (`#176`).
    #[must_use]
    pub fn build_internal_snapshot_json(&self) -> serde_json::Value {
        let policies: Vec<&Policy> = self.folio_catalog.policies().collect();
        let folios: Vec<&PolicyFolio> = self.folio_catalog.folios().collect();
        let roles: Vec<&RoleSpec> = self.role_catalog.iter().collect();
        let users = self.build_platform_users();
        let recent_activity: Vec<&AuditActivityEntryDto> =
            self.audit_activity.iter().rev().take(50).collect();

        serde_json::json!({
            "revision": self.snapshot_revision,
            "etag": self.etag(),
            "anonymous_lockdown": self.is_anonymous_lockdown(),
            "anonymous_login_only": self.is_anonymous_lockdown(),
            "baseline_role": self.baseline_role_id().as_str(),
            "roles": roles,
            "folios": folios,
            "policies": policies,
            "role_folio_index": self.role_folio_index,
            "users": users,
            "subsystems": [],
            "invites": [],
            "recent_activity": recent_activity,
        })
    }

    #[must_use]
    pub fn etag(&self) -> String {
        format!("\"rev-{}\"", self.snapshot_revision)
    }

    /// Updates user display name & UI skin/font preferences (`#175`, `#176`).
    pub fn update_user_profile(
        &mut self,
        login_key: &str,
        display_name: Option<Option<&str>>,
        skin: Option<ConsoleSkinDto>,
        font: Option<CrtFontDto>,
        now_ms: u64,
    ) -> Result<UserProfileDto, String> {
        let Some(user) = self.users.get_mut(login_key).filter(|u| !u.revoked) else {
            return Err("Authenticated user is not bound".to_string());
        };
        if let Some(maybe_name) = display_name {
            user.display_name = match maybe_name {
                Some(raw) => {
                    let trimmed = raw.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(
                            validate_display_name(trimmed)
                                .map_err(|e| format!("Invalid display_name: {e}"))?
                                .to_string(),
                        )
                    }
                }
                None => None,
            };
        }
        let prefs = self.user_prefs.entry(login_key.to_string()).or_default();
        if let Some(s) = skin {
            prefs.skin = s;
        }
        if let Some(f) = font {
            prefs.font = f;
        }
        let actor = user.github_login.clone();
        self.record_audit(&actor, "profile.update", None, "ok", now_ms);
        self.snapshot_revision = self.snapshot_revision.saturating_add(1);
        self.build_profile_dto(login_key)
            .ok_or_else(|| "User missing after update".to_string())
    }
}

/// Decodes and validates trusted GitHub edge identity using `mu-auth::GithubEdgeAuthAdapter`.
#[must_use]
pub fn authenticate_edge_github_login(
    proxy_secret: Option<&str>,
    header_secret: Option<&str>,
    forwarded_user: Option<&str>,
) -> Option<String> {
    let expected = proxy_secret?.trim();
    if expected.is_empty() {
        return None;
    }
    let cfg = EdgeAuthConfig::with_proxy_secret(expected).ok()?;
    let adapter = GithubEdgeAuthAdapter::new(cfg);
    let mut headers = Vec::new();
    if let Some(s) = header_secret {
        headers.push(("X-Proxy-Secret", s));
    }
    if let Some(u) = forwarded_user {
        headers.push(("X-Forwarded-User", u));
    }
    adapter
        .authenticate_headers(&headers, None)
        .ok()
        .flatten()
        .map(|id| id.login.as_str().to_string())
}

/// Signs an invite token (`inv_<id>.<hex>`) with `mu-auth::InviteCodec`.
pub fn sign_baseline_invite_token(
    signing_key: &str,
    invite_id: &str,
    expires_at_ms: u64,
    role_catalog: &RoleCatalog,
) -> Result<(String, String), String> {
    let codec =
        InviteCodec::new(signing_key).map_err(|e| format!("Invalid invite signing key: {e}"))?;
    let signed = codec
        .sign_invite(invite_id, expires_at_ms, role_catalog)
        .map_err(|e| format!("Failed to sign baseline invite: {e}"))?;
    Ok((signed.token, signed.hmac_hex))
}

/// Constant-time verification of a presented invite HMAC hex string.
#[must_use]
pub fn verify_baseline_invite_token(
    signing_key: &str,
    invite_id: &str,
    expires_at_ms: u64,
    presented_hmac: &str,
    role_catalog: &RoleCatalog,
) -> bool {
    let Ok(codec) = InviteCodec::new(signing_key) else {
        return false;
    };
    let Ok(expected) = codec.sign_invite(invite_id, expires_at_ms, role_catalog) else {
        return false;
    };
    expected
        .hmac_hex
        .as_bytes()
        .ct_eq(presented_hmac.as_bytes())
        .into()
}

/// Builds a [`WebauthnPasskeyService`] from [`crate::config::Config`].
pub fn build_webauthn_service(
    config: &crate::config::Config,
) -> Result<WebauthnPasskeyService, String> {
    let mut origins = Vec::new();
    for raw in config.webauthn_rp_origin.split(',') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed: url::Url = trimmed
            .parse()
            .map_err(|e| format!("Invalid webauthn_rp_origin '{trimmed}': {e}"))?;
        origins.push(parsed);
    }
    let cfg = WebauthnConfig::with_ttl(
        config.webauthn_rp_name.clone(),
        config.webauthn_rp_id.clone(),
        origins,
        DEFAULT_WEBAUTHN_CHALLENGE_TTL_SECS,
    )
    .map_err(|e| format!("Invalid WebAuthn configuration: {e}"))?;
    Ok(WebauthnPasskeyService::new(cfg))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevatedCookieClaims {
    pub login_key: String,
    pub epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Mints a signed `__Host-mu_elevated` cookie token bound to `@github_login` and `elevation_epoch`.
pub fn sign_elevated_cookie(
    signing_key: &str,
    claims: &ElevatedCookieClaims,
) -> Result<String, String> {
    let payload_json =
        serde_json::to_vec(claims).map_err(|e| format!("Failed to encode cookie claims: {e}"))?;
    let payload_hex = hex::encode(payload_json);
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
        .map_err(|e| format!("Invalid elevation HMAC key: {e}"))?;
    mac.update(payload_hex.as_bytes());
    let sig_hex = hex::encode(mac.finalize().into_bytes());
    Ok(format!("{payload_hex}.{sig_hex}"))
}

/// Verifies a signed `__Host-mu_elevated` cookie token in constant time.
#[must_use]
pub fn verify_elevated_cookie(
    signing_key: &str,
    token: &str,
    expected_login_key: &str,
    expected_epoch: u64,
    now_ms: u64,
) -> Option<ElevatedCookieClaims> {
    let (payload_hex, sig_hex) = token.trim().split_once('.')?;
    let sig_bytes = hex::decode(sig_hex).ok()?;
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes()).ok()?;
    mac.update(payload_hex.as_bytes());
    mac.verify_slice(&sig_bytes).ok()?;
    let payload_bytes = hex::decode(payload_hex).ok()?;
    let claims: ElevatedCookieClaims = serde_json::from_slice(&payload_bytes).ok()?;
    if claims.login_key != expected_login_key {
        return None;
    }
    if claims.epoch != expected_epoch {
        return None;
    }
    if claims.expires_at_ms <= now_ms {
        return None;
    }
    Some(claims)
}

/// Formats `Set-Cookie` header value to activate `__Host-mu_elevated`.
#[must_use]
pub fn format_elevated_set_cookie(token: &str, max_age_secs: u64) -> String {
    format!(
        "{ELEVATED_COOKIE_NAME}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age_secs}"
    )
}

/// Formats `Set-Cookie` header value to immediately expire `__Host-mu_elevated`.
#[must_use]
pub fn format_elevated_clear_cookie() -> String {
    format!("{ELEVATED_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0")
}

/// Atomically persists [`PlatformAuthState`] JSON to disk (`tmp` + rename).
pub fn save_auth_state_atomic(path: &Path, state: &PlatformAuthState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create auth state parent dir: {e}"))?;
    }
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| format!("Failed to serialize PlatformAuthState: {e}"))?;
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, json.as_bytes())
        .map_err(|e| format!("Failed to write temp auth state: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("Failed to atomically commit auth state file: {e}"))?;
    Ok(())
}

/// Loads [`PlatformAuthState`] JSON from disk if present.
pub fn load_auth_state_file(path: &Path) -> Result<Option<PlatformAuthState>, String> {
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read auth state file {}: {e}", path.display()))?;
    let mut parsed: PlatformAuthState = serde_json::from_str(&raw)
        .map_err(|e| format!("Failed to parse auth state file {}: {e}", path.display()))?;
    parsed.reconcile_after_load();
    Ok(Some(parsed))
}

#[must_use]
pub fn default_auth_state_path(workspace_dir: &Path) -> PathBuf {
    workspace_dir.join("logs").join("platform_auth.json")
}

#[must_use]
pub fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[must_use]
pub fn datetime_to_epoch_ms(dt: DateTime<Utc>) -> u64 {
    u64::try_from(dt.timestamp_millis().max(0)).unwrap_or(0)
}

#[must_use]
pub fn fid(raw: &str) -> FolioId {
    FolioId::new(raw).expect("canonical folio id valid")
}

#[must_use]
pub fn rid(raw: &str) -> RoleId {
    RoleId::new(raw).expect("canonical role id valid")
}

#[must_use]
pub fn normalize_login(raw: &str) -> Option<String> {
    GithubLogin::new(raw.trim().to_string())
        .ok()
        .map(|g| g.as_str().to_ascii_lowercase())
}

/// Parses and executes break-glass host CLI subcommands (`reset-passkeys <login>`).
/// Returns `None` if argv does not invoke a CLI subcommand (starts daemon normally).
pub fn execute_reset_passkeys_cli(args: &[String]) -> Option<Result<String, String>> {
    let tail = args.get(1..)?;
    let (target_idx, login) = if tail.first().map(String::as_str) == Some("reset-passkeys") {
        (2usize, tail.get(1)?)
    } else if tail.first().map(String::as_str) == Some("auth")
        && tail.get(1).map(String::as_str) == Some("reset-passkeys")
    {
        (3usize, tail.get(2)?)
    } else if tail.first().map(String::as_str) == Some("--reset-passkeys") {
        (2usize, tail.get(1)?)
    } else if matches!(
        tail.first().map(String::as_str),
        Some("reset-passkeys") | Some("--reset-passkeys")
    ) {
        return Some(Err(
            "Usage: mu-ci-controller reset-passkeys <github_login> [--workspace <dir>] [--auth-state-file <path>]".to_string(),
        ));
    } else {
        return None;
    };

    let mut workspace_dir: Option<PathBuf> = std::env::var("ACTION_RUNNER_WORKSPACE_DIR")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let mut explicit_file: Option<PathBuf> = std::env::var("ACTION_RUNNER_AUTH_STATE_FILE")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);

    let mut i = target_idx;
    while i < tail.len() {
        match tail[i].as_str() {
            "--workspace" => {
                let Some(val) = tail.get(i + 1) else {
                    return Some(Err("--workspace requires a directory path".to_string()));
                };
                workspace_dir = Some(PathBuf::from(val));
                i += 2;
            }
            "--auth-state-file" => {
                let Some(val) = tail.get(i + 1) else {
                    return Some(Err("--auth-state-file requires a file path".to_string()));
                };
                explicit_file = Some(PathBuf::from(val));
                i += 2;
            }
            other => {
                return Some(Err(format!("Unknown reset-passkeys argument: {other}")));
            }
        }
    }

    let state_path = explicit_file.unwrap_or_else(|| {
        default_auth_state_path(
            workspace_dir
                .as_deref()
                .unwrap_or_else(|| Path::new("./workspace")),
        )
    });

    let mut state = match load_auth_state_file(&state_path) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Some(Err(format!(
                "No auth state file found at {}",
                state_path.display()
            )));
        }
        Err(err) => return Some(Err(err)),
    };

    let removed = match state.reset_user_passkeys(login, "host-cli", current_epoch_ms()) {
        Ok(n) => n,
        Err(err) => return Some(Err(err)),
    };
    if let Err(err) = save_auth_state_atomic(&state_path, &state) {
        return Some(Err(err));
    }

    Some(Ok(serde_json::json!({
        "status": "ok",
        "github_login": login.trim(),
        "removed_passkeys": removed,
        "passkey_count": 0,
        "passkey_enrollment_required": true,
        "auth_state_file": state_path.display().to_string(),
    })
    .to_string()))
}

/// Checks if a JSON payload contains any forbidden client-supplied TTL override keys.
#[must_use]
pub fn payload_has_forbidden_ttl_fields(val: &serde_json::Value) -> bool {
    const FORBIDDEN: [&str; 9] = [
        "ttl",
        "ttl_secs",
        "ttl_seconds",
        "hard_ttl_secs",
        "idle_ttl_secs",
        "expires_at",
        "expires_at_ms",
        "hard_expires_at_ms",
        "idle_expires_at_ms",
    ];
    let Some(obj) = val.as_object() else {
        return false;
    };
    FORBIDDEN.iter().any(|k| obj.contains_key(*k))
}

/// Executes a single `Elective` or `Timed` role lease activation strictly from server `RoleCatalog` TTLs.
pub fn activate_server_role_lease(
    state: &mut PlatformAuthState,
    login_key: &str,
    role_id: &RoleId,
    step_up_verified: bool,
    now_ms: u64,
) -> Result<(RoleSpec, Option<mu_auth::RoleLease>), (AuthReasonCodeDto, String)> {
    let Some(spec) = state.role_catalog.get(role_id).cloned() else {
        return Err((
            AuthReasonCodeDto::AuthorizationDenied,
            format!("Unknown role '{role_id}'"),
        ));
    };
    let bound_roles = state.user_roles.get(login_key).cloned().unwrap_or_default();
    if !bound_roles.contains(role_id) {
        return Err((
            AuthReasonCodeDto::AuthorizationDenied,
            "Role is not assigned to this account".to_string(),
        ));
    }
    let user = state
        .users
        .get(login_key)
        .filter(|u| !u.revoked)
        .ok_or_else(|| {
            (
                AuthReasonCodeDto::AuthorizationDenied,
                "Account is not active".to_string(),
            )
        })?;
    let passkey_count = state.passkey_count_for(login_key) as usize;
    let principal = Principal::Authenticated {
        login: user.github_login.clone(),
        bound_roles,
        passkey_count,
    };

    let role_catalog = &state.role_catalog;
    let leases = state
        .role_leases
        .entry(login_key.to_string())
        .or_insert_with(|| RoleLeases::for_login(role_catalog, &principal));
    let _ = leases.prune_expired(now_ms);

    match spec.activation {
        RoleActivation::PinnedBaseline => Err((
            AuthReasonCodeDto::PinnedBaselineImmutable,
            "Canonical PinnedBaseline role is always active".to_string(),
        )),
        RoleActivation::Elective => {
            leases
                .enable_elective(role_catalog, &principal, role_id, step_up_verified)
                .map_err(|e| (AuthReasonCodeDto::StepUpRequired, e.to_string()))?;
            Ok((spec, None))
        }
        RoleActivation::Timed { .. } => {
            let lease = leases
                .activate_timed(role_catalog, &principal, role_id, now_ms, step_up_verified)
                .map_err(|e| (AuthReasonCodeDto::CeilingExceeded, e.to_string()))?
                .clone();
            Ok((spec, Some(lease)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mu_auth::{canonical_manifests, FolioOrigin, PolicyId};

    #[test]
    fn canonical_defaults_and_seed_idempotency() {
        let _ = canonical_manifests();
        let mut st = PlatformAuthState::seeded_default();
        assert!(!st.is_anonymous_lockdown());
        assert_eq!(st.baseline_role_id().as_str(), BASELINE_ROLE_ID);

        let now = Utc::now();
        assert!(st.seed_bootstrap_admins(&["LMA1980".to_string()], now));
        assert!(!st.seed_bootstrap_admins(&["LMA1980".to_string()], now));

        st.role_folio_index
            .set_anonymous_folios(BTreeSet::new(), &st.folio_catalog)
            .unwrap();
        assert!(st.is_anonymous_lockdown());
        st.reconcile_after_load();
        assert!(
            st.is_anonymous_lockdown(),
            "operator anonymous lockdown customization must persist across reload"
        );
    }

    #[test]
    fn composite_folio_cycle_rejection_and_additive_resolution() {
        let mut st = PlatformAuthState::seeded_default();
        let op_other = PolicyFolio {
            id: fid("folio:op:other"),
            display_name: "Other".to_string(),
            description: "Leaf folio".to_string(),
            origin: FolioOrigin::Operator,
            owner_subsystem: None,
            includes: BTreeSet::new(),
            policies: BTreeSet::from([PolicyId::new("cd:runs.read").unwrap()]),
        };
        st.folio_catalog.upsert_operator_folio(op_other).unwrap();

        let op_a = PolicyFolio {
            id: fid("folio:op:custom-ops"),
            display_name: "Custom Ops".to_string(),
            description: "Combines ci:read and op:other".to_string(),
            origin: FolioOrigin::Operator,
            owner_subsystem: None,
            includes: BTreeSet::from([fid("folio:ci:read"), fid("folio:op:other")]),
            policies: BTreeSet::from([PolicyId::new("ci:jobs.restart").unwrap()]),
        };
        st.folio_catalog.upsert_operator_folio(op_a).unwrap();
        st.folio_catalog.validate_graph().unwrap();

        let resolved = st
            .folio_catalog
            .resolve_folio(&fid("folio:op:custom-ops"))
            .unwrap();
        assert!(resolved.contains_str("ci:jobs.read"));
        assert!(resolved.contains_str("cd:runs.read"));
        assert!(resolved.contains_str("ci:jobs.restart"));

        // Attempting to make op:other include custom-ops closes a cycle and must fail.
        let op_other_cyclic = PolicyFolio {
            id: fid("folio:op:other"),
            display_name: "Other Cyclic".to_string(),
            description: "Closes cycle".to_string(),
            origin: FolioOrigin::Operator,
            owner_subsystem: None,
            includes: BTreeSet::from([fid("folio:op:custom-ops")]),
            policies: BTreeSet::new(),
        };
        let insert_res = st.folio_catalog.upsert_operator_folio(op_other_cyclic);
        assert!(insert_res.is_err() || st.folio_catalog.validate_graph().is_err());
    }

    #[test]
    fn zero_passkey_gate_withholds_baseline_until_enrolled() {
        let mut st = PlatformAuthState::seeded_default();
        let now = Utc::now();
        st.bind_baseline_user("alice", "LMA1980", Some("inv-1"), now);

        let (_, _, eval_zero) = st.evaluate_principal(Some("alice"), false, 10_000);
        assert!(eval_zero.passkey_enrollment_required);
        assert!(eval_zero.active_roles.is_empty());
        assert!(eval_zero.policies.is_empty());

        let dto = st.build_session_dto(Some("alice"), &RoleLeases::new(), &eval_zero, 10_000);
        assert!(dto.authenticated);
        assert!(dto.invite_bound);
        assert!(dto.passkey_enrollment_required);
        assert_eq!(dto.role, None);
        assert_eq!(dto.baseline_role.as_deref(), Some("operator"));
        assert!(dto.active_policies.is_empty());
    }

    #[test]
    fn independent_timed_role_expiry_and_idle_activity_bounds() {
        let mut st = PlatformAuthState::seeded_default();
        let now = Utc::now();
        st.bind_baseline_user("alice", "LMA1980", None, now);

        let sec_role = RoleSpec::timed(
            rid("sec-auditor"),
            Some("Security Auditor"),
            "Timed short lease",
            120,
            60,
        )
        .unwrap();
        st.role_catalog.upsert_role(sec_role).unwrap();
        st.role_folio_index
            .set_role_folios(
                rid("sec-auditor"),
                BTreeSet::from([fid("folio:platform:read")]),
                &st.folio_catalog,
                &st.role_catalog,
            )
            .unwrap();
        let bound_roles = BTreeSet::from([
            rid(BASELINE_ROLE_ID),
            rid(ADMIN_TIMED_ROLE_ID),
            rid("sec-auditor"),
        ]);
        let principal = Principal::Authenticated {
            login: "alice".to_string(),
            bound_roles,
            passkey_count: 1,
        };
        let mut leases = RoleLeases::for_login(&st.role_catalog, &principal);
        leases
            .activate_timed(
                &st.role_catalog,
                &principal,
                &rid("sec-auditor"),
                1_000,
                true,
            )
            .unwrap();
        leases
            .activate_timed(
                &st.role_catalog,
                &principal,
                &rid(ADMIN_TIMED_ROLE_ID),
                1_000,
                true,
            )
            .unwrap();

        let _ = leases.record_activity(50_000);
        let sec_lease = leases.timed_leases.get(&rid("sec-auditor")).unwrap();
        assert_eq!(sec_lease.hard_expires_at_ms, 121_000);
        assert_eq!(sec_lease.idle_expires_at_ms, 110_000);

        let _ = leases.record_activity(90_000);
        let sec_lease = leases.timed_leases.get(&rid("sec-auditor")).unwrap();
        assert_eq!(sec_lease.idle_expires_at_ms, 121_000);

        st.role_leases.insert("alice".to_string(), leases);
        let expired = st.prune_user_leases("alice", 122_000);
        assert_eq!(expired, vec![rid("sec-auditor")]);
        let leases_after = st.role_leases.get("alice").unwrap();
        assert!(!leases_after.timed_leases.contains_key(&rid("sec-auditor")));
        assert!(leases_after
            .timed_leases
            .contains_key(&rid(ADMIN_TIMED_ROLE_ID)));
    }

    #[test]
    fn cookie_hmac_roundtrip_epoch_and_tamper_rejection() {
        let claims = ElevatedCookieClaims {
            login_key: "alice".to_string(),
            epoch: 3,
            issued_at_ms: 1_000,
            expires_at_ms: 100_000,
        };
        let token = sign_elevated_cookie("super-secret", &claims).unwrap();
        assert!(verify_elevated_cookie("super-secret", &token, "alice", 3, 50_000).is_some());
        assert!(verify_elevated_cookie("super-secret", &token, "bob", 3, 50_000).is_none());
        assert!(verify_elevated_cookie("super-secret", &token, "alice", 4, 50_000).is_none());
        assert!(verify_elevated_cookie("super-secret", &token, "alice", 3, 100_000).is_none());
        assert!(verify_elevated_cookie("wrong-secret", &token, "alice", 3, 50_000).is_none());
    }

    #[test]
    fn last_admin_lockout_guard_detects_missing_admin_capacity() {
        let mut st = PlatformAuthState::seeded_default();
        let now = Utc::now();
        st.seed_bootstrap_admins(&["LMA1980".to_string()], now);
        assert!(st.has_active_platform_admin());

        st.users.get_mut("lma1980").unwrap().revoked = true;
        assert!(!st.has_active_platform_admin());

        st.users.get_mut("lma1980").unwrap().revoked = false;
        st.bind_baseline_user("alice", "LMA1980", None, now);
        st.user_roles
            .get_mut("alice")
            .unwrap()
            .insert(rid(ADMIN_TIMED_ROLE_ID));
        st.users.get_mut("lma1980").unwrap().revoked = true;
        assert!(
            st.has_active_platform_admin(),
            "alice retains platform-admin so LMA1980 can be safely revoked"
        );
    }
}
