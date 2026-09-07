// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::net::SocketAddr;
use std::str::FromStr as _;
use std::time::Duration;

use chain_types::subxt::utils::AccountId32;
use secrecy::{SecretBox, SecretString};

#[derive(Debug)]
pub struct Config {
    pub bind_addr: SocketAddr,
    /// Postgres connection string (required; no default). May embed a password,
    /// so it is a secret.
    pub database_url: SecretString,
    /// Ed25519 seed used to sign JWTs (32 bytes). device-attestation is the sole issuer.
    pub jwt_secret: SecretBox<[u8; 32]>,
    /// JWT `iss` claim; kept as the current backend's value for compatibility.
    pub jwt_issuer: String,
    /// People Chain RPC endpoint for read-path chain queries.
    pub people_rpc_url: String,
    /// Attester authority: published by `GET /api/v1/attester` as `0x`+hex and
    /// attested as by device-attestation-chain-writer, from one shared value.
    pub attester_account: [u8; 32],
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
    pub challenge_ttl: Duration,
    /// Max requests per client per window on the unauthenticated auth routes.
    pub auth_rate_limit: u32,
    pub auth_rate_window: Duration,
    /// Master attestation switch; `false` makes platform attestation a no-op
    /// (the sr25519 account proof still runs).
    pub auth_enabled: bool,
    /// Hard gate (`true`) vs soft/advisory (`false`): log the verdict, never
    /// reject.
    pub enforce_auth: bool,
    /// Registration-queue gate: `true` routes claims into the balance-priority
    /// queue (`QUEUED` intake + the `/api/v1/registration/queue` surface);
    /// `false` (the M0 default) keeps the direct-to-writer flow and wire.
    pub queue_enabled: bool,
    /// Registration-voucher gate (the eligibility slice's INSTANT lane):
    /// `true` recognises `lifetimePoUDVoucher` on `POST /api/v1/usernames`;
    /// `false` (default) ignores the field, keeping the frozen wire.
    pub registration_vouchers_enabled: bool,
    /// Whether registration accepts the optional `dotns` block (mirrors the
    /// legacy `DOTNS_GATEWAY_ENABLED` gate and its captured 400 message).
    pub dotns_gateway_enabled: bool,
    /// Max age, in seconds, of `dotns.signedAt` (the intake freshness bound).
    pub dotns_intake_freshness_max_age_secs: u32,
    /// Max future skew, in seconds, tolerated on `dotns.signedAt`.
    pub dotns_max_future_skew_secs: u32,
    /// App IDs (`TEAMID.bundle.id`) accepted in App Attest rpIdHash checks.
    /// Required (non-empty) when `auth_enabled` is true.
    pub apple_app_attest_app_ids: Vec<String>,
    /// iOS bundle ids accepted in the `Auth-iOS-Package` header.
    /// Required (non-empty) when `auth_enabled` is true.
    pub ios_package_names: Vec<String>,
    /// Android package names accepted in key-attestation / Play Integrity
    /// verdicts. Required (non-empty) when `auth_enabled` is true.
    pub android_package_names: Vec<String>,
    /// SHA-256 fingerprint of the Play Store signing certificate.
    /// Required when `auth_enabled` is true.
    pub android_signing_digest_playstore: Option<[u8; 32]>,
    /// SHA-256 fingerprint of the website/vanilla-APK signing certificate.
    /// Required when `auth_enabled` is true.
    pub android_signing_digest_website: Option<[u8; 32]>,
    /// URL of Google's Android attestation revocation list.
    pub android_crl_url: String,
    /// Cache TTL for the attestation revocation list.
    pub android_crl_cache_ttl: Duration,
    /// Maximum age a cached CRL snapshot may reach while refreshes fail before
    /// it is refused (surfaced as a hard-mode `503`). Bounds the "serve stale"
    /// fallback to the spec's 1-hour maximum staleness (SC-004).
    pub android_crl_max_stale: Duration,
    /// Play Integrity verdict acceptance mode (`strict` default).
    pub play_integrity_mode: crate::auth::play_integrity::PlayIntegrityMode,
    /// AES-256 Play Integrity response decryption key (self-managed keys).
    /// Optional until the Play Console key exchange lands; without it the
    /// Google-API fallback is used (if configured), else every play-integrity
    /// verdict fails (posture-gated).
    pub play_integrity_decryption_key: Option<SecretBox<[u8; 32]>>,
    /// EC P-256 Play Integrity verification key, DER SPKI (self-managed keys).
    pub play_integrity_verification_key: Option<Vec<u8>>,
    /// Legacy `GOOGLE_CREDENTIALS` service account (base64 JSON) for the
    /// temporary `decodeIntegrityToken` fallback. Delete with the fallback.
    pub google_credentials: Option<crate::auth::play_integrity::google::GoogleCredentials>,
    /// Apple DeviceCheck (iOS uniqueness at username claim). `None` while
    /// `DEVICE_CHECK_IOS_ENABLED=false`; required key material otherwise.
    pub device_check: Option<DeviceCheckConfig>,
    /// Payment lane (the eligibility slice's PAYMENT_REQUIRED quote). `None`
    /// while `PAYMENT_LANE_ENABLED=false` — device-gate blocks then keep the
    /// frozen bare `PAYMENT_REQUIRED` body (a dead end); enabled, blocks
    /// return a deposit address + amount and store the claim for the watcher.
    pub payment: Option<PaymentConfig>,
    /// Widevine dedup gate; `None` while `WIDEVINE_DEDUP_ENABLED=false`, in
    /// which case the evidence fields are ignored entirely.
    pub widevine: Option<WidevineConfig>,
}

/// Widevine dedup parameters (all under `WIDEVINE_DEDUP_ENABLED=true`).
#[derive(Debug)]
pub struct WidevineConfig {
    /// `WIDEVINE_DEDUP_ENFORCE`: soft mode verifies and logs only; `true`
    /// makes the dedup routing live.
    pub enforce: bool,
    /// 32-byte HMAC-SHA256 key (`WIDEVINE_DEDUP_HMAC_KEY`) pseudonymizing
    /// the client-hashed device id before storage.
    pub hmac_key: SecretBox<[u8; 32]>,
}

/// Payment-lane parameters (all required when `PAYMENT_LANE_ENABLED=true`).
#[derive(Debug, Clone)]
pub struct PaymentConfig {
    /// Cold master account (`PAYMENT_MASTER_ACCOUNT`, SS58): deposit
    /// addresses are its threshold-1 multisigs with a keyless per-subject
    /// dummy; the service never holds a key for it or the deposits.
    pub master_account: [u8; 32],
    /// Required deposit per registration in planck
    /// (`PAYMENT_AMOUNT_PLANCK`, > 0; must clear the existential deposit).
    pub amount_planck: u64,
    /// Quote lifetime (`PAYMENT_REQUEST_TTL_SECS`); an unpaid request past
    /// this expires and the client must re-claim.
    pub request_ttl: Duration,
}

/// Apple DeviceCheck key material and endpoint (legacy env names).
#[derive(Debug, Clone)]
pub struct DeviceCheckConfig {
    /// Apple Developer team id (`APPLE_TEAM_ID`) — the JWT issuer.
    pub team_id: String,
    /// DeviceCheck key id (`DEVICE_CHECK_KEY_ID`) — the JWT `kid`.
    pub key_id: String,
    /// DeviceCheck `.p8` private key PEM (`DEVICE_CHECK_PRIVATE_KEY`).
    pub private_key_pem: SecretString,
    /// API base URL (`DEVICE_CHECK_URL`); production Apple by default.
    pub base_url: String,
}

/// A required or malformed configuration value; surfaced at startup.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("required environment variable {0} is not set")]
    Missing(&'static str),
    #[error("environment variable {key} is invalid: {reason}")]
    Invalid { key: &'static str, reason: String },
}

impl Config {
    /// Read and validate configuration from the environment.
    ///
    /// Fails (rather than defaulting) for `DEVICE_ATTESTATION_DATABASE_URL`
    /// and `JWT_ED25519_SECRET`; everything else has a safe local default.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = parse_var("BIND_ADDR", "0.0.0.0:8080")?;
        let database_url = std::env::var("DEVICE_ATTESTATION_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or(ConfigError::Missing("DEVICE_ATTESTATION_DATABASE_URL"))?;
        let jwt_secret = parse_jwt_secret()?;

        let auth_enabled = env_bool("AUTH_ENABLED", false)?;
        let apple_app_attest_app_ids = env_list("APPLE_APP_ATTEST_APP_IDS");
        let ios_package_names = env_list("IOS_PACKAGE_NAMES");
        let android_package_names = env_list("ANDROID_PACKAGE_NAMES");
        let android_signing_digest_playstore =
            parse_signing_digest("ANDROID_SIGNING_DIGEST_PLAYSTORE")?;
        let android_signing_digest_website =
            parse_signing_digest("ANDROID_SIGNING_DIGEST_WEBSITE")?;
        let play_integrity_decryption_key = parse_play_integrity_decryption_key()?;
        let play_integrity_verification_key = parse_play_integrity_verification_key()?;
        // The self-managed keys only work as a pair; exactly one set is a
        // deployment error that would silently re-route verification.
        if play_integrity_decryption_key.is_some() != play_integrity_verification_key.is_some() {
            return Err(ConfigError::Invalid {
                key: "PLAY_INTEGRITY_DECRYPTION_KEY",
                reason: "PLAY_INTEGRITY_DECRYPTION_KEY and PLAY_INTEGRITY_VERIFICATION_KEY \
                         must be set together"
                    .to_string(),
            });
        }
        // 2026-01-28 lesson: attestation-on with no verifiable App ID must stop
        // the process loudly, not silently reject every iOS device.
        if auth_enabled && apple_app_attest_app_ids.is_empty() {
            return Err(ConfigError::Missing("APPLE_APP_ATTEST_APP_IDS"));
        }
        if auth_enabled && ios_package_names.is_empty() {
            return Err(ConfigError::Missing("IOS_PACKAGE_NAMES"));
        }
        // Same rule for Android: without these every key-attestation verdict
        // fails its packageName / signing-digest check.
        if auth_enabled && android_package_names.is_empty() {
            return Err(ConfigError::Missing("ANDROID_PACKAGE_NAMES"));
        }
        if auth_enabled && android_signing_digest_playstore.is_none() {
            return Err(ConfigError::Missing("ANDROID_SIGNING_DIGEST_PLAYSTORE"));
        }
        if auth_enabled && android_signing_digest_website.is_none() {
            return Err(ConfigError::Missing("ANDROID_SIGNING_DIGEST_WEBSITE"));
        }

        let enforce_auth = env_bool("ENFORCE_AUTH", false)?;
        let widevine = parse_widevine()?;
        // Warn, not fatal: an advisory rollout stage is deliberate.
        if widevine.as_ref().is_some_and(|w| w.enforce) && !(auth_enabled && enforce_auth) {
            tracing::warn!(
                auth_enabled,
                enforce_auth,
                "WIDEVINE_DEDUP_ENFORCE is set without hard attestation \
                 (AUTH_ENABLED + ENFORCE_AUTH); the dedup gate is advisory \
                 in this configuration"
            );
        }

        Ok(Self {
            bind_addr,
            database_url: SecretString::from(database_url),
            jwt_secret: SecretBox::new(Box::new(jwt_secret)),
            jwt_issuer: std::env::var("JWT_ISSUER").unwrap_or_else(|_| "polkadot-app".to_string()),
            people_rpc_url: std::env::var("PEOPLE_RPC_URL")
                .unwrap_or_else(|_| "wss://previewnet.substrate.dev/people".to_string()),
            attester_account: attester_account_from_env()?,
            access_ttl: Duration::from_secs(parse_var("ACCESS_TOKEN_TTL_SECS", "86400")?),
            refresh_ttl: Duration::from_secs(parse_var("REFRESH_TOKEN_TTL_SECS", "2592000")?),
            challenge_ttl: Duration::from_secs(parse_var("CHALLENGE_TTL_SECS", "300")?),
            auth_rate_limit: parse_var("AUTH_RATE_LIMIT", "30")?,
            auth_rate_window: Duration::from_secs(parse_var("AUTH_RATE_WINDOW_SECS", "60")?),
            auth_enabled,
            enforce_auth,
            queue_enabled: env_bool("QUEUE_ENABLED", false)?,
            registration_vouchers_enabled: env_bool("REGISTRATION_VOUCHERS_ENABLED", false)?,
            // Defaults off in code while `.env.example` and `docker-compose.yml` ship it
            // on: their PEOPLE_RPC_URL and ASSET_HUB_RPC_URL name the same network, which
            // is what makes the lane safe. A bare process has no such pairing, so the
            // fallback stays conservative. Must match the writer's default.
            dotns_gateway_enabled: env_bool("DOTNS_GATEWAY_ENABLED", false)?,
            dotns_intake_freshness_max_age_secs: parse_var(
                "DOTNS_INTAKE_FRESHNESS_MAX_AGE_SECS",
                "600",
            )?,
            // 30s matches the gateway pallet's MaxFutureSkewSeconds
            dotns_max_future_skew_secs: parse_var("DOTNS_MAX_FUTURE_SKEW_SECS", "30")?,
            apple_app_attest_app_ids,
            ios_package_names,
            android_package_names,
            android_signing_digest_playstore,
            android_signing_digest_website,
            android_crl_url: std::env::var("ANDROID_ATTESTATION_CRL_URL").unwrap_or_else(|_| {
                "https://android.googleapis.com/attestation/status".to_string()
            }),
            android_crl_cache_ttl: Duration::from_secs(parse_var(
                "ANDROID_ATTESTATION_CRL_CACHE_TTL_SECS",
                "3600",
            )?),
            android_crl_max_stale: Duration::from_secs(parse_var(
                "ANDROID_ATTESTATION_CRL_MAX_STALE_SECS",
                "3600",
            )?),
            play_integrity_mode: parse_var("PLAY_INTEGRITY_MODE", "strict")?,
            play_integrity_decryption_key: play_integrity_decryption_key
                .map(|k| SecretBox::new(Box::new(k))),
            play_integrity_verification_key,
            google_credentials: parse_google_credentials()?,
            device_check: parse_device_check()?,
            payment: parse_payment()?,
            widevine: parse_widevine()?,
        })
    }

    /// A fully-populated config for unit tests (no environment access).
    #[doc(hidden)]
    pub fn test_default() -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().expect("valid addr"),
            database_url: SecretString::from("unused".to_string()),
            jwt_secret: SecretBox::new(Box::new([7u8; 32])),
            jwt_issuer: "polkadot-app".to_string(),
            people_rpc_url: "unused".to_string(),
            attester_account: [0xaa; 32],
            access_ttl: Duration::from_secs(86_400),
            refresh_ttl: Duration::from_secs(2_592_000),
            challenge_ttl: Duration::from_secs(300),
            auth_rate_limit: 1_000,
            auth_rate_window: Duration::from_secs(60),
            auth_enabled: false,
            enforce_auth: false,
            queue_enabled: false,
            registration_vouchers_enabled: false,
            dotns_gateway_enabled: true,
            dotns_intake_freshness_max_age_secs: 600,
            dotns_max_future_skew_secs: 600,
            apple_app_attest_app_ids: Vec::new(),
            ios_package_names: Vec::new(),
            android_package_names: Vec::new(),
            android_signing_digest_playstore: None,
            android_signing_digest_website: None,
            android_crl_url: "https://android.googleapis.com/attestation/status".to_string(),
            android_crl_cache_ttl: Duration::from_secs(3_600),
            android_crl_max_stale: Duration::from_secs(3_600),
            play_integrity_mode: crate::auth::play_integrity::PlayIntegrityMode::Strict,
            play_integrity_decryption_key: None,
            play_integrity_verification_key: None,
            google_credentials: None,
            device_check: None,
            payment: None,
            widevine: None,
        }
    }

    /// Human-readable attestation posture for startup logs and `/readyz` detail.
    pub fn attestation_mode(&self) -> &'static str {
        match (self.auth_enabled, self.enforce_auth) {
            (false, _) => "disabled (attestation is a no-op; JWT still issued)",
            (true, false) => "soft (verdicts logged, not enforced)",
            (true, true) => "hard (bad or missing attestation rejected)",
        }
    }
}

/// Parse `JWT_ED25519_SECRET` (hex or base64) into a 32-byte Ed25519 seed.
fn parse_jwt_secret() -> Result<[u8; 32], ConfigError> {
    let raw = std::env::var("JWT_ED25519_SECRET")
        .map_err(|_| ConfigError::Missing("JWT_ED25519_SECRET"))?;
    decode_jwt_secret(&raw)
}

/// Decode a JWT signing seed: hex (optional `0x`) or base64, exactly 32 bytes.
fn decode_jwt_secret(raw: &str) -> Result<[u8; 32], ConfigError> {
    use base64::Engine as _;

    let trimmed = raw.trim();
    let bytes = hex::decode(trimmed.strip_prefix("0x").unwrap_or(trimmed))
        .ok()
        .or_else(|| {
            base64::engine::general_purpose::STANDARD
                .decode(trimmed)
                .ok()
        })
        .ok_or_else(|| ConfigError::Invalid {
            key: "JWT_ED25519_SECRET",
            reason: "expected 32 bytes as hex or base64".to_string(),
        })?;

    bytes.try_into().map_err(|_| ConfigError::Invalid {
        key: "JWT_ED25519_SECRET",
        reason: "decoded secret must be exactly 32 bytes".to_string(),
    })
}

/// Parse `ATTESTER_ACCOUNT` (SS58) into the raw 32-byte account.
///
/// Shared by device-attestation-api and device-attestation-chain-writer: clients bind their
/// registration signature to the published key, so a separately-configured
/// attester drifts into `PeopleLite::InvalidAttestationSignature`. The `0x`+hex
/// wire form is derived from this, never configured.
pub(crate) fn attester_account_from_env() -> Result<[u8; 32], ConfigError> {
    let raw =
        std::env::var("ATTESTER_ACCOUNT").map_err(|_| ConfigError::Missing("ATTESTER_ACCOUNT"))?;
    parse_attester_account(&raw)
}

/// Decode one SS58 attester account into its raw 32 bytes.
fn parse_attester_account(raw: &str) -> Result<[u8; 32], ConfigError> {
    let account = AccountId32::from_str(raw.trim()).map_err(|e| ConfigError::Invalid {
        key: "ATTESTER_ACCOUNT",
        reason: format!("expected an SS58 account: {e}"),
    })?;
    Ok(account.0)
}

/// Parse an optional Android signing-certificate SHA-256 fingerprint env var.
///
/// Accepts the colon-separated uppercase form published in Play Console
/// (`5A:A3:…`) as well as bare hex; normalises to 32 raw bytes.
fn parse_signing_digest(key: &'static str) -> Result<Option<[u8; 32]>, ConfigError> {
    let Ok(raw) = std::env::var(key) else {
        return Ok(None);
    };
    decode_signing_digest(key, &raw)
}

/// Decode a signing-certificate fingerprint: colon-separated or bare hex, any
/// case; blank means "not configured".
fn decode_signing_digest(key: &'static str, raw: &str) -> Result<Option<[u8; 32]>, ConfigError> {
    let normalized = raw.trim().to_ascii_lowercase().replace(':', "");
    if normalized.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(&normalized).map_err(|e| ConfigError::Invalid {
        key,
        reason: format!("expected hex: {e}"),
    })?;
    let digest: [u8; 32] = bytes.try_into().map_err(|_| ConfigError::Invalid {
        key,
        reason: "expected a 32-byte SHA-256 fingerprint".to_string(),
    })?;
    Ok(Some(digest))
}

/// Parse the optional base64 AES-256 `PLAY_INTEGRITY_DECRYPTION_KEY`.
fn parse_play_integrity_decryption_key() -> Result<Option<[u8; 32]>, ConfigError> {
    let Ok(raw) = std::env::var("PLAY_INTEGRITY_DECRYPTION_KEY") else {
        return Ok(None);
    };
    decode_play_integrity_decryption_key(&raw)
}

/// Decode the AES-256 decryption key: base64, exactly 32 bytes; blank means
/// "not configured".
fn decode_play_integrity_decryption_key(raw: &str) -> Result<Option<[u8; 32]>, ConfigError> {
    use base64::Engine as _;

    const KEY: &str = "PLAY_INTEGRITY_DECRYPTION_KEY";
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| ConfigError::Invalid {
            key: KEY,
            reason: format!("expected base64: {e}"),
        })?;
    let key = bytes.try_into().map_err(|_| ConfigError::Invalid {
        key: KEY,
        reason: "expected a 32-byte AES-256 key".to_string(),
    })?;
    Ok(Some(key))
}

/// Parse the optional base64 DER-SPKI `PLAY_INTEGRITY_VERIFICATION_KEY`,
/// validating it decodes to an EC P-256 public key at startup.
fn parse_play_integrity_verification_key() -> Result<Option<Vec<u8>>, ConfigError> {
    let Ok(raw) = std::env::var("PLAY_INTEGRITY_VERIFICATION_KEY") else {
        return Ok(None);
    };
    decode_play_integrity_verification_key(&raw)
}

/// Decode and validate the verification key: base64 DER SPKI holding an EC
/// P-256 public key; blank means "not configured".
fn decode_play_integrity_verification_key(raw: &str) -> Result<Option<Vec<u8>>, ConfigError> {
    use base64::Engine as _;
    use p256::pkcs8::DecodePublicKey as _;

    const KEY: &str = "PLAY_INTEGRITY_VERIFICATION_KEY";
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| ConfigError::Invalid {
            key: KEY,
            reason: format!("expected base64: {e}"),
        })?;
    p256::ecdsa::VerifyingKey::from_public_key_der(&der).map_err(|e| ConfigError::Invalid {
        key: KEY,
        reason: format!("expected DER SPKI EC P-256 public key: {e}"),
    })?;
    Ok(Some(der))
}

/// Parse the optional legacy `GOOGLE_CREDENTIALS` (base64 service-account
/// JSON) for the temporary Play Integrity Google-API fallback.
fn parse_google_credentials(
) -> Result<Option<crate::auth::play_integrity::google::GoogleCredentials>, ConfigError> {
    const KEY: &str = "GOOGLE_CREDENTIALS";
    let Ok(raw) = std::env::var(KEY) else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    crate::auth::play_integrity::google::GoogleCredentials::parse(&raw)
        .map(Some)
        .map_err(|reason| ConfigError::Invalid { key: KEY, reason })
}

/// Parse the DeviceCheck block: `None` while `DEVICE_CHECK_IOS_ENABLED` is
/// false; enabled, the legacy vars are required and the key must be a usable
/// EC PEM (fail-fast).
fn parse_device_check() -> Result<Option<DeviceCheckConfig>, ConfigError> {
    if !env_bool("DEVICE_CHECK_IOS_ENABLED", false)? {
        return Ok(None);
    }
    let require = |key: &'static str| -> Result<String, ConfigError> {
        std::env::var(key)
            .map(|v| v.trim().to_string())
            .ok()
            .filter(|v| !v.is_empty())
            .ok_or(ConfigError::Missing(key))
    };
    let private_key_pem = validate_device_check_pem(&require("DEVICE_CHECK_PRIVATE_KEY")?)?;
    Ok(Some(DeviceCheckConfig {
        team_id: require("APPLE_TEAM_ID")?,
        key_id: require("DEVICE_CHECK_KEY_ID")?,
        private_key_pem: SecretString::from(private_key_pem),
        base_url: std::env::var("DEVICE_CHECK_URL")
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .unwrap_or_else(|_| "https://api.devicecheck.apple.com/v1".to_string()),
    }))
}

/// Unescape (`\n` from single-line env injection) and validate a DeviceCheck
/// `.p8` private key, insisting on a usable EC PEM (fail-fast).
fn validate_device_check_pem(raw: &str) -> Result<String, ConfigError> {
    let private_key_pem = raw.replace("\\n", "\n");
    jsonwebtoken::EncodingKey::from_ec_pem(private_key_pem.as_bytes()).map_err(|e| {
        ConfigError::Invalid {
            key: "DEVICE_CHECK_PRIVATE_KEY",
            reason: format!("not a usable EC private key PEM: {e}"),
        }
    })?;
    Ok(private_key_pem)
}

/// Parse the payment-lane block: `None` while `PAYMENT_LANE_ENABLED` is
/// false; enabled, the master account and amount are required and validated
/// (fail-fast — a mistyped master would quote unsweepable addresses).
fn parse_payment() -> Result<Option<PaymentConfig>, ConfigError> {
    if !env_bool("PAYMENT_LANE_ENABLED", false)? {
        return Ok(None);
    }
    let master_raw = std::env::var("PAYMENT_MASTER_ACCOUNT")
        .map(|v| v.trim().to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or(ConfigError::Missing("PAYMENT_MASTER_ACCOUNT"))?;
    let master_account = decode_payment_master(&master_raw)?;
    let amount_raw = std::env::var("PAYMENT_AMOUNT_PLANCK")
        .map_err(|_| ConfigError::Missing("PAYMENT_AMOUNT_PLANCK"))?;
    let amount_planck = decode_payment_amount(&amount_raw)?;
    Ok(Some(PaymentConfig {
        master_account,
        amount_planck,
        request_ttl: Duration::from_secs(parse_var("PAYMENT_REQUEST_TTL_SECS", "86400")?),
    }))
}

/// Decode the cold master account from SS58.
fn decode_payment_master(raw: &str) -> Result<[u8; 32], ConfigError> {
    use std::str::FromStr as _;

    Ok(subxt::utils::AccountId32::from_str(raw)
        .map_err(|e| ConfigError::Invalid {
            key: "PAYMENT_MASTER_ACCOUNT",
            reason: format!("expected an SS58 address: {e}"),
        })?
        .0)
}

/// Decode the per-registration deposit: a positive planck amount that the
/// quote row's BIGINT column can hold (refused at startup rather than letting
/// the insert clamp or fail late).
fn decode_payment_amount(raw: &str) -> Result<u64, ConfigError> {
    let amount_planck: u64 = raw.trim().parse().map_err(|e| ConfigError::Invalid {
        key: "PAYMENT_AMOUNT_PLANCK",
        reason: format!("expected planck as an integer: {e}"),
    })?;
    if amount_planck == 0 {
        return Err(ConfigError::Invalid {
            key: "PAYMENT_AMOUNT_PLANCK",
            reason: "must be greater than zero".to_string(),
        });
    }
    if i64::try_from(amount_planck).is_err() {
        return Err(ConfigError::Invalid {
            key: "PAYMENT_AMOUNT_PLANCK",
            reason: "must fit a signed 64-bit integer (database BIGINT)".to_string(),
        });
    }
    Ok(amount_planck)
}

/// Parse the Widevine dedup block: `None` while `WIDEVINE_DEDUP_ENABLED` is
/// false; enabled, the HMAC key is required and validated (fail-fast — a
/// missing key would make every device record uncomputable).
fn parse_widevine() -> Result<Option<WidevineConfig>, ConfigError> {
    if !env_bool("WIDEVINE_DEDUP_ENABLED", false)? {
        return Ok(None);
    }
    let raw = std::env::var("WIDEVINE_DEDUP_HMAC_KEY")
        .map(|v| v.trim().to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or(ConfigError::Missing("WIDEVINE_DEDUP_HMAC_KEY"))?;
    Ok(Some(WidevineConfig {
        enforce: env_bool("WIDEVINE_DEDUP_ENFORCE", false)?,
        hmac_key: decode_widevine_hmac_key(&raw)?,
    }))
}

/// Decode `WIDEVINE_DEDUP_HMAC_KEY`: one 32-byte key as hex (optional `0x`)
/// or base64.
fn decode_widevine_hmac_key(raw: &str) -> Result<SecretBox<[u8; 32]>, ConfigError> {
    use base64::Engine as _;

    const KEY: &str = "WIDEVINE_DEDUP_HMAC_KEY";
    let invalid = |reason: String| ConfigError::Invalid { key: KEY, reason };

    let bytes = hex::decode(raw.strip_prefix("0x").unwrap_or(raw))
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD.decode(raw).ok())
        .ok_or_else(|| invalid("expected hex or base64".to_string()))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid("key must be exactly 32 bytes".to_string()))?;
    Ok(SecretBox::new(Box::new(key)))
}

/// Parse an env var into `T`, falling back to `default` when unset.
fn parse_var<T>(key: &'static str, default: &str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let raw = std::env::var(key).unwrap_or_else(|_| default.to_string());
    raw.parse().map_err(|e: T::Err| ConfigError::Invalid {
        key,
        reason: e.to_string(),
    })
}

/// Strict boolean env parsing. A missing variable takes `default`; a present
/// value must be one of the accepted tokens (a case-insensitive superset of the
/// legacy Effect `Config.boolean` values). An unrecognized value aborts startup
/// rather than silently disabling a security gate (e.g. `AUTH_ENABLED=treu`).
pub(crate) fn env_bool(key: &'static str, default: bool) -> Result<bool, ConfigError> {
    let Ok(raw) = std::env::var(key) else {
        return Ok(default);
    };
    parse_bool(raw.trim()).ok_or_else(|| ConfigError::Invalid {
        key,
        reason: format!("expected a boolean (true/false), got {:?}", raw.trim()),
    })
}

/// The accepted boolean tokens (case-insensitive). `None` = unrecognized, which
/// the caller turns into a startup error.
fn parse_bool(raw: &str) -> Option<bool> {
    match raw.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" | "y" => Some(true),
        "false" | "no" | "off" | "0" | "n" => Some(false),
        _ => None,
    }
}

/// Parse a comma-separated env var into trimmed, non-empty entries.
fn env_list(key: &str) -> Vec<String> {
    std::env::var(key)
        .map(|raw| split_list(&raw))
        .unwrap_or_default()
}

/// Split a comma-separated list into trimmed, non-empty entries.
fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_secrets() {
        let mut config = Config::test_default();
        config.database_url =
            SecretString::from("postgres://user:SUPER_SECRET_PW@localhost/db".to_string());
        config.play_integrity_decryption_key = Some(SecretBox::new(Box::new([9u8; 32])));
        config.device_check = Some(DeviceCheckConfig {
            team_id: "TEAM123".to_string(),
            key_id: "KEY123".to_string(),
            private_key_pem: SecretString::from("BEGIN P8_SECRET_MATERIAL END".to_string()),
            base_url: "https://api.devicecheck.apple.com".to_string(),
        });

        let rendered = format!("{config:?}");

        assert!(!rendered.contains("SUPER_SECRET_PW"), "database URL leaked");
        assert!(
            !rendered.contains("P8_SECRET_MATERIAL"),
            "DeviceCheck key leaked"
        );
        assert!(rendered.contains("REDACTED"));
        assert!(rendered.contains("TEAM123"));

        let dc = format!("{:?}", config.device_check.unwrap());
        assert!(!dc.contains("P8_SECRET_MATERIAL"));
        assert!(dc.contains("REDACTED"));
    }

    #[test]
    fn jwt_secret_decodes_hex_and_base64_to_exactly_32_bytes() {
        use base64::Engine as _;

        let seed = [3u8; 32];
        let hex_raw = hex::encode(seed);
        assert_eq!(decode_jwt_secret(&hex_raw).unwrap(), seed);
        assert_eq!(decode_jwt_secret(&format!("0x{hex_raw}")).unwrap(), seed);
        assert_eq!(decode_jwt_secret(&format!("  {hex_raw}\n")).unwrap(), seed);
        let b64_raw = base64::engine::general_purpose::STANDARD.encode(seed);
        assert_eq!(decode_jwt_secret(&b64_raw).unwrap(), seed);

        let err = decode_jwt_secret("not-a-key!").unwrap_err();
        assert!(err.to_string().contains("JWT_ED25519_SECRET"), "{err}");
        let err = decode_jwt_secret(&hex::encode([3u8; 16])).unwrap_err();
        assert!(err.to_string().contains("exactly 32 bytes"), "{err}");
    }

    #[test]
    fn attester_account_parses_ss58_and_rejects_hex() {
        const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        const ALICE_HEX: &str = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

        let want: [u8; 32] = hex::decode(ALICE_HEX).unwrap().try_into().unwrap();
        assert_eq!(parse_attester_account(ALICE_SS58).unwrap(), want);
        assert_eq!(
            parse_attester_account(&format!("  {ALICE_SS58}  ")).unwrap(),
            want
        );

        let err = parse_attester_account(&format!("0x{ALICE_HEX}")).unwrap_err();
        assert!(err.to_string().contains("ATTESTER_ACCOUNT"), "{err}");
        let err = parse_attester_account("not-an-account").unwrap_err();
        assert!(
            err.to_string().contains("expected an SS58 account"),
            "{err}"
        );
    }

    #[test]
    fn signing_digest_accepts_play_console_and_bare_hex_forms() {
        const KEY: &str = "ANDROID_SIGNING_DIGEST_PLAYSTORE";
        let digest = [0x5Au8; 32];
        let colons = digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(decode_signing_digest(KEY, &colons).unwrap(), Some(digest));
        assert_eq!(
            decode_signing_digest(KEY, &hex::encode(digest)).unwrap(),
            Some(digest)
        );
        assert_eq!(decode_signing_digest(KEY, "   ").unwrap(), None);

        let err = decode_signing_digest(KEY, "not hex").unwrap_err();
        assert!(err.to_string().contains(KEY), "{err}");
        let err = decode_signing_digest(KEY, &hex::encode([1u8; 20])).unwrap_err();
        assert!(err.to_string().contains("32-byte SHA-256"), "{err}");
    }

    #[test]
    fn play_integrity_decryption_key_wants_32_base64_bytes() {
        use base64::Engine as _;

        let key = [9u8; 32];
        let raw = base64::engine::general_purpose::STANDARD.encode(key);
        assert_eq!(
            decode_play_integrity_decryption_key(&raw).unwrap(),
            Some(key)
        );
        assert_eq!(decode_play_integrity_decryption_key("").unwrap(), None);

        let err = decode_play_integrity_decryption_key("!!!").unwrap_err();
        assert!(err.to_string().contains("expected base64"), "{err}");
        let short = base64::engine::general_purpose::STANDARD.encode([9u8; 16]);
        let err = decode_play_integrity_decryption_key(&short).unwrap_err();
        assert!(err.to_string().contains("32-byte AES-256"), "{err}");
    }

    #[test]
    fn play_integrity_verification_key_must_be_der_spki_p256() {
        use base64::Engine as _;
        use p256::pkcs8::EncodePublicKey as _;

        let der = p256::SecretKey::from_slice(&[7u8; 32])
            .expect("valid scalar")
            .public_key()
            .to_public_key_der()
            .expect("encode SPKI")
            .into_vec();
        let raw = base64::engine::general_purpose::STANDARD.encode(&der);
        assert_eq!(
            decode_play_integrity_verification_key(&raw).unwrap(),
            Some(der)
        );
        assert_eq!(decode_play_integrity_verification_key(" ").unwrap(), None);

        let junk = base64::engine::general_purpose::STANDARD.encode([1u8; 40]);
        let err = decode_play_integrity_verification_key(&junk).unwrap_err();
        assert!(err.to_string().contains("EC P-256"), "{err}");
    }

    #[test]
    fn device_check_pem_unescapes_and_validates() {
        let pem = rcgen::KeyPair::generate()
            .expect("generate EC key")
            .serialize_pem();
        assert_eq!(validate_device_check_pem(&pem).unwrap(), pem);
        let escaped = pem.replace('\n', "\\n");
        assert_eq!(validate_device_check_pem(&escaped).unwrap(), pem);

        let err = validate_device_check_pem("garbage").unwrap_err();
        assert!(
            err.to_string().contains("not a usable EC private key PEM"),
            "{err}"
        );
    }

    #[test]
    fn payment_master_decodes_ss58() {
        let alice = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let want: [u8; 32] =
            hex::decode("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(decode_payment_master(alice).unwrap(), want);

        let err = decode_payment_master("not-an-address").unwrap_err();
        assert!(
            err.to_string().contains("expected an SS58 address"),
            "{err}"
        );
    }

    #[test]
    fn payment_amount_is_positive_and_bigint_safe() {
        assert_eq!(
            decode_payment_amount(" 1000000000 ").unwrap(),
            1_000_000_000
        );

        let err = decode_payment_amount("0").unwrap_err();
        assert!(err.to_string().contains("greater than zero"), "{err}");
        let err = decode_payment_amount("ten").unwrap_err();
        assert!(err.to_string().contains("expected planck"), "{err}");
        let err = decode_payment_amount(&u64::MAX.to_string()).unwrap_err();
        assert!(err.to_string().contains("signed 64-bit"), "{err}");
    }

    #[test]
    fn widevine_hmac_key_decodes_a_32_byte_key() {
        use base64::Engine as _;
        use secrecy::ExposeSecret as _;

        let hex_key = hex::encode([1u8; 32]);
        let b64_key = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
        assert_eq!(
            *decode_widevine_hmac_key(&format!("0x{hex_key}"))
                .expect("hex")
                .expose_secret(),
            [1u8; 32]
        );
        assert_eq!(
            *decode_widevine_hmac_key(&b64_key)
                .expect("base64")
                .expose_secret(),
            [2u8; 32]
        );

        // Wrong length, not a key at all.
        assert!(decode_widevine_hmac_key(&hex::encode([1u8; 16])).is_err());
        assert!(decode_widevine_hmac_key("not-a-key!").is_err());
    }

    #[test]
    fn split_list_trims_and_drops_empties() {
        assert_eq!(split_list(" a , ,b,, c "), vec!["a", "b", "c"]);
        assert!(split_list("").is_empty());
        assert!(split_list(" , ,").is_empty());
    }

    #[test]
    fn attestation_mode_tracks_both_gates() {
        let mut config = Config::test_default();
        assert!(config.attestation_mode().starts_with("disabled"));
        config.auth_enabled = true;
        assert!(config.attestation_mode().starts_with("soft"));
        config.enforce_auth = true;
        assert!(config.attestation_mode().starts_with("hard"));
    }

    #[test]
    fn from_env_fails_fast_and_gates_requireds_on_auth_enabled() {
        use base64::Engine as _;

        const VARS: &[&str] = &[
            "DEVICE_ATTESTATION_DATABASE_URL",
            "JWT_ED25519_SECRET",
            "ATTESTER_ACCOUNT",
            "AUTH_ENABLED",
            "APPLE_APP_ATTEST_APP_IDS",
            "IOS_PACKAGE_NAMES",
            "ANDROID_PACKAGE_NAMES",
            "ANDROID_SIGNING_DIGEST_PLAYSTORE",
            "ANDROID_SIGNING_DIGEST_WEBSITE",
            "PLAY_INTEGRITY_DECRYPTION_KEY",
            "PLAY_INTEGRITY_VERIFICATION_KEY",
        ];
        let _guard = crate::ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let clear = || VARS.iter().for_each(|k| std::env::remove_var(k));
        let missing = |key: &str| {
            let err = Config::from_env().expect_err(key);
            assert!(
                matches!(err, ConfigError::Missing(k) if k == key),
                "want Missing({key}), got {err}"
            );
        };
        clear();

        missing("DEVICE_ATTESTATION_DATABASE_URL");
        std::env::set_var("DEVICE_ATTESTATION_DATABASE_URL", "postgres://unused");
        missing("JWT_ED25519_SECRET");
        std::env::set_var("JWT_ED25519_SECRET", hex::encode([1u8; 32]));
        missing("ATTESTER_ACCOUNT");
        std::env::set_var(
            "ATTESTER_ACCOUNT",
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        );

        let config = Config::from_env().expect("minimal env");
        assert_eq!(config.bind_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(config.jwt_issuer, "polkadot-app");
        assert!(!config.auth_enabled);
        assert!(
            !config.dotns_gateway_enabled,
            "the gateway is opt-in; a minimal environment must not claim dotNS labels"
        );
        let alice: [u8; 32] =
            hex::decode("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(config.attester_account, alice);
        assert!(config.payment.is_none());
        assert!(config.device_check.is_none());
        assert!(config.widevine.is_none());

        std::env::set_var(
            "PLAY_INTEGRITY_DECRYPTION_KEY",
            base64::engine::general_purpose::STANDARD.encode([9u8; 32]),
        );
        let err = Config::from_env().expect_err("unpaired key");
        assert!(err.to_string().contains("must be set together"), "{err}");
        std::env::remove_var("PLAY_INTEGRITY_DECRYPTION_KEY");

        std::env::set_var("AUTH_ENABLED", "true");
        missing("APPLE_APP_ATTEST_APP_IDS");
        std::env::set_var("APPLE_APP_ATTEST_APP_IDS", "TEAM123.app.bundle");
        missing("IOS_PACKAGE_NAMES");
        std::env::set_var("IOS_PACKAGE_NAMES", "app.bundle");
        missing("ANDROID_PACKAGE_NAMES");
        std::env::set_var("ANDROID_PACKAGE_NAMES", "com.example.app, com.example.beta");
        missing("ANDROID_SIGNING_DIGEST_PLAYSTORE");
        std::env::set_var("ANDROID_SIGNING_DIGEST_PLAYSTORE", "AA".repeat(32));
        missing("ANDROID_SIGNING_DIGEST_WEBSITE");
        std::env::set_var("ANDROID_SIGNING_DIGEST_WEBSITE", "BB".repeat(32));
        let config = Config::from_env().expect("full auth env");
        assert!(config.auth_enabled);
        assert_eq!(
            config.android_package_names,
            vec!["com.example.app", "com.example.beta"]
        );
        assert_eq!(config.android_signing_digest_playstore, Some([0xAA; 32]));
        assert_eq!(config.android_signing_digest_website, Some([0xBB; 32]));

        clear();
    }

    #[test]
    fn parse_bool_is_strict() {
        for t in ["true", "TRUE", "yes", "on", "1", "y"] {
            assert_eq!(parse_bool(t), Some(true), "{t:?} should be true");
        }
        for f in ["false", "No", "off", "0", "n"] {
            assert_eq!(parse_bool(f), Some(false), "{f:?} should be false");
        }
        for bad in ["treu", "tru", "", "2", "enabled", "t"] {
            assert_eq!(parse_bool(bad), None, "{bad:?} should be rejected");
        }
    }
}
