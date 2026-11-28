// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

mod workload_token;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use self::workload_token::{WorkloadTokens, METADATA_TOKEN_URL};
use super::token::TokenPayload;

const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const PLAY_INTEGRITY_API: &str = "https://playintegrity.googleapis.com";
/// The only scope `decodeIntegrityToken` accepts (its discovery document lists
/// no other), so a workload's own `cloud-platform` token cannot call it: one
/// with this scope is minted through the IAM Credentials API instead.
const PLAY_INTEGRITY_SCOPE: &str = "https://www.googleapis.com/auth/playintegrity";
const IAM_CREDENTIALS_API: &str = "https://iamcredentials.googleapis.com";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const TOKEN_REFRESH_BUFFER_SECS: i64 = 60;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Lifetime asked of a minted token: Google's default and maximum.
const MINTED_LIFETIME: Duration = Duration::from_secs(3600);
/// Refetch a minted token this long before it expires.
const MINTED_REFRESH_BUFFER: Duration = Duration::from_secs(225);
const IAM_BODY_MAX: usize = 64 * 1024;
/// How long a failed mint answers for the next callers instead of being
/// repeated, so a failing IAM API is not asked once per queued attestation.
const MINT_FAILURE_HOLD: Duration = Duration::from_secs(1);
/// What the app is told when no `playintegrity` token could be had. A
/// hard-mode rejection returns the reason to the client, so it names nothing;
/// the cause is in the log.
const TOKEN_UNAVAILABLE: &str = "play integrity token unavailable";
const LOGGED_BODY_MAX: usize = 512;

#[derive(Clone)]
pub struct GoogleCredentials {
    pub client_email: String,
    pub private_key: String,
}

impl std::fmt::Debug for GoogleCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleCredentials")
            .field("client_email", &self.client_email)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl GoogleCredentials {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        let json_bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .unwrap_or_else(|_| trimmed.as_bytes().to_vec());

        #[derive(Deserialize)]
        struct ServiceAccount {
            #[serde(default)]
            client_email: String,
            #[serde(default)]
            private_key: String,
        }
        let account: ServiceAccount = serde_json::from_slice(&json_bytes)
            .map_err(|e| format!("not valid service-account JSON: {e}"))?;
        if account.client_email.is_empty() || account.private_key.is_empty() {
            return Err("missing client_email or private_key".to_string());
        }
        EncodingKey::from_rsa_pem(account.private_key.as_bytes())
            .map_err(|e| format!("private_key is not a usable RSA PEM: {e}"))?;
        Ok(Self {
            client_email: account.client_email,
            private_key: account.private_key,
        })
    }
}

/// Whether `email` is a user-managed service account,
/// `<name>@<project>.iam.gserviceaccount.com`, in lowercase ASCII: the only
/// shape `PLAY_INTEGRITY_SERVICE_ACCOUNT` takes, and safe to place in a URL.
pub fn is_service_account_email(email: &str) -> bool {
    let id = |s: &str| {
        let b = s.as_bytes();
        (6..=30).contains(&b.len())
            && b[0].is_ascii_lowercase()
            && b[b.len() - 1] != b'-'
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
    };
    email
        .split_once('@')
        .and_then(|(name, domain)| Some((name, domain.strip_suffix(".iam.gserviceaccount.com")?)))
        .is_some_and(|(name, project)| id(name) && id(project))
}

#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MintedToken {
    access_token: String,
}

struct CachedToken {
    token: String,
    expires_at: i64,
}

struct CachedMinted {
    token: SecretString,
    /// Monotonic, so a wall-clock step cannot keep a token past its life.
    refresh_at: Instant,
    expires_at: Instant,
}

/// Why a mint failed, for the log, and whether it is likely to pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MintFailure {
    reason: &'static str,
    transient: bool,
}

/// The outcome of [`GoogleDecoder::check`].
#[derive(Debug, PartialEq, Eq)]
pub enum DecoderCheck {
    /// A service-account key: nothing to check at start-up.
    NotApplicable,
    /// A `playintegrity` token was minted for the named account.
    Ready,
    /// No token could be minted; Android attestations through this decoder
    /// fail until it is fixed.
    Unavailable(&'static str),
}

/// Where the decoder's `playintegrity` access token comes from.
enum TokenSource {
    /// A service-account key (`GOOGLE_CREDENTIALS`): a JWT-bearer assertion
    /// exchanged at Google's token endpoint.
    Key {
        credentials: GoogleCredentials,
        encoding_key: EncodingKey,
        token: Mutex<Option<CachedToken>>,
    },
    /// The workload's own identity (`PLAY_INTEGRITY_SERVICE_ACCOUNT`): its
    /// metadata-server token asks the IAM Credentials API for a
    /// `playintegrity` token of the named service account. No key is held.
    Impersonate(Box<Impersonation>),
}

struct Impersonation {
    service_account: String,
    metadata: WorkloadTokens,
    iam: reqwest::Client,
    iam_api: String,
    cached: Mutex<Option<CachedMinted>>,
    /// One mint at a time; callers that queue behind it take its token.
    refresh: tokio::sync::Mutex<()>,
    /// The last failed mint and when it failed.
    last_failure: Mutex<Option<(Instant, MintFailure)>>,
    failure_hold: Duration,
}

/// Where the decoder sends its requests. Fixed in production; tests point them
/// at a local server.
struct Endpoints {
    decode_api: String,
    iam_api: String,
    metadata_token: String,
    https_only: bool,
    failure_hold: Duration,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            decode_api: PLAY_INTEGRITY_API.to_string(),
            iam_api: IAM_CREDENTIALS_API.to_string(),
            metadata_token: METADATA_TOKEN_URL.to_string(),
            https_only: true,
            failure_hold: MINT_FAILURE_HOLD,
        }
    }
}

fn mint_failure(reason: &'static str, transient: bool) -> MintFailure {
    MintFailure { reason, transient }
}

pub struct GoogleDecoder {
    client: reqwest::Client,
    decode_api: String,
    source: TokenSource,
}

impl GoogleDecoder {
    /// A decoder authenticating with a service-account key.
    pub fn new(credentials: GoogleCredentials) -> Result<Self, String> {
        let encoding_key = EncodingKey::from_rsa_pem(credentials.private_key.as_bytes())
            .map_err(|e| format!("google credentials private key: {e}"))?;
        Self::with_source(
            TokenSource::Key {
                credentials,
                encoding_key,
                token: Mutex::new(None),
            },
            Endpoints::default().decode_api,
        )
    }

    /// A decoder authenticating as `service_account` with the workload's own
    /// identity (GKE Workload Identity), with no key.
    pub fn impersonating(service_account: &str) -> Result<Self, String> {
        Self::impersonating_at(service_account, Endpoints::default())
    }

    fn impersonating_at(service_account: &str, endpoints: Endpoints) -> Result<Self, String> {
        if !is_service_account_email(service_account) {
            return Err("not a user-managed service account email".to_string());
        }
        // The workload's token goes only to the IAM Credentials API over TLS:
        // no plain HTTP, no proxy from the environment, no redirects.
        let iam = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .https_only(endpoints.https_only)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        let metadata = WorkloadTokens::new(&endpoints.metadata_token)
            .map_err(|e| format!("http client: {e}"))?;
        Self::with_source(
            TokenSource::Impersonate(Box::new(Impersonation {
                service_account: service_account.to_string(),
                metadata,
                iam,
                iam_api: endpoints.iam_api.trim_end_matches('/').to_string(),
                cached: Mutex::new(None),
                refresh: tokio::sync::Mutex::new(()),
                last_failure: Mutex::new(None),
                failure_hold: endpoints.failure_hold,
            })),
            endpoints.decode_api,
        )
    }

    fn with_source(source: TokenSource, decode_api: String) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self {
            client,
            decode_api: decode_api.trim_end_matches('/').to_string(),
            source,
        })
    }

    /// A short, log-safe name for how this decoder authenticates.
    pub fn label(&self) -> &'static str {
        match self.source {
            TokenSource::Key { .. } => "service-account-key",
            TokenSource::Impersonate(_) => "workload-identity",
        }
    }

    pub async fn decode(
        &self,
        package_name: &str,
        integrity_token: &str,
    ) -> Result<TokenPayload, String> {
        let access_token = self.access_token().await?;
        let url = format!("{}/v1/{package_name}:decodeIntegrityToken", self.decode_api);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&access_token)
            .json(&serde_json::json!({ "integrityToken": integrity_token }))
            .send()
            .await
            .map_err(|e| format!("decodeIntegrityToken request failed: {e}"))?;

        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|e| format!("decodeIntegrityToken body: {e}"))?;
        if !status.is_success() {
            if let TokenSource::Impersonate(_) = self.source {
                // A minted token Play Integrity no longer accepts is dropped,
                // so the next request mints a new one instead of failing for
                // an hour.
                if status == reqwest::StatusCode::UNAUTHORIZED {
                    self.forget_minted(&access_token);
                }
                // Google's text can name the project (an API not enabled, a
                // project not linked); it goes to the log, not to the app.
                tracing::warn!(
                    status = status.as_u16(),
                    error = ?truncated(&google_error_message(&body), LOGGED_BODY_MAX),
                    "decodeIntegrityToken refused the workload's token"
                );
                return Err(format!(
                    "decodeIntegrityToken rejected ({})",
                    status.as_u16()
                ));
            }
            return Err(format!(
                "decodeIntegrityToken rejected ({}): {}",
                status.as_u16(),
                google_error_message(&body)
            ));
        }
        parse_decode_response(&body)
    }

    async fn access_token(&self) -> Result<String, String> {
        match &self.source {
            TokenSource::Key {
                credentials,
                encoding_key,
                token,
            } => key_access_token(&self.client, credentials, encoding_key, token).await,
            TokenSource::Impersonate(_) => self.minted_token().await.map_err(|failure| {
                tracing::warn!(
                    reason = failure.reason,
                    "no Play Integrity token for the workload's decoder account"
                );
                TOKEN_UNAVAILABLE.to_string()
            }),
        }
    }

    /// For the keyless source, mint a token now, retrying transient failures
    /// `attempts` times `retry` apart, so a missing grant or an unreachable
    /// metadata server shows at start-up rather than on the first Android
    /// attestation. The token is cached as usual.
    pub async fn check(&self, attempts: u32, retry: Duration) -> DecoderCheck {
        if let TokenSource::Key { .. } = self.source {
            return DecoderCheck::NotApplicable;
        }
        let mut attempt = 1;
        loop {
            match self.minted_token().await {
                Ok(_) => return DecoderCheck::Ready,
                Err(failure) if failure.transient && attempt < attempts => {
                    attempt += 1;
                    tokio::time::sleep(retry).await;
                }
                Err(failure) => return DecoderCheck::Unavailable(failure.reason),
            }
        }
    }

    fn forget_minted(&self, rejected: &str) {
        if let TokenSource::Impersonate(impersonation) = &self.source {
            let mut cached = impersonation.cached.lock().expect("token lock");
            if cached
                .as_ref()
                .is_some_and(|c| c.token.expose_secret() == rejected)
            {
                cached.take();
            }
        }
    }

    /// A cached `playintegrity` token for the impersonated service account,
    /// minted when due.
    async fn minted_token(&self) -> Result<String, MintFailure> {
        let TokenSource::Impersonate(impersonation) = &self.source else {
            unreachable!("only called on the impersonation path");
        };
        let Impersonation {
            service_account,
            metadata,
            iam,
            iam_api,
            cached,
            refresh,
            last_failure,
            failure_hold,
        } = impersonation.as_ref();
        let usable = |deadline: fn(&CachedMinted) -> Instant| {
            cached
                .lock()
                .expect("token lock")
                .as_ref()
                .filter(|c| Instant::now() < deadline(c))
                .map(|c| c.token.expose_secret().to_string())
        };
        if let Some(token) = usable(|c| c.refresh_at) {
            return Ok(token);
        }
        let waited_since = Instant::now();
        let _minting = refresh.lock().await;
        if let Some(token) = usable(|c| c.refresh_at) {
            return Ok(token);
        }
        // A mint that failed while this caller waited, or a moment ago,
        // answers for it rather than being repeated.
        let recent = last_failure
            .lock()
            .expect("failure lock")
            .filter(|(at, _)| *at >= waited_since || at.elapsed() < *failure_hold)
            .map(|(_, failure)| failure);
        let failure = match recent {
            Some(failure) => failure,
            None => {
                let minted_at = Instant::now();
                let url = format!(
                    "{iam_api}/v1/projects/-/serviceAccounts/{service_account}:generateAccessToken"
                );
                let minted = match mint(iam, metadata, &url).await {
                    Err(Mint::Unauthorized(workload)) => {
                        // The workload token was refused before it was due.
                        metadata.invalidate(&workload);
                        mint(iam, metadata, &url).await
                    }
                    other => other,
                };
                match minted {
                    Ok(token) => {
                        *cached.lock().expect("token lock") = Some(CachedMinted {
                            token: SecretString::from(token.clone()),
                            refresh_at: minted_at
                                + MINTED_LIFETIME.saturating_sub(MINTED_REFRESH_BUFFER),
                            expires_at: minted_at + MINTED_LIFETIME,
                        });
                        last_failure.lock().expect("failure lock").take();
                        return Ok(token);
                    }
                    Err(error) => {
                        let failure = error.into_failure();
                        *last_failure.lock().expect("failure lock") =
                            Some((Instant::now(), failure));
                        failure
                    }
                }
            }
        };
        // Inside the refresh margin the cached token is still valid: a
        // transient failure to replace it does not fail the attestation.
        if failure.transient {
            if let Some(token) = usable(|c| c.expires_at) {
                tracing::warn!(
                    reason = failure.reason,
                    "Play Integrity token refresh failed; using the cached token until it expires"
                );
                return Ok(token);
            }
        }
        Err(failure)
    }
}

/// One mint's failure: the workload's token refused (worth one retry with a
/// new one) or anything else.
enum Mint {
    Unauthorized(SecretString),
    Failed(MintFailure),
}

impl Mint {
    fn into_failure(self) -> MintFailure {
        match self {
            Self::Unauthorized(_) => mint_failure("token minting denied", false),
            Self::Failed(failure) => failure,
        }
    }
}

/// Ask the IAM Credentials API for a `playintegrity` token of the service
/// account in `url`, with the workload's own token.
async fn mint(iam: &reqwest::Client, metadata: &WorkloadTokens, url: &str) -> Result<String, Mint> {
    let workload = metadata
        .token()
        .await
        .map_err(|error| Mint::Failed(mint_failure(error.why, error.transient)))?;
    let mut response = iam
        .post(url)
        .bearer_auth(workload.expose_secret())
        .json(&serde_json::json!({
            "scope": [PLAY_INTEGRITY_SCOPE],
            "lifetime": format!("{}s", MINTED_LIFETIME.as_secs()),
        }))
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(error = ?error, "IAM Credentials request failed");
            Mint::Failed(mint_failure(
                if error.is_timeout() {
                    "token minting timed out"
                } else {
                    "token minting unreachable"
                },
                true,
            ))
        })?;
    let status = response.status();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        tracing::warn!(error = ?error, "reading an IAM Credentials response failed");
        Mint::Failed(mint_failure("token minting unreachable", true))
    })? {
        if body.len() + chunk.len() > IAM_BODY_MAX {
            return Err(Mint::Failed(mint_failure(
                "token minting answer too large",
                false,
            )));
        }
        body.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        tracing::warn!(
            status = status.as_u16(),
            body = ?truncated(&String::from_utf8_lossy(&body), LOGGED_BODY_MAX),
            "IAM Credentials refused to mint a Play Integrity token"
        );
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Mint::Unauthorized(workload));
        }
        return Err(Mint::Failed(match status.as_u16() {
            403 => mint_failure("token minting denied", false),
            404 => mint_failure("service account not found", false),
            408 | 429 => mint_failure("token minting throttled", true),
            code if code >= 500 => mint_failure("token minting server error", true),
            _ => mint_failure("token minting refused", false),
        }));
    }
    // Category and position only: serde quotes the offending value, which
    // here could be the token itself.
    let minted: MintedToken = serde_json::from_slice(&body).map_err(|error| {
        tracing::warn!(
            category = ?error.classify(),
            line = error.line(),
            column = error.column(),
            "IAM Credentials answer is unreadable"
        );
        Mint::Failed(mint_failure("token minting answer unreadable", false))
    })?;
    if minted.access_token.is_empty() {
        return Err(Mint::Failed(mint_failure(
            "token minting answer unreadable",
            false,
        )));
    }
    Ok(minted.access_token)
}

/// The key path's token: a JWT-bearer assertion exchanged at Google's token
/// endpoint, cached until a minute before it expires.
async fn key_access_token(
    client: &reqwest::Client,
    credentials: &GoogleCredentials,
    encoding_key: &EncodingKey,
    token: &Mutex<Option<CachedToken>>,
) -> Result<String, String> {
    let cached = {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        token
            .lock()
            .expect("token lock")
            .as_ref()
            .filter(|cached| now < cached.expires_at)
            .map(|cached| cached.token.clone())
    };
    if let Some(cached) = cached {
        return Ok(cached);
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let assertion = assertion(credentials, encoding_key, now)?;
    let response = client
        .post(TOKEN_ENDPOINT)
        .form(&[("grant_type", GRANT_TYPE), ("assertion", &assertion)])
        .send()
        .await
        .map_err(|e| format!("token exchange failed: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "token exchange rejected ({}): {body}",
            status.as_u16()
        ));
    }
    let fetched: TokenResponse = response
        .json()
        .await
        .map_err(|e| format!("token response: {e}"))?;
    let expires_at = now + fetched.expires_in - TOKEN_REFRESH_BUFFER_SECS;
    *token.lock().expect("token lock") = Some(CachedToken {
        token: fetched.access_token.clone(),
        expires_at,
    });
    Ok(fetched.access_token)
}

fn assertion(
    credentials: &GoogleCredentials,
    encoding_key: &EncodingKey,
    now: i64,
) -> Result<String, String> {
    let claims = AssertionClaims {
        iss: &credentials.client_email,
        scope: PLAY_INTEGRITY_SCOPE,
        aud: TOKEN_ENDPOINT,
        iat: now,
        exp: now + 3600,
    };
    jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, encoding_key)
        .map_err(|e| format!("assertion: {e}"))
}

/// At most `max` bytes of `text`, cut on a character boundary.
fn truncated(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let end = (0..=max)
        .rev()
        .find(|&index| text.is_char_boundary(index))
        .unwrap_or(0);
    &text[..end]
}

fn parse_decode_response(body: &[u8]) -> Result<TokenPayload, String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DecodeResponse {
        token_payload_external: Option<TokenPayload>,
    }
    let response: DecodeResponse =
        serde_json::from_slice(body).map_err(|e| format!("decodeIntegrityToken response: {e}"))?;
    response
        .token_payload_external
        .ok_or_else(|| "decodeIntegrityToken response has no tokenPayloadExternal".to_string())
}

fn google_error_message(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            let error = value.get("error")?;
            error
                .get("message")
                .or_else(|| error.get("status"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unparseable error body".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_RSA: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDIx8ZRNzzE1j7T\nmKphU2VTJj6tsJkkJepRMNrSOFS7TrwmGG3LmgoqMpaKk6mgaASjtgayQy7JkXWS\n+rLjoriA3BiMN7HQR+LbMdz1xTQ4IqROZg9V63iz6LiRaOK1Iy6O72syZu9WFSeC\nKqpbOhVPLOukc80mvYMNv52nWjlE8//9Xr3MDnwuoIS7zGXCpqeRkWTFzlTJT6UJ\nboGOWQmdzVnb420kW5Eh+tAl2VG10NiS53BRtvtKb60FPs6XaE4oYOeO7DquNeDU\n9suyFZTtO2TDZgBlu2wdewTX4IQlK6laWHh0OxI0kyoRr4XkcCciu2Mnm++chFfF\nO+/Do/urAgMBAAECggEAXxH5XcuCAtJPvXG0e5E5kT2ywBu2597sLLWtZ4000dxe\nSsuWcanm1kRN9CAnWcTnLX2rfg1BwkAWJBqBSjhqlNmi5gIZOD5RtOjPb7CJIWuF\n0XmSGWT+KnIvsuqvLoYSLaxAXgVPnrs1kfUR5VCDdpIWojATHBzwSTpKNEwMghEQ\nR/L0E6s5+PGEhW51ROJjkI581uL83khJQIGXQwAimcH0nVrQ9aq7yrUDM83ptSx2\nO34yMA4OKyGwJz931HMmVuKj0BL/3il60kSQpLX5AHncUHNrAXfegSuMI9vYBW6q\nh4W9Gv6ctL60sTtmOiN5MNuKLqKLLyNTKpE1U+HEQQKBgQDvZojpf7A6aIxq4okF\nnYYQYgWvRUOxbmYCIvdTQ6dAHpsvcXHwRL9g88evuoxwrzWE76FKEaiFPjhDYXPa\nAgg3PIcNRFcnMHjJZw84SM3Gwb7JWrWkS2+RKndZHHb/4C9ZES9LFCHDDjQkd8iD\nf46Y1wBoYIGDbzj9rYyRvRMwRQKBgQDWs7cKsNIIt+0vG7Js2tF1CpIh0ugO2k8k\ngri3l6a4MLBMV/gRfk0L51AdxcWsROwk6afX3GZiCoBxjTmjktfIsuNVe/UZ8wDL\ns1Z94sqQJWQ3AmWOroAf6CyLdvlbV1fqu3biAF+ZCcQ/nM4y/NtTIJiBIOKj/voo\nSFqx3XUTLwKBgQDNd/taLLVb7A9YTUW9BA3kUbz/STtoNZBnlQsg85fAeIRIm91m\nkhqPY6unLz0KGdadWe3cXHt+oIA5lJKSMdxLTC+9O0Jx6DBC66ksbY/vXqoYtzne\n4L/In+H/IWchBZCdqRomHgk8GBy4j/YQppIEq8M10l5WKEeJskJLczPc4QKBgECd\nByoNergq+hNiR3khBUYu7zmEqlfF9WlsecCuv/rQlE31b298Th2V+HNtUIb+mv6k\n3uFEr/8zX+JMeRs0FwKMa4QPcPzlN8kV6KKr/QAScK1paDzfYSm5CqbSIEsP5yJ6\nVlW/fQWmfcwTGa8Yj7zdo2fBCNQH6Sr0U28R0aj7AoGAKfzvVm/AdJ+4/ACrBULM\n6pCaMKefJWxI6u1DpmofObpqozE42HPUyt4gEmUIG2wEIglPpC3UiW8E4Cb5p2hT\nrEgEpX9GDN++vyPKl8TVSpf//gK2DKAhpRRZG074k4SrzbY7Yfa1Z0zt8DuOZ6iQ\neSsIvJ7DzLlMVnjD4l7Pncc=\n-----END PRIVATE KEY-----\n";

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn service_account_json() -> String {
        json!({
            "type": "service_account",
            "project_id": "polkadot-app",
            "client_email": "integrity@polkadot-app.iam.gserviceaccount.com",
            "private_key": TEST_RSA,
        })
        .to_string()
    }

    #[test]
    fn credentials_parse_base64_and_raw_json_and_reject_garbage() {
        let raw = service_account_json();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&raw);

        for input in [raw.as_str(), encoded.as_str()] {
            let creds = GoogleCredentials::parse(input).expect("parses");
            assert_eq!(
                creds.client_email,
                "integrity@polkadot-app.iam.gserviceaccount.com"
            );
        }

        assert!(GoogleCredentials::parse("not json").is_err());
        assert!(GoogleCredentials::parse(r#"{"client_email":"a@b.c"}"#).is_err());
        assert!(
            GoogleCredentials::parse(r#"{"client_email":"a@b.c","private_key":"not a pem"}"#)
                .is_err()
        );
    }

    #[test]
    fn assertion_is_rs256_with_the_playintegrity_scope() {
        let creds = GoogleCredentials::parse(&service_account_json()).unwrap();
        let key = EncodingKey::from_rsa_pem(creds.private_key.as_bytes()).unwrap();
        let assertion = assertion(&creds, &key, 1_700_000_000).expect("assertion");

        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        let claims: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            claims["iss"],
            "integrity@polkadot-app.iam.gserviceaccount.com"
        );
        assert_eq!(claims["scope"], PLAY_INTEGRITY_SCOPE);
        assert_eq!(claims["aud"], TOKEN_ENDPOINT);
        assert_eq!(claims["exp"], 1_700_003_600i64);
    }

    #[test]
    fn decode_response_parses_the_verdict_payload_shape() {
        let body = json!({
            "tokenPayloadExternal": {
                "requestDetails": {
                    "requestPackageName": "io.pcf.polkadotapp",
                    "nonce": "bm9uY2U",
                    "timestampMillis": "1750000000000"
                },
                "appIntegrity": {
                    "appRecognitionVerdict": "PLAY_RECOGNIZED",
                    "packageName": "io.pcf.polkadotapp",
                    "certificateSha256Digest": ["digest"],
                    "versionCode": "42"
                },
                "deviceIntegrity": {
                    "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]
                },
                "accountDetails": { "appLicensingVerdict": "LICENSED" }
            }
        })
        .to_string();

        let payload = parse_decode_response(body.as_bytes()).expect("parses");
        assert_eq!(
            payload.request_details.unwrap().nonce.as_deref(),
            Some("bm9uY2U")
        );
        assert_eq!(
            payload
                .app_integrity
                .unwrap()
                .app_recognition_verdict
                .as_deref(),
            Some("PLAY_RECOGNIZED")
        );

        assert!(parse_decode_response(b"{}").is_err());
        assert!(parse_decode_response(b"not json").is_err());
    }

    #[test]
    fn error_message_extraction_is_concise() {
        let body = br#"{"error":{"code":400,"message":"Integrity token cannot be decoded.","status":"INVALID_ARGUMENT"}}"#;
        assert_eq!(
            google_error_message(body),
            "Integrity token cannot be decoded."
        );
        assert_eq!(google_error_message(b"nope"), "unparseable error body");
    }

    #[test]
    fn the_key_path_keeps_its_endpoint_and_label() {
        let creds = GoogleCredentials::parse(&service_account_json()).unwrap();
        let decoder = GoogleDecoder::new(creds).unwrap();
        assert_eq!(decoder.decode_api, "https://playintegrity.googleapis.com");
        assert_eq!(decoder.label(), "service-account-key");
    }

    #[test]
    fn service_account_emails_are_validated() {
        assert!(is_service_account_email(SA));
        for bad in [
            "",
            "decoder",
            "decoder@gmail.com",
            "Decoder@pcf-polkadot-app.iam.gserviceaccount.com",
            "decoder@pcf-polkadot-app.iam.gserviceaccount.com.evil",
            "123456-compute@developer.gserviceaccount.com",
            "decoder@pcf/../x.iam.gserviceaccount.com",
            "a/b@pcf-polkadot-app.iam.gserviceaccount.com",
            "decoder@pcf-polkadot-app.iam.gserviceaccount.com\n",
            "dec@pcf-polkadot-app.iam.gserviceaccount.com",
        ] {
            assert!(!is_service_account_email(bad), "{bad:?}");
        }
        assert!(GoogleDecoder::impersonating("decoder@gmail.com").is_err());
    }

    const SA: &str = "play-integrity-decoder@pcf-polkadot-app.iam.gserviceaccount.com";
    const PACKAGE: &str = "io.pcf.polkadotapp";

    mod impersonation {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        use axum::extract::{Path, State};
        use axum::http::{HeaderMap, StatusCode};
        use axum::response::{IntoResponse, Response};

        use super::*;

        /// A stand-in for the metadata server (`/token`), the IAM Credentials
        /// API and Play Integrity (`/v1/...`). An unexpected request gets a
        /// 400 naming why.
        struct Mock {
            metadata_hits: AtomicUsize,
            mint_hits: AtomicUsize,
            decode_hits: AtomicUsize,
            metadata_status: u16,
            /// Answer this many mints with 401, then `mint_status`.
            mint_unauthorized: usize,
            mint_status: u16,
            mint_body: Option<String>,
            mint_delay: Duration,
            /// Answer this many decodes with 401 first.
            decode_unauthorized: usize,
        }

        impl Mock {
            fn new() -> Self {
                Self {
                    metadata_hits: 0.into(),
                    mint_hits: 0.into(),
                    decode_hits: 0.into(),
                    metadata_status: 200,
                    mint_unauthorized: 0,
                    mint_status: 200,
                    mint_body: None,
                    mint_delay: Duration::ZERO,
                    decode_unauthorized: 0,
                }
            }
        }

        fn bearer(headers: &HeaderMap) -> String {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        }

        fn bad(why: &str) -> Response {
            (StatusCode::BAD_REQUEST, why.to_string()).into_response()
        }

        async fn api(mock: Arc<Mock>, rest: String, headers: HeaderMap, body: String) -> Response {
            let auth = bearer(&headers);
            if let Some(account) = rest
                .strip_prefix("projects/-/serviceAccounts/")
                .and_then(|r| r.strip_suffix(":generateAccessToken"))
            {
                if account != SA {
                    return bad("minting for another service account");
                }
                if !auth.starts_with("Bearer ya29.workload") {
                    return bad("mint not authenticated with the workload token");
                }
                let request: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                if request["scope"] != json!([PLAY_INTEGRITY_SCOPE])
                    || request["lifetime"] != "3600s"
                {
                    return bad("wrong scope or lifetime");
                }
                let hit = mock.mint_hits.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(mock.mint_delay).await;
                if hit < mock.mint_unauthorized {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                if mock.mint_status != 200 {
                    return (
                        StatusCode::from_u16(mock.mint_status).unwrap(),
                        r#"{"error":{"message":"Permission 'iam.serviceAccounts.getAccessToken' denied on resource (or it may not exist)."}}"#,
                    )
                        .into_response();
                }
                if let Some(body) = &mock.mint_body {
                    return body.clone().into_response();
                }
                return json!({"accessToken": format!("ya29.pi{hit}"), "expireTime": "2026-11-28T12:00:00Z"})
                    .to_string()
                    .into_response();
            }
            if let Some(package) = rest.strip_suffix(":decodeIntegrityToken") {
                if package != PACKAGE {
                    return bad("decoding for another package");
                }
                if !auth.starts_with("Bearer ya29.pi") {
                    return bad("decode not authenticated with a minted token");
                }
                let hit = mock.decode_hits.fetch_add(1, Ordering::SeqCst);
                if hit < mock.decode_unauthorized {
                    return (
                        StatusCode::UNAUTHORIZED,
                        r#"{"error":{"message":"Play Integrity API has not been used in project 123456789012 before"}}"#,
                    )
                        .into_response();
                }
                return json!({"tokenPayloadExternal": {"requestDetails": {"nonce": auth}}})
                    .to_string()
                    .into_response();
            }
            bad("unknown path")
        }

        async fn serve(mock: Mock) -> (String, Arc<Mock>) {
            let mock = Arc::new(mock);
            let app = axum::Router::new()
                .route(
                    "/token",
                    axum::routing::get(|State(mock): State<Arc<Mock>>| async move {
                        let hit = mock.metadata_hits.fetch_add(1, Ordering::SeqCst);
                        let mut response: Response = (
                            StatusCode::from_u16(mock.metadata_status).unwrap(),
                            json!({"access_token": format!("ya29.workload{hit}"), "expires_in": 3599})
                                .to_string(),
                        )
                            .into_response();
                        response
                            .headers_mut()
                            .insert("metadata-flavor", "Google".parse().unwrap());
                        response
                    }),
                )
                .route(
                    "/v1/{*rest}",
                    axum::routing::post(
                        |State(mock): State<Arc<Mock>>,
                         Path(rest): Path<String>,
                         headers: HeaderMap,
                         body: String| api(mock, rest, headers, body),
                    ),
                )
                .with_state(mock.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (format!("http://{addr}"), mock)
        }

        fn decoder(base: &str) -> GoogleDecoder {
            GoogleDecoder::impersonating_at(
                SA,
                Endpoints {
                    decode_api: base.to_string(),
                    iam_api: base.to_string(),
                    metadata_token: format!("{base}/token"),
                    https_only: false,
                    failure_hold: Duration::ZERO,
                },
            )
            .unwrap()
        }

        fn hits(counter: &AtomicUsize) -> usize {
            counter.load(Ordering::SeqCst)
        }

        fn bearer_seen(payload: &TokenPayload) -> String {
            payload
                .request_details
                .as_ref()
                .and_then(|d| d.nonce.clone())
                .unwrap_or_default()
        }

        #[tokio::test]
        async fn decodes_with_a_minted_playintegrity_token_and_reuses_it() {
            let (base, mock) = serve(Mock::new()).await;
            let decoder = decoder(&base);
            assert_eq!(decoder.label(), "workload-identity");
            let first = decoder.decode(PACKAGE, "token").await.unwrap();
            let second = decoder.decode(PACKAGE, "token").await.unwrap();
            assert_eq!(bearer_seen(&first), "Bearer ya29.pi0");
            assert_eq!(bearer_seen(&second), "Bearer ya29.pi0");
            assert_eq!(hits(&mock.metadata_hits), 1);
            assert_eq!(hits(&mock.mint_hits), 1);
        }

        #[tokio::test]
        async fn concurrent_decodes_share_one_mint() {
            let mut mock = Mock::new();
            mock.mint_delay = Duration::from_millis(100);
            let (base, mock) = serve(mock).await;
            let decoder = Arc::new(decoder(&base));
            let calls: Vec<_> = (0..6)
                .map(|_| {
                    let decoder = decoder.clone();
                    tokio::spawn(async move { decoder.decode(PACKAGE, "token").await })
                })
                .collect();
            for call in calls {
                call.await.unwrap().unwrap();
            }
            assert_eq!(hits(&mock.mint_hits), 1);
        }

        #[tokio::test]
        async fn queued_callers_take_a_failed_mint_instead_of_repeating_it() {
            let mut mock = Mock::new();
            mock.mint_status = 503;
            mock.mint_delay = Duration::from_millis(200);
            let (base, mock) = serve(mock).await;
            let decoder = Arc::new(decoder(&base));
            let calls: Vec<_> = (0..6)
                .map(|_| {
                    let decoder = decoder.clone();
                    tokio::spawn(async move { decoder.decode(PACKAGE, "token").await })
                })
                .collect();
            for call in calls {
                assert_eq!(call.await.unwrap().unwrap_err(), TOKEN_UNAVAILABLE);
            }
            assert_eq!(hits(&mock.mint_hits), 1);
        }

        #[tokio::test]
        async fn a_refused_workload_token_is_replaced_once() {
            let mut mock = Mock::new();
            mock.mint_unauthorized = 1;
            let (base, mock) = serve(mock).await;
            decoder(&base).decode(PACKAGE, "token").await.unwrap();
            assert_eq!(hits(&mock.metadata_hits), 2);
            assert_eq!(hits(&mock.mint_hits), 2);

            let mut mock = Mock::new();
            mock.mint_unauthorized = 10;
            let (base, mock) = serve(mock).await;
            assert_eq!(
                decoder(&base).minted_token().await.unwrap_err(),
                mint_failure("token minting denied", false)
            );
            assert_eq!(hits(&mock.mint_hits), 2, "no third attempt");
        }

        #[tokio::test]
        async fn a_minted_token_play_integrity_refuses_is_dropped_and_its_text_kept_out() {
            let mut mock = Mock::new();
            mock.decode_unauthorized = 1;
            let (base, mock) = serve(mock).await;
            let decoder = decoder(&base);
            assert_eq!(
                decoder.decode(PACKAGE, "token").await.unwrap_err(),
                "decodeIntegrityToken rejected (401)",
                "Google's text, which names the project, stays in the log"
            );
            let payload = decoder.decode(PACKAGE, "token").await.unwrap();
            assert_eq!(bearer_seen(&payload), "Bearer ya29.pi1");
            assert_eq!(hits(&mock.mint_hits), 2);
        }

        #[tokio::test]
        async fn minting_refusals_are_classified_and_the_client_sees_one_string() {
            for (status, why, transient) in [
                (403, "token minting denied", false),
                (404, "service account not found", false),
                (429, "token minting throttled", true),
                (408, "token minting throttled", true),
                (503, "token minting server error", true),
                (400, "token minting refused", false),
            ] {
                let mut mock = Mock::new();
                mock.mint_status = status;
                let (base, _) = serve(mock).await;
                let decoder = decoder(&base);
                assert_eq!(
                    decoder.minted_token().await.unwrap_err(),
                    mint_failure(why, transient),
                    "{status}"
                );
                assert_eq!(
                    decoder.decode(PACKAGE, "token").await.unwrap_err(),
                    TOKEN_UNAVAILABLE
                );
            }
        }

        #[tokio::test]
        async fn unusable_mint_answers_are_refused() {
            for body in [
                json!({"accessToken": ""}).to_string(),
                json!({"expireTime": "2026-11-28T12:00:00Z"}).to_string(),
                json!("ya29.bare").to_string(),
                format!("{{\"accessToken\":\"{}\"}}", "x".repeat(IAM_BODY_MAX)),
            ] {
                let mut mock = Mock::new();
                mock.mint_body = Some(body);
                let (base, _) = serve(mock).await;
                let failure = decoder(&base).minted_token().await.unwrap_err();
                assert!(!failure.transient, "{failure:?}");
                assert!(
                    matches!(
                        failure.reason,
                        "token minting answer unreadable" | "token minting answer too large"
                    ),
                    "{failure:?}"
                );
            }
        }

        #[tokio::test]
        async fn a_still_valid_token_rides_out_a_transient_refresh_failure() {
            let mut mock = Mock::new();
            mock.mint_status = 503;
            let (base, mock) = serve(mock).await;
            let decoder = decoder(&base);
            let set_cached = |valid_for: Duration| {
                let TokenSource::Impersonate(impersonation) = &decoder.source else {
                    unreachable!()
                };
                let cached = &impersonation.cached;
                let now = Instant::now();
                *cached.lock().unwrap() = Some(CachedMinted {
                    token: SecretString::from("ya29.pi-old".to_string()),
                    refresh_at: now,
                    expires_at: now + valid_for,
                });
            };
            set_cached(Duration::from_secs(120));
            let payload = decoder.decode(PACKAGE, "token").await.unwrap();
            assert_eq!(bearer_seen(&payload), "Bearer ya29.pi-old");
            assert_eq!(hits(&mock.mint_hits), 1, "a refresh was attempted");

            // An expired token is never served.
            set_cached(Duration::ZERO);
            assert_eq!(
                decoder.decode(PACKAGE, "token").await.unwrap_err(),
                TOKEN_UNAVAILABLE
            );
        }

        #[tokio::test]
        async fn a_refusal_is_not_ridden_out_on_a_still_valid_token() {
            let mut mock = Mock::new();
            mock.mint_status = 403;
            let (base, _) = serve(mock).await;
            let decoder = decoder(&base);
            let TokenSource::Impersonate(impersonation) = &decoder.source else {
                unreachable!()
            };
            let cached = &impersonation.cached;
            let now = Instant::now();
            *cached.lock().unwrap() = Some(CachedMinted {
                token: SecretString::from("ya29.pi-old".to_string()),
                refresh_at: now,
                expires_at: now + Duration::from_secs(120),
            });
            assert_eq!(
                decoder.decode(PACKAGE, "token").await.unwrap_err(),
                TOKEN_UNAVAILABLE
            );
        }

        #[tokio::test]
        async fn the_start_up_check_reports_and_retries_only_transient_failures() {
            let (base, _) = serve(Mock::new()).await;
            assert_eq!(
                decoder(&base).check(3, Duration::ZERO).await,
                DecoderCheck::Ready
            );

            let mut mock = Mock::new();
            mock.mint_status = 503;
            let (base, mock) = serve(mock).await;
            assert_eq!(
                decoder(&base).check(3, Duration::ZERO).await,
                DecoderCheck::Unavailable("token minting server error")
            );
            assert_eq!(hits(&mock.mint_hits), 3);

            let mut mock = Mock::new();
            mock.mint_status = 403;
            let (base, mock) = serve(mock).await;
            assert_eq!(
                decoder(&base).check(3, Duration::ZERO).await,
                DecoderCheck::Unavailable("token minting denied")
            );
            assert_eq!(hits(&mock.mint_hits), 1);

            let creds = GoogleCredentials::parse(&service_account_json()).unwrap();
            assert_eq!(
                GoogleDecoder::new(creds)
                    .unwrap()
                    .check(3, Duration::ZERO)
                    .await,
                DecoderCheck::NotApplicable
            );
        }

        #[tokio::test]
        async fn without_a_workload_token_nothing_is_minted() {
            let mut mock = Mock::new();
            mock.metadata_status = 403;
            let (base, mock) = serve(mock).await;
            assert_eq!(
                decoder(&base).minted_token().await.unwrap_err(),
                mint_failure("metadata server refused a token", false)
            );
            assert_eq!(hits(&mock.mint_hits), 0);

            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let base = format!("http://{}", socket.local_addr().unwrap());
            assert_eq!(
                decoder(&base).minted_token().await.unwrap_err(),
                mint_failure("metadata server unreachable", true)
            );
            drop(socket);
        }

        #[test]
        fn production_endpoints_refuse_plain_http() {
            let endpoints = Endpoints::default();
            assert!(endpoints.https_only);
            assert!(endpoints.iam_api.starts_with("https://"));
            assert!(endpoints.decode_api.starts_with("https://"));
        }
    }
}
