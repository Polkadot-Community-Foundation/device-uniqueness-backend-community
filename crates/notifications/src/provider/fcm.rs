// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Mutex;
use std::time::Duration;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, warn};

use super::{ProviderError, PushOutcome, PushProvider, PushRequest, SendFuture};
use crate::config::ConfigError;

const PUSH_TYPE: &str = "chat";
const ANDROID_PRIORITY: &str = "high";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// Also accepted by FCM v1 `messages.send`, and the scope a metadata-server
/// token is expected to carry.
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
/// The workload's default service account on the metadata server: `/token`,
/// `/email` and `/scopes` hang off it. Under GKE Workload Identity the GKE
/// metadata server answers for the IAM service account the pod's Kubernetes
/// service account is bound to.
///
/// Addressed by IP rather than `metadata.google.internal`, so the lookup can
/// not be answered by a cluster DNS search domain first. No `scopes` parameter
/// is sent: the GKE metadata server does not document one, and the token's
/// actual scopes are checked at start-up instead (see
/// [`FcmProvider::workload_identity`]).
const METADATA_ACCOUNT_URL: &str =
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default";
/// Metadata tokens are issued for at most an hour; a longer claimed lifetime is
/// not trusted for caching.
const METADATA_TOKEN_MAX_LIFETIME_SECS: i64 = 3600;
/// The metadata server is link-local, so a connection that does not open at
/// once means it is not there (off Google Cloud, or egress blocked).
const METADATA_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
/// How much of a metadata error body reaches the log.
const METADATA_LOGGED_BODY_MAX: usize = 512;
const TOKEN_REFRESH_BUFFER_SECS: i64 = 60;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Validated FCM configuration.
#[derive(Clone, Debug)]
pub struct FcmConfig {
    /// Firebase project id (the FCM v1 send path segment).
    pub project_id: String,
    /// Where the provider's OAuth2 access token comes from.
    pub credentials: FcmCredentials,
}

/// How the FCM provider obtains its OAuth2 access token.
#[derive(Clone)]
pub enum FcmCredentials {
    /// A service-account key (`FCM_SERVICE_ACCOUNT_JSON`): the provider signs a
    /// JWT-bearer assertion and exchanges it at Google's token endpoint.
    ServiceAccountKey {
        /// Service-account client email (the assertion issuer).
        client_email: String,
        /// Service-account RSA private key (PEM).
        private_key: String,
    },
    /// The workload's own Google identity (`FCM_PROJECT_ID` alone): tokens come
    /// from the metadata server, as under GKE Workload Identity, and the
    /// process holds no key material.
    Metadata,
}

impl FcmCredentials {
    /// A short, log-safe name for the credential source.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ServiceAccountKey { .. } => "service-account-key",
            Self::Metadata => "metadata",
        }
    }
}

/// Hand-written so the service-account private key never reaches logs or errors.
impl std::fmt::Debug for FcmCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceAccountKey { client_email, .. } => f
                .debug_struct("ServiceAccountKey")
                .field("client_email", client_email)
                .field("private_key", &"<redacted>")
                .finish(),
            Self::Metadata => f.write_str("Metadata"),
        }
    }
}

#[derive(Deserialize)]
struct ServiceAccount {
    #[serde(default)]
    project_id: String,
    #[serde(default)]
    client_email: String,
    #[serde(default)]
    private_key: String,
}

impl FcmConfig {
    /// Read FCM config from the environment.
    ///
    /// Exactly one credential source may be set:
    /// - `FCM_SERVICE_ACCOUNT_JSON`: a service-account JSON with `project_id`,
    ///   `client_email`, and `private_key`;
    /// - `FCM_PROJECT_ID`: the Firebase project to send through, with the
    ///   access token taken from the metadata server.
    ///
    /// Returns `Ok(None)` when neither is set (Android FCM not configured), and
    /// an error when both are, or when the one set is malformed.
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        Self::from_getter(|key| std::env::var(key).ok())
    }

    /// Read FCM config through a caller-provided lookup (testable).
    pub fn from_getter<F>(get: F) -> Result<Option<Self>, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let set = |key| get(key).filter(|v: &String| !v.trim().is_empty());
        match (set("FCM_SERVICE_ACCOUNT_JSON"), set("FCM_PROJECT_ID")) {
            (None, None) => Ok(None),
            (Some(_), Some(_)) => Err(ConfigError::Invalid {
                key: "FCM_PROJECT_ID",
                reason: "set together with FCM_SERVICE_ACCOUNT_JSON; set the key JSON \
                         or FCM_PROJECT_ID (workload credentials), not both"
                    .to_string(),
            }),
            (Some(raw), None) => Self::from_service_account_json(&raw).map(Some),
            (None, Some(project_id)) => Ok(Some(Self {
                project_id: validated_project_id(project_id)?,
                credentials: FcmCredentials::Metadata,
            })),
        }
    }

    fn from_service_account_json(raw: &str) -> Result<Self, ConfigError> {
        let account: ServiceAccount =
            serde_json::from_str(raw).map_err(|error| ConfigError::Invalid {
                key: "FCM_SERVICE_ACCOUNT_JSON",
                reason: format!("not valid service-account JSON: {error}"),
            })?;
        if account.project_id.is_empty()
            || account.client_email.is_empty()
            || account.private_key.is_empty()
        {
            return Err(ConfigError::Invalid {
                key: "FCM_SERVICE_ACCOUNT_JSON",
                reason: "missing project_id, client_email, or private_key".to_string(),
            });
        }
        Ok(Self {
            project_id: account.project_id,
            credentials: FcmCredentials::ServiceAccountKey {
                client_email: account.client_email,
                private_key: account.private_key,
            },
        })
    }
}

/// Accept only a well-formed Google Cloud project id: 6-30 lowercase letters,
/// digits or hyphens, starting with a letter and not ending with a hyphen.
///
/// The id is interpolated into the FCM send URL path, so anything else (a
/// stray space, a slash, a pasted project number or display name) is refused
/// at start-up instead of surfacing as a 404 on the first push.
fn validated_project_id(raw: String) -> Result<String, ConfigError> {
    let bytes = raw.as_bytes();
    let well_formed = (6..=30).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    if well_formed {
        Ok(raw)
    } else {
        Err(ConfigError::Invalid {
            key: "FCM_PROJECT_ID",
            reason: "not a Google Cloud project id (6-30 lowercase letters, digits or \
                     hyphens, starting with a letter, not ending with a hyphen)"
                .to_string(),
        })
    }
}

/// Why the FCM provider could not be initialized.
#[derive(Debug, thiserror::Error)]
pub enum FcmInitError {
    /// The service-account private key was not a usable RSA key.
    #[error("invalid FCM private key: {0}")]
    InvalidPrivateKey(#[source] jsonwebtoken::errors::Error),
    #[error("could not build HTTP client: {0}")]
    HttpClient(#[source] reqwest::Error),
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

struct CachedToken {
    token: String,
    expires_at: i64,
}

/// Where [`FcmProvider`] gets a fresh access token when its cached one is stale.
enum TokenSource {
    /// Sign a JWT-bearer assertion with the service-account key and exchange it.
    Assertion {
        issuer: String,
        encoding_key: EncodingKey,
    },
    /// Ask the metadata server for the workload's own token.
    Metadata {
        client: reqwest::Client,
        /// The service-account base URL (see [`METADATA_ACCOUNT_URL`]).
        account_url: String,
    },
}

/// The identity the metadata server reports for this workload, from
/// [`FcmProvider::workload_identity`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadIdentity {
    /// The service account the workload's tokens are issued for.
    pub email: String,
    /// The OAuth scopes its tokens carry.
    pub scopes: Vec<String>,
}

impl WorkloadIdentity {
    /// Whether the tokens carry a scope FCM v1 `messages.send` accepts.
    pub fn can_send_fcm(&self) -> bool {
        self.scopes
            .iter()
            .any(|scope| scope == FCM_SCOPE || scope == CLOUD_PLATFORM_SCOPE)
    }
}

/// OAuth2-authenticated FCM v1 push provider.
pub struct FcmProvider {
    client: reqwest::Client,
    project_id: String,
    source: TokenSource,
    token: Mutex<Option<CachedToken>>,
}

impl FcmProvider {
    /// Build a provider from validated config (parses the key, builds the client).
    pub fn new(config: FcmConfig) -> Result<Self, FcmInitError> {
        Self::with_metadata_account_url(config, METADATA_ACCOUNT_URL)
    }

    fn with_metadata_account_url(
        config: FcmConfig,
        account_url: &str,
    ) -> Result<Self, FcmInitError> {
        let source = match config.credentials {
            FcmCredentials::ServiceAccountKey {
                client_email,
                private_key,
            } => TokenSource::Assertion {
                encoding_key: EncodingKey::from_rsa_pem(private_key.as_bytes())
                    .map_err(FcmInitError::InvalidPrivateKey)?,
                issuer: client_email,
            },
            FcmCredentials::Metadata => TokenSource::Metadata {
                // The token comes back over plain HTTP from a node-local
                // endpoint: never route that through a proxy taken from the
                // environment, and never follow a redirect elsewhere.
                client: reqwest::Client::builder()
                    .connect_timeout(METADATA_CONNECT_TIMEOUT)
                    .timeout(REQUEST_TIMEOUT)
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(FcmInitError::HttpClient)?,
                account_url: account_url.trim_end_matches('/').to_string(),
            },
        };
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(FcmInitError::HttpClient)?;
        Ok(Self {
            client,
            project_id: config.project_id,
            source,
            token: Mutex::new(None),
        })
    }

    fn cached_token(&self) -> Option<String> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let guard = self.token.lock().expect("token lock");
        guard
            .as_ref()
            .filter(|cached| now < cached.expires_at)
            .map(|cached| cached.token.clone())
    }

    /// Return a cached access token, fetching a fresh one from the configured
    /// source when stale.
    async fn access_token(&self) -> Result<String, ProviderError> {
        if let Some(token) = self.cached_token() {
            return Ok(token);
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = match &self.source {
            TokenSource::Assertion {
                issuer,
                encoding_key,
            } => {
                let assertion = assertion(issuer, encoding_key, now)?;
                self.exchange_assertion(&assertion).await?
            }
            TokenSource::Metadata {
                client,
                account_url,
            } => fetch_metadata_token(client, account_url).await?,
        };
        let expires_at = now.saturating_add(token.expires_in) - TOKEN_REFRESH_BUFFER_SECS;
        *self.token.lock().expect("token lock") = Some(CachedToken {
            token: token.access_token.clone(),
            expires_at,
        });
        Ok(token.access_token)
    }

    /// For the metadata credential source, fetch a token and report the
    /// identity and scopes the metadata server gives this workload; `Ok(None)`
    /// for a service-account key.
    ///
    /// Meant to run once at start-up: the token fetch is what fails when the
    /// Workload Identity binding is missing, and the scopes show a workload
    /// that fell back to a node or VM service account whose access scopes FCM
    /// does not accept. Either would otherwise surface only on the first push.
    /// The fetched token is cached as usual.
    pub async fn workload_identity(&self) -> Result<Option<WorkloadIdentity>, ProviderError> {
        let TokenSource::Metadata {
            client,
            account_url,
        } = &self.source
        else {
            return Ok(None);
        };
        self.access_token().await?;
        let email = metadata_text(client, &format!("{account_url}/email")).await?;
        let scopes = metadata_text(client, &format!("{account_url}/scopes"))
            .await?
            .lines()
            .map(str::trim)
            .filter(|scope| !scope.is_empty())
            .map(str::to_string)
            .collect();
        Ok(Some(WorkloadIdentity {
            email: email.trim().to_string(),
            scopes,
        }))
    }

    /// Exchange a signed assertion at the token endpoint (JWT-bearer grant).
    async fn exchange_assertion(&self, assertion: &str) -> Result<TokenResponse, ProviderError> {
        let response = self
            .client
            .post(TOKEN_ENDPOINT)
            .form(&[("grant_type", GRANT_TYPE), ("assertion", assertion)])
            .send()
            .await
            .map_err(|error| {
                ProviderError::Delivery(format!("fcm token exchange failed: {error}"))
            })?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ProviderError::Delivery(format!(
                "fcm token exchange rejected ({}): {body}",
                status.as_u16()
            )));
        }
        response
            .json()
            .await
            .map_err(|error| ProviderError::Delivery(format!("fcm token response: {error}")))
    }

    async fn deliver(&self, request: &PushRequest) -> Result<PushOutcome, ProviderError> {
        let access_token = self.access_token().await?;
        let body = build_message(&request.device_token, &request.push_id, &request.message);
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );

        let response = self
            .client
            .post(&url)
            .bearer_auth(&access_token)
            .json(&body)
            .send()
            .await
            .map_err(|error| ProviderError::Delivery(format!("fcm request failed: {error}")))?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.is_success() {
            let message_id = serde_json::from_str::<Value>(&body)
                .ok()
                .and_then(|value| value.get("name")?.as_str().map(str::to_string));
            debug!(project = %self.project_id, "FCM push accepted");
            // Legacy shape: FCM success reports sent + messageId, never `failed`.
            return Ok(fcm_success(message_id));
        }

        warn!(
            project = %self.project_id,
            status = status.as_u16(),
            reason = fcm_error_code(&body).as_deref().unwrap_or("-"),
            "FCM push rejected"
        );
        // Legacy: `messaging.send()` rejects on any provider failure, so the
        // route emits the generic `200 success:false` fallback — a returned
        // error here routes the notify handler down that same path.
        Err(ProviderError::Delivery(fcm_error_message(
            &body,
            status.as_u16(),
        )))
    }
}

/// Sign the RS256 assertion the token endpoint exchanges for an access token.
fn assertion(issuer: &str, key: &EncodingKey, now: i64) -> Result<String, ProviderError> {
    let claims = AssertionClaims {
        iss: issuer,
        scope: FCM_SCOPE,
        aud: TOKEN_ENDPOINT,
        iat: now,
        exp: now + 3600,
    };
    jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, key)
        .map_err(|error| ProviderError::Delivery(format!("fcm assertion: {error}")))
}

/// The error a metadata failure becomes.
///
/// Failure detail (the endpoint, the bound service account, the IAM error
/// behind a refusal) goes to the operator's log only; this error reaches the
/// calling app in the relay's failure body, so it stays generic.
fn credentials_unavailable(why: &str) -> ProviderError {
    ProviderError::Delivery(format!("fcm credentials unavailable ({why})"))
}

/// GET one metadata-server path (`/token`, `/email`, `/scopes`), returning the
/// response only when it succeeded.
async fn metadata_get(
    client: &reqwest::Client,
    url: &str,
) -> Result<reqwest::Response, ProviderError> {
    let response = client
        .get(url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await
        .map_err(|error| {
            warn!(%error, "metadata server unreachable for FCM credentials");
            credentials_unavailable("metadata server unreachable")
        })?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        warn!(
            status = status.as_u16(),
            body = %truncated(&body, METADATA_LOGGED_BODY_MAX),
            "metadata server refused an FCM credentials request"
        );
        return Err(credentials_unavailable(&format!(
            "metadata status {}",
            status.as_u16()
        )));
    }
    Ok(response)
}

/// Fetch the workload's access token from the metadata server.
async fn fetch_metadata_token(
    client: &reqwest::Client,
    account_url: &str,
) -> Result<TokenResponse, ProviderError> {
    let response = metadata_get(client, &format!("{account_url}/token")).await?;
    let mut token: TokenResponse = response.json().await.map_err(|error| {
        warn!(%error, "metadata server sent an unreadable FCM token response");
        credentials_unavailable("malformed metadata token response")
    })?;
    if token.access_token.is_empty() || token.expires_in <= 0 {
        warn!(
            expires_in = token.expires_in,
            "metadata server sent an FCM token response without a usable token"
        );
        return Err(credentials_unavailable("malformed metadata token response"));
    }
    token.expires_in = token.expires_in.min(METADATA_TOKEN_MAX_LIFETIME_SECS);
    Ok(token)
}

/// Read a plain-text metadata value.
async fn metadata_text(client: &reqwest::Client, url: &str) -> Result<String, ProviderError> {
    metadata_get(client, url)
        .await?
        .text()
        .await
        .map_err(|error| {
            warn!(%error, "metadata server sent an unreadable FCM credentials response");
            credentials_unavailable("malformed metadata response")
        })
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

impl PushProvider for FcmProvider {
    fn send<'a>(&'a self, request: &'a PushRequest) -> SendFuture<'a> {
        Box::pin(async move { self.deliver(request).await })
    }
}

/// Build the FCM v1 message body, matching the shipping backend's flat `data`.
fn build_message(device_token: &str, push_id: &str, message: &str) -> Value {
    json!({
        "message": {
            "token": device_token,
            "data": { "pushType": PUSH_TYPE, "pushId": push_id, "message": message },
            "android": { "priority": ANDROID_PRIORITY },
        }
    })
}

/// A single accepted FCM push: `sent` plus the provider message id, and —
/// matching the legacy adapter — no `failed` field.
fn fcm_success(message_id: Option<String>) -> PushOutcome {
    PushOutcome {
        success: true,
        sent: Some(1),
        failed: None,
        message_id,
        errors: None,
    }
}

/// A concise message for the generic failure body: the FCM v1 `error.message`
/// (or `error.status`), falling back to the HTTP status. Kept short so raw
/// provider diagnostics do not leak into the response.
fn fcm_error_message(body: &str, status: u16) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            let error = value.get("error")?;
            error
                .get("message")
                .or_else(|| error.get("status"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("FCM rejected the push (status {status})"))
}
/// Extract the FCM v1 `errorCode` (or `status`) from an error body, for logging.
fn fcm_error_code(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    let error = value.get("error")?;
    error
        .get("details")
        .and_then(|details| details.as_array())
        .and_then(|details| details.iter().find_map(|d| d.get("errorCode")?.as_str()))
        .or_else(|| error.get("status").and_then(Value::as_str))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::collections::HashMap;
    use std::sync::Arc;

    const TEST_RSA: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDIx8ZRNzzE1j7T\nmKphU2VTJj6tsJkkJepRMNrSOFS7TrwmGG3LmgoqMpaKk6mgaASjtgayQy7JkXWS\n+rLjoriA3BiMN7HQR+LbMdz1xTQ4IqROZg9V63iz6LiRaOK1Iy6O72syZu9WFSeC\nKqpbOhVPLOukc80mvYMNv52nWjlE8//9Xr3MDnwuoIS7zGXCpqeRkWTFzlTJT6UJ\nboGOWQmdzVnb420kW5Eh+tAl2VG10NiS53BRtvtKb60FPs6XaE4oYOeO7DquNeDU\n9suyFZTtO2TDZgBlu2wdewTX4IQlK6laWHh0OxI0kyoRr4XkcCciu2Mnm++chFfF\nO+/Do/urAgMBAAECggEAXxH5XcuCAtJPvXG0e5E5kT2ywBu2597sLLWtZ4000dxe\nSsuWcanm1kRN9CAnWcTnLX2rfg1BwkAWJBqBSjhqlNmi5gIZOD5RtOjPb7CJIWuF\n0XmSGWT+KnIvsuqvLoYSLaxAXgVPnrs1kfUR5VCDdpIWojATHBzwSTpKNEwMghEQ\nR/L0E6s5+PGEhW51ROJjkI581uL83khJQIGXQwAimcH0nVrQ9aq7yrUDM83ptSx2\nO34yMA4OKyGwJz931HMmVuKj0BL/3il60kSQpLX5AHncUHNrAXfegSuMI9vYBW6q\nh4W9Gv6ctL60sTtmOiN5MNuKLqKLLyNTKpE1U+HEQQKBgQDvZojpf7A6aIxq4okF\nnYYQYgWvRUOxbmYCIvdTQ6dAHpsvcXHwRL9g88evuoxwrzWE76FKEaiFPjhDYXPa\nAgg3PIcNRFcnMHjJZw84SM3Gwb7JWrWkS2+RKndZHHb/4C9ZES9LFCHDDjQkd8iD\nf46Y1wBoYIGDbzj9rYyRvRMwRQKBgQDWs7cKsNIIt+0vG7Js2tF1CpIh0ugO2k8k\ngri3l6a4MLBMV/gRfk0L51AdxcWsROwk6afX3GZiCoBxjTmjktfIsuNVe/UZ8wDL\ns1Z94sqQJWQ3AmWOroAf6CyLdvlbV1fqu3biAF+ZCcQ/nM4y/NtTIJiBIOKj/voo\nSFqx3XUTLwKBgQDNd/taLLVb7A9YTUW9BA3kUbz/STtoNZBnlQsg85fAeIRIm91m\nkhqPY6unLz0KGdadWe3cXHt+oIA5lJKSMdxLTC+9O0Jx6DBC66ksbY/vXqoYtzne\n4L/In+H/IWchBZCdqRomHgk8GBy4j/YQppIEq8M10l5WKEeJskJLczPc4QKBgECd\nByoNergq+hNiR3khBUYu7zmEqlfF9WlsecCuv/rQlE31b298Th2V+HNtUIb+mv6k\n3uFEr/8zX+JMeRs0FwKMa4QPcPzlN8kV6KKr/QAScK1paDzfYSm5CqbSIEsP5yJ6\nVlW/fQWmfcwTGa8Yj7zdo2fBCNQH6Sr0U28R0aj7AoGAKfzvVm/AdJ+4/ACrBULM\n6pCaMKefJWxI6u1DpmofObpqozE42HPUyt4gEmUIG2wEIglPpC3UiW8E4Cb5p2hT\nrEgEpX9GDN++vyPKl8TVSpf//gK2DKAhpRRZG074k4SrzbY7Yfa1Z0zt8DuOZ6iQ\neSsIvJ7DzLlMVnjD4l7Pncc=\n-----END PRIVATE KEY-----\n";

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn config(pairs: &[(&str, &str)]) -> Result<Option<FcmConfig>, ConfigError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        FcmConfig::from_getter(|key| map.get(key).cloned())
    }

    fn service_account_json() -> String {
        json!({
            "type": "service_account",
            "project_id": "brevity-proj",
            "client_email": "push@brevity-proj.iam.gserviceaccount.com",
            "private_key": TEST_RSA,
        })
        .to_string()
    }

    fn provider() -> FcmProvider {
        let cfg = config(&[("FCM_SERVICE_ACCOUNT_JSON", &service_account_json())])
            .unwrap()
            .expect("configured");
        FcmProvider::new(cfg).expect("valid key")
    }

    #[test]
    fn message_body_matches_legacy_flat_data() {
        let body = build_message("dev-token", "pid", "0xdead");
        let message = &body["message"];
        assert_eq!(message["token"], "dev-token");
        assert_eq!(message["data"]["pushType"], "chat");
        assert_eq!(message["data"]["pushId"], "pid");
        assert_eq!(message["data"]["message"], "0xdead");
        assert_eq!(message["android"]["priority"], "high");
    }

    #[test]
    fn config_is_none_absent_and_validated_when_present() {
        assert!(config(&[]).unwrap().is_none());
        assert!(matches!(
            config(&[("FCM_SERVICE_ACCOUNT_JSON", "not json")]).unwrap_err(),
            ConfigError::Invalid { .. }
        ));
        assert!(matches!(
            config(&[("FCM_SERVICE_ACCOUNT_JSON", r#"{"project_id":"p"}"#)]).unwrap_err(),
            ConfigError::Invalid { .. }
        ));
        let full = config(&[("FCM_SERVICE_ACCOUNT_JSON", &service_account_json())])
            .unwrap()
            .expect("configured");
        assert_eq!(full.project_id, "brevity-proj");
        let FcmCredentials::ServiceAccountKey { client_email, .. } = &full.credentials else {
            panic!("key JSON selects the service-account key, got {full:?}");
        };
        assert_eq!(client_email, "push@brevity-proj.iam.gserviceaccount.com");
    }

    #[test]
    fn project_id_alone_selects_metadata_credentials() {
        let cfg = config(&[("FCM_PROJECT_ID", "pcf-push-devnet")])
            .unwrap()
            .expect("configured");
        assert_eq!(cfg.project_id, "pcf-push-devnet");
        assert!(matches!(cfg.credentials, FcmCredentials::Metadata));
        assert_eq!(cfg.credentials.label(), "metadata");
        // Blank counts as unset, the same rule as the key JSON.
        assert!(config(&[("FCM_PROJECT_ID", "  ")]).unwrap().is_none());
    }

    #[test]
    fn key_json_and_project_id_together_are_refused() {
        let error = config(&[
            ("FCM_SERVICE_ACCOUNT_JSON", &service_account_json()),
            ("FCM_PROJECT_ID", "brevity-proj"),
        ])
        .unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Invalid {
                key: "FCM_PROJECT_ID",
                ..
            }
        ));
    }

    #[test]
    fn malformed_project_id_is_refused() {
        for bad in [
            "short",
            "Upper-case-proj",
            "1starts-with-digit",
            "ends-with-hyphen-",
            " pcf-push-devnet",
            "pcf-push-devnet\n",
            "pcf/../other-proj",
            "pcf-push?x=1",
            "123456789012",
            "a-project-id-that-is-longer-than-thirty",
            "prøject-id",
        ] {
            assert!(
                matches!(
                    config(&[("FCM_PROJECT_ID", bad)]),
                    Err(ConfigError::Invalid {
                        key: "FCM_PROJECT_ID",
                        ..
                    })
                ),
                "{bad:?} should be refused"
            );
        }
        for good in [
            "abcdef",
            "pcf-polkadot-app",
            "a2345678901234567890123456789z",
        ] {
            assert!(
                config(&[("FCM_PROJECT_ID", good)]).unwrap().is_some(),
                "{good:?} should be accepted"
            );
        }
    }

    #[test]
    fn debug_never_prints_the_private_key() {
        let cfg = config(&[("FCM_SERVICE_ACCOUNT_JSON", &service_account_json())])
            .unwrap()
            .expect("configured");
        let printed = format!("{cfg:?}");
        assert!(printed.contains("<redacted>"));
        assert!(!printed.contains("PRIVATE KEY"));
    }

    #[test]
    fn assertion_is_rs256_with_service_account_issuer_and_scope() {
        let TokenSource::Assertion {
            issuer,
            encoding_key,
        } = &provider().source
        else {
            panic!("key JSON builds an assertion source");
        };
        let token = assertion(issuer, encoding_key, 1_700_000_000).expect("assertion");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: Value = serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");

        let claims: Value = serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "push@brevity-proj.iam.gserviceaccount.com");
        assert_eq!(claims["scope"], FCM_SCOPE);
        assert_eq!(claims["aud"], TOKEN_ENDPOINT);
        assert_eq!(claims["exp"], 1_700_003_600i64);
    }

    #[test]
    fn success_reports_sent_and_message_id_without_failed() {
        let outcome = fcm_success(Some("projects/p/messages/123".to_string()));
        assert!(outcome.success);
        assert_eq!(outcome.sent, Some(1));
        assert_eq!(outcome.failed, None);
        assert_eq!(
            outcome.message_id.as_deref(),
            Some("projects/p/messages/123")
        );
    }

    #[test]
    fn error_message_is_concise_with_fallbacks() {
        let body = r#"{"error":{"code":404,"status":"NOT_FOUND","message":"Requested entity was not found.","details":[{"errorCode":"UNREGISTERED"}]}}"#;
        assert_eq!(
            fcm_error_message(body, 404),
            "Requested entity was not found."
        );
        assert_eq!(fcm_error_code(body).as_deref(), Some("UNREGISTERED"));
        assert_eq!(
            fcm_error_message("not json", 503),
            "FCM rejected the push (status 503)"
        );
    }

    /// A stand-in metadata server under `/sa` (`/token`, `/email`, `/scopes`).
    /// It counts token requests and records whether every request carried
    /// `Metadata-Flavor: Google` and no query string.
    struct MetadataMock {
        token_hits: std::sync::atomic::AtomicUsize,
        well_formed: std::sync::atomic::AtomicBool,
        token: (u16, String),
        scopes: String,
    }

    async fn metadata_server_with_scopes(
        status: u16,
        token: Value,
        scopes: &str,
    ) -> (String, Arc<MetadataMock>) {
        use axum::extract::{Path, RawQuery, State};
        use axum::http::{header, HeaderMap, StatusCode};
        use axum::response::IntoResponse;
        use std::sync::atomic::Ordering;

        let mock = Arc::new(MetadataMock {
            token_hits: 0.into(),
            well_formed: true.into(),
            token: (status, token.to_string()),
            scopes: scopes.to_string(),
        });
        let app = axum::Router::new()
            .route(
                "/sa/{item}",
                axum::routing::get(
                    |State(mock): State<Arc<MetadataMock>>,
                     Path(item): Path<String>,
                     RawQuery(query): RawQuery,
                     headers: HeaderMap| async move {
                        let flavored = headers
                            .get("metadata-flavor")
                            .is_some_and(|value| value == "Google");
                        if !flavored || query.is_some() {
                            mock.well_formed.store(false, Ordering::SeqCst);
                        }
                        match item.as_str() {
                            "token" => {
                                mock.token_hits.fetch_add(1, Ordering::SeqCst);
                                let (status, body) = &mock.token;
                                let status = StatusCode::from_u16(*status).unwrap();
                                if status.is_redirection() {
                                    // Point somewhere that would succeed if followed.
                                    return (status, [(header::LOCATION, "/sa/email")], "")
                                        .into_response();
                                }
                                (status, body.clone()).into_response()
                            }
                            "email" => "fcm-push-sender@pcf-push-devnet.iam.gserviceaccount.com"
                                .into_response(),
                            "scopes" => mock.scopes.clone().into_response(),
                            _ => StatusCode::NOT_FOUND.into_response(),
                        }
                    },
                ),
            )
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/sa"), mock)
    }

    async fn metadata_server(status: u16, token: Value) -> (String, Arc<MetadataMock>) {
        metadata_server_with_scopes(status, token, &format!("{CLOUD_PLATFORM_SCOPE}\n")).await
    }

    fn metadata_provider(account_url: &str) -> FcmProvider {
        let cfg = config(&[("FCM_PROJECT_ID", "pcf-push-devnet")])
            .unwrap()
            .expect("configured");
        FcmProvider::with_metadata_account_url(cfg, account_url).expect("provider")
    }

    fn hits(mock: &MetadataMock) -> usize {
        mock.token_hits.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn good_token() -> Value {
        json!({"access_token": "ya29.workload", "expires_in": 3599, "token_type": "Bearer"})
    }

    #[tokio::test]
    async fn metadata_token_is_fetched_once_and_cached() {
        let (url, mock) = metadata_server(200, good_token()).await;
        let provider = metadata_provider(&url);

        assert_eq!(provider.access_token().await.unwrap(), "ya29.workload");
        assert_eq!(provider.access_token().await.unwrap(), "ya29.workload");
        assert_eq!(hits(&mock), 1, "second call must be served from the cache");
        assert!(
            mock.well_formed.load(std::sync::atomic::Ordering::SeqCst),
            "requests must carry Metadata-Flavor: Google and no scopes query"
        );
    }

    #[tokio::test]
    async fn metadata_token_inside_the_refresh_buffer_is_not_reused() {
        let (url, mock) = metadata_server(
            200,
            json!({"access_token": "ya29.expiring", "expires_in": TOKEN_REFRESH_BUFFER_SECS}),
        )
        .await;
        let provider = metadata_provider(&url);

        provider.access_token().await.unwrap();
        provider.access_token().await.unwrap();
        assert_eq!(hits(&mock), 2, "a token about to expire is refetched");
    }

    #[tokio::test]
    async fn metadata_token_lifetime_is_capped_at_an_hour() {
        let (url, _mock) = metadata_server(
            200,
            json!({"access_token": "ya29.forever", "expires_in": i64::MAX}),
        )
        .await;
        let provider = metadata_provider(&url);
        let before = time::OffsetDateTime::now_utc().unix_timestamp();

        provider.access_token().await.unwrap();
        let expires_at = provider.token.lock().unwrap().as_ref().unwrap().expires_at;
        assert!(
            expires_at <= before + METADATA_TOKEN_MAX_LIFETIME_SECS - TOKEN_REFRESH_BUFFER_SECS + 1,
            "cached until {expires_at}, more than an hour after {before}"
        );
    }

    #[tokio::test]
    async fn metadata_refusal_is_a_concise_provider_error() {
        let (url, mock) = metadata_server(
            403,
            json!("Unable to generate access token; IAM returned 403 Forbidden: Permission 'iam.serviceAccounts.getAccessToken' denied"),
        )
        .await;
        let provider = metadata_provider(&url);

        let error = provider.access_token().await.unwrap_err().to_string();
        assert_eq!(error, "fcm credentials unavailable (metadata status 403)");
        // A failure is not cached: the next push asks again.
        provider.access_token().await.unwrap_err();
        assert_eq!(hits(&mock), 2);
    }

    #[tokio::test]
    async fn metadata_redirect_is_not_followed() {
        let (url, mock) = metadata_server(302, json!(null)).await;
        let error = metadata_provider(&url)
            .access_token()
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(error, "fcm credentials unavailable (metadata status 302)");
        assert_eq!(hits(&mock), 1);
    }

    #[tokio::test]
    async fn metadata_response_without_a_usable_token_is_refused() {
        for body in [
            json!({"access_token": "", "expires_in": 3599}),
            json!({"access_token": "ya29.x", "expires_in": 0}),
            json!({"access_token": "ya29.x", "expires_in": -5}),
            json!({"access_token": "ya29.x", "expires_in": "3599"}),
            json!({"access_token": "ya29.x"}),
            json!({"expires_in": 3599}),
            json!("not an object"),
        ] {
            let (url, _mock) = metadata_server(200, body.clone()).await;
            let provider = metadata_provider(&url);
            assert_eq!(
                provider.access_token().await.unwrap_err().to_string(),
                "fcm credentials unavailable (malformed metadata token response)",
                "{body} must not yield a token"
            );
        }
    }

    #[tokio::test]
    async fn unreachable_metadata_server_does_not_echo_the_endpoint() {
        // Bound but never listening: connections are refused, and the port
        // stays reserved so no other test's mock server can be given it.
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let url = format!("http://{}/sa", socket.local_addr().unwrap());

        let error = metadata_provider(&url)
            .access_token()
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "fcm credentials unavailable (metadata server unreachable)"
        );
        drop(socket);
    }

    #[tokio::test]
    async fn workload_identity_reports_email_and_scopes_and_warms_the_cache() {
        let (url, mock) = metadata_server(200, good_token()).await;
        let provider = metadata_provider(&url);

        let identity = provider
            .workload_identity()
            .await
            .unwrap()
            .expect("metadata source");
        assert_eq!(
            identity.email,
            "fcm-push-sender@pcf-push-devnet.iam.gserviceaccount.com"
        );
        assert_eq!(identity.scopes, vec![CLOUD_PLATFORM_SCOPE.to_string()]);
        assert!(identity.can_send_fcm());

        provider.access_token().await.unwrap();
        assert_eq!(
            hits(&mock),
            1,
            "the check's token is reused by the first push"
        );
    }

    #[tokio::test]
    async fn workload_identity_flags_scopes_fcm_does_not_accept() {
        // What a VM or node service account with default access scopes reports.
        let (url, _mock) = metadata_server_with_scopes(
            200,
            good_token(),
            "https://www.googleapis.com/auth/devstorage.read_only\n\
             https://www.googleapis.com/auth/logging.write\n",
        )
        .await;
        let identity = metadata_provider(&url)
            .workload_identity()
            .await
            .unwrap()
            .expect("metadata source");
        assert_eq!(identity.scopes.len(), 2);
        assert!(!identity.can_send_fcm());

        let fcm_only = WorkloadIdentity {
            email: String::new(),
            scopes: vec![FCM_SCOPE.to_string()],
        };
        assert!(fcm_only.can_send_fcm());
    }

    #[tokio::test]
    async fn workload_identity_is_none_for_a_service_account_key() {
        assert_eq!(provider().workload_identity().await.unwrap(), None);
    }

    #[test]
    fn logged_bodies_are_truncated_on_a_char_boundary() {
        assert_eq!(truncated("short", 512), "short");
        assert_eq!(truncated("abcdef", 3), "abc");
        // "é" is two bytes; a cut through it backs off to the boundary before.
        assert_eq!(truncated("aé", 2), "a");
        assert_eq!(truncated("", 0), "");
    }
}
