// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Mutex;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, warn};

use super::{ProviderError, PushOutcome, PushProvider, PushRequest, SendFuture};
use crate::config::ConfigError;

const PUSH_TYPE: &str = "chat";
const ANDROID_PRIORITY: &str = "high";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const FCM_SEND_BASE: &str = "https://fcm.googleapis.com";
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
/// [`FcmProvider::check_workload_identity`]).
const METADATA_ACCOUNT_URL: &str =
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default";
/// Metadata tokens are issued for at most an hour; a longer claimed lifetime is
/// not trusted for caching.
const METADATA_TOKEN_MAX_LIFETIME_SECS: i64 = 3600;
/// The metadata server is link-local, so a connection that does not open at
/// once means it is not there (off Google Cloud, or egress blocked).
const METADATA_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
/// The largest metadata response read. A token, an email or a scope list is
/// well under a kilobyte; anything bigger is not the metadata server.
const METADATA_BODY_MAX: usize = 64 * 1024;
/// How much of a metadata error body reaches the log.
const METADATA_LOGGED_BODY_MAX: usize = 512;
/// How long a failed metadata fetch answers for the next callers instead of
/// being repeated, so a failing server is not asked once per queued push.
const METADATA_FAILURE_HOLD: Duration = Duration::from_secs(1);
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
    /// The workload's own Google identity (`FCM_PROJECT_ID`): tokens come from
    /// the metadata server, as under GKE Workload Identity, and the process
    /// holds no key material.
    Metadata {
        /// `FCM_SERVICE_ACCOUNT_EMAIL`: the only identity the provider will
        /// send as. When set, a token the metadata server issues for any other
        /// account (a node or VM default account the pod fell back to) is
        /// refused rather than used.
        expected_email: Option<String>,
    },
}

impl FcmCredentials {
    /// A short, log-safe name for the credential source.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ServiceAccountKey { .. } => "service-account-key",
            Self::Metadata { .. } => "metadata",
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
            Self::Metadata { expected_email } => f
                .debug_struct("Metadata")
                .field("expected_email", expected_email)
                .finish(),
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
    ///   access token taken from the metadata server, optionally pinned to one
    ///   identity with `FCM_SERVICE_ACCOUNT_EMAIL`.
    ///
    /// Returns `Ok(None)` when neither is set (Android FCM not configured), and
    /// an error when both are, when `FCM_SERVICE_ACCOUNT_EMAIL` is set without
    /// `FCM_PROJECT_ID`, or when a value is malformed.
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        Self::from_getter(|key| std::env::var(key).ok())
    }

    /// Read FCM config through a caller-provided lookup (testable).
    pub fn from_getter<F>(get: F) -> Result<Option<Self>, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let set = |key| get(key).filter(|v: &String| !v.trim().is_empty());
        let expected_email = set("FCM_SERVICE_ACCOUNT_EMAIL");
        match (set("FCM_SERVICE_ACCOUNT_JSON"), set("FCM_PROJECT_ID")) {
            (Some(_), Some(_)) => Err(ConfigError::Invalid {
                key: "FCM_PROJECT_ID",
                reason: "set together with FCM_SERVICE_ACCOUNT_JSON; set the key JSON \
                         or FCM_PROJECT_ID (workload credentials), not both"
                    .to_string(),
            }),
            (_, None) if expected_email.is_some() => Err(ConfigError::Invalid {
                key: "FCM_SERVICE_ACCOUNT_EMAIL",
                reason: "applies only to workload credentials; set FCM_PROJECT_ID \
                         instead of FCM_SERVICE_ACCOUNT_JSON"
                    .to_string(),
            }),
            (None, None) => Ok(None),
            (Some(raw), None) => Self::from_service_account_json(&raw).map(Some),
            (None, Some(project_id)) => Ok(Some(Self {
                project_id: validated_project_id(project_id)?,
                credentials: FcmCredentials::Metadata {
                    expected_email: expected_email
                        .map(validated_service_account_email)
                        .transpose()?,
                },
            })),
        }
    }

    fn from_service_account_json(raw: &str) -> Result<Self, ConfigError> {
        // Only the error's category and position: serde quotes the offending
        // value, which for a double-encoded secret is the whole key.
        let account: ServiceAccount =
            serde_json::from_str(raw).map_err(|error| ConfigError::Invalid {
                key: "FCM_SERVICE_ACCOUNT_JSON",
                reason: format!(
                    "not valid service-account JSON ({:?} error at line {}, column {})",
                    error.classify(),
                    error.line(),
                    error.column()
                ),
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
/// at start-up instead of surfacing as a 404 on the first push. Legacy
/// domain-scoped ids (`example.com:project`) are refused too.
fn validated_project_id(raw: String) -> Result<String, ConfigError> {
    if is_project_id(&raw) {
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

fn is_project_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (6..=30).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Accept only a Google service-account email:
/// `<name>@<project>.iam.gserviceaccount.com`, or a Google-managed
/// `…@…gserviceaccount.com` account, in lowercase ASCII.
fn validated_service_account_email(raw: String) -> Result<String, ConfigError> {
    let well_formed = raw.split_once('@').is_some_and(|(name, domain)| {
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && domain.ends_with(".gserviceaccount.com")
            && !domain.starts_with('.')
            && !domain.contains("..")
            && domain
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    });
    if well_formed {
        Ok(raw)
    } else {
        Err(ConfigError::Invalid {
            key: "FCM_SERVICE_ACCOUNT_EMAIL",
            reason: "not a Google service-account email \
                     (<name>@<project>.iam.gserviceaccount.com)"
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
    #[error("workload tokens are only fetched from the metadata server")]
    NotMetadataServer,
}

/// The plain-HTTP token request may only go to Google's link-local metadata
/// server, so nothing can point it at another host or path. Test builds also
/// allow a loopback mock server.
fn is_metadata_account(url: &str, allow_loopback: bool) -> bool {
    url == METADATA_ACCOUNT_URL
        || (allow_loopback
            && reqwest::Url::parse(url)
                .is_ok_and(|url| url.scheme() == "http" && url.host_str() == Some("127.0.0.1")))
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
    /// When to stop using it and fetch a new one (expiry minus the buffer).
    refresh_at: i64,
    /// When it stops being valid at all.
    expires_at: i64,
}

impl CachedToken {
    fn new(token: String, now: i64, expires_in: i64) -> Self {
        let expires_at = now.saturating_add(expires_in);
        Self {
            token,
            refresh_at: expires_at.saturating_sub(TOKEN_REFRESH_BUFFER_SECS),
            expires_at,
        }
    }
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
        expected_email: Option<String>,
    },
}

/// The identity the metadata server reports for this workload.
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

/// The outcome of [`FcmProvider::check_workload_identity`].
#[derive(Debug)]
pub enum IdentityCheck {
    /// A service-account key: there is no workload identity to check.
    NotApplicable,
    /// Tokens can be fetched and carry a scope FCM accepts.
    Ready(WorkloadIdentity),
    /// Tokens can be fetched but carry no scope FCM accepts: FCM will refuse
    /// every push.
    UnusableScopes(WorkloadIdentity),
    /// No usable token could be fetched: Android pushes report provider
    /// failure until this is fixed.
    TokenUnavailable(ProviderError),
    /// A token was fetched but the identity behind it could not be read;
    /// pushes may still work.
    IdentityUnreadable(ProviderError),
}

/// Where the provider sends its requests. Fixed in production; a test points
/// them at a local server.
struct Endpoints {
    token: String,
    send_base: String,
    metadata_account: String,
    failure_hold: Duration,
}

/// OAuth2-authenticated FCM v1 push provider.
pub struct FcmProvider {
    client: reqwest::Client,
    project_id: String,
    source: TokenSource,
    token_endpoint: String,
    send_base: String,
    token: Mutex<Option<CachedToken>>,
    /// Held while a metadata token is fetched, so callers that arrive during a
    /// refresh wait for it instead of each fetching their own.
    refresh: tokio::sync::Mutex<()>,
    /// The last failed metadata fetch and when it failed.
    last_failure: Mutex<Option<(Instant, MetadataFailure)>>,
    failure_hold: Duration,
}

impl FcmProvider {
    /// Build a provider from validated config (parses the key, builds the client).
    pub fn new(config: FcmConfig) -> Result<Self, FcmInitError> {
        Self::with_endpoints(
            config,
            Endpoints {
                token: TOKEN_ENDPOINT.to_string(),
                send_base: FCM_SEND_BASE.to_string(),
                metadata_account: METADATA_ACCOUNT_URL.to_string(),
                failure_hold: METADATA_FAILURE_HOLD,
            },
        )
    }

    fn with_endpoints(config: FcmConfig, endpoints: Endpoints) -> Result<Self, FcmInitError> {
        let source = match config.credentials {
            FcmCredentials::ServiceAccountKey {
                client_email,
                private_key,
            } => TokenSource::Assertion {
                encoding_key: EncodingKey::from_rsa_pem(private_key.as_bytes())
                    .map_err(FcmInitError::InvalidPrivateKey)?,
                issuer: client_email,
            },
            FcmCredentials::Metadata { expected_email } => TokenSource::Metadata {
                account_url: {
                    let url = endpoints.metadata_account.trim_end_matches('/');
                    if !is_metadata_account(url, cfg!(test)) {
                        return Err(FcmInitError::NotMetadataServer);
                    }
                    url.to_string()
                },
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
                expected_email,
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
            token_endpoint: endpoints.token,
            send_base: endpoints.send_base,
            token: Mutex::new(None),
            refresh: tokio::sync::Mutex::new(()),
            last_failure: Mutex::new(None),
            failure_hold: endpoints.failure_hold,
        })
    }

    /// The cached token, if `deadline` (refresh or expiry) has not passed.
    fn cached_token(&self, deadline: fn(&CachedToken) -> i64) -> Option<String> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let guard = self.token.lock().expect("token lock");
        guard
            .as_ref()
            .filter(|cached| now < deadline(cached))
            .map(|cached| cached.token.clone())
    }

    fn store_token(&self, token: &TokenResponse, now: i64) {
        *self.token.lock().expect("token lock") = Some(CachedToken::new(
            token.access_token.clone(),
            now,
            token.expires_in,
        ));
    }

    /// Return a cached access token, fetching a fresh one from the configured
    /// source when stale.
    async fn access_token(&self) -> Result<String, ProviderError> {
        if let Some(token) = self.cached_token(|cached| cached.refresh_at) {
            return Ok(token);
        }
        match &self.source {
            TokenSource::Assertion {
                issuer,
                encoding_key,
            } => {
                let now = time::OffsetDateTime::now_utc().unix_timestamp();
                let assertion = assertion(issuer, encoding_key, now)?;
                let token = self.exchange_assertion(&assertion).await?;
                self.store_token(&token, now);
                Ok(token.access_token)
            }
            TokenSource::Metadata {
                client,
                account_url,
                expected_email,
            } => {
                let waited_since = Instant::now();
                let _refreshing = self.refresh.lock().await;
                if let Some(token) = self.cached_token(|cached| cached.refresh_at) {
                    return Ok(token);
                }
                // A fetch that failed while this caller waited, or a moment
                // ago, answers for it rather than being repeated.
                let failure = match self.recent_failure(waited_since) {
                    Some(failure) => failure,
                    None => {
                        let now = time::OffsetDateTime::now_utc().unix_timestamp();
                        match fetch_metadata_token(client, account_url, expected_email.as_deref())
                            .await
                        {
                            Ok(token) => {
                                self.store_token(&token, now);
                                self.last_failure.lock().expect("failure lock").take();
                                return Ok(token.access_token);
                            }
                            Err(failure) => {
                                *self.last_failure.lock().expect("failure lock") =
                                    Some((Instant::now(), failure.clone()));
                                failure
                            }
                        }
                    }
                };
                // Inside the refresh buffer the cached token is still valid:
                // a transient failure to refresh it does not fail the push.
                if failure.transient {
                    if let Some(token) = self.cached_token(|cached| cached.expires_at) {
                        warn!(error = %failure.error, "FCM token refresh failed; using the cached token until it expires");
                        return Ok(token);
                    }
                }
                Err(failure.error)
            }
        }
    }

    /// Whether metadata tokens are pinned to one identity
    /// (`FCM_SERVICE_ACCOUNT_EMAIL`).
    pub fn pins_identity(&self) -> bool {
        matches!(
            self.source,
            TokenSource::Metadata {
                expected_email: Some(_),
                ..
            }
        )
    }

    /// The last metadata failure, if it happened after `waited_since` (while
    /// the caller queued for the refresh) or within the failure hold.
    fn recent_failure(&self, waited_since: Instant) -> Option<MetadataFailure> {
        let guard = self.last_failure.lock().expect("failure lock");
        guard
            .as_ref()
            .filter(|(at, _)| *at >= waited_since || at.elapsed() < self.failure_hold)
            .map(|(_, failure)| failure.clone())
    }

    /// For the metadata credential source, fetch a token and read the identity
    /// and scopes behind it, retrying `attempts` times `retry` apart while it
    /// fails. Meant to run once at start-up, so that a missing Workload
    /// Identity binding, an unexpected identity or an unusable scope shows
    /// before the first push. The fetched token is cached as usual.
    pub async fn check_workload_identity(&self, attempts: u32, retry: Duration) -> IdentityCheck {
        let TokenSource::Metadata {
            client,
            account_url,
            ..
        } = &self.source
        else {
            return IdentityCheck::NotApplicable;
        };
        let mut attempt = 1;
        loop {
            let outcome = match self.access_token().await {
                Err(error) => IdentityCheck::TokenUnavailable(error),
                Ok(_) => match read_identity(client, account_url)
                    .await
                    .map_err(|failure| failure.error)
                {
                    Ok(identity) if identity.can_send_fcm() => IdentityCheck::Ready(identity),
                    Ok(identity) => IdentityCheck::UnusableScopes(identity),
                    Err(error) => IdentityCheck::IdentityUnreadable(error),
                },
            };
            let failed = matches!(
                outcome,
                IdentityCheck::TokenUnavailable(_) | IdentityCheck::IdentityUnreadable(_)
            );
            if !failed || attempt >= attempts {
                return outcome;
            }
            attempt += 1;
            tokio::time::sleep(retry).await;
        }
    }

    /// Exchange a signed assertion at the token endpoint (JWT-bearer grant).
    async fn exchange_assertion(&self, assertion: &str) -> Result<TokenResponse, ProviderError> {
        let response = self
            .client
            .post(&self.token_endpoint)
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
            "{}/v1/projects/{}/messages:send",
            self.send_base, self.project_id
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

        // A workload identity can be rebound or revoked under a running
        // process; drop a token FCM no longer accepts so the next push fetches
        // a new one rather than failing until it expires. Only that token: a
        // concurrent refresh may already have replaced it.
        if status == reqwest::StatusCode::UNAUTHORIZED
            && matches!(self.source, TokenSource::Metadata { .. })
        {
            let mut cached = self.token.lock().expect("token lock");
            if cached
                .as_ref()
                .is_some_and(|cached| cached.token == access_token)
            {
                cached.take();
            }
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

/// A failed metadata request: the error the caller sees, and whether it is
/// worth riding out on a still-valid cached token.
#[derive(Clone, Debug)]
struct MetadataFailure {
    error: ProviderError,
    /// The server could not be reached, answered 5xx, 429 or 408, or broke
    /// off: likely to pass. A refusal, a wrong identity or a malformed answer
    /// is not.
    transient: bool,
}

/// The failure a metadata problem becomes.
///
/// Failure detail (the endpoint, the bound service account, the IAM error
/// behind a refusal) goes to the operator's log only; this error reaches the
/// calling app in the relay's failure body, so it stays generic.
fn credentials_unavailable(why: &str, transient: bool) -> MetadataFailure {
    MetadataFailure {
        error: ProviderError::Delivery(format!("fcm credentials unavailable ({why})")),
        transient,
    }
}

/// Why a response body could not be read.
enum BodyError {
    TooLarge,
    Read(reqwest::Error),
}

impl BodyError {
    fn describe(&self) -> String {
        match self {
            Self::TooLarge => "body too large".to_string(),
            Self::Read(error) => format!("{error:?}"),
        }
    }
}

/// GET one metadata-server path (`/token`, `/email`, `/scopes`) and return its
/// body, only from a successful response that says it comes from Google's
/// metadata server, and only up to [`METADATA_BODY_MAX`].
async fn metadata_get(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, MetadataFailure> {
    let response = client
        .get(url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await
        .map_err(|error| {
            warn!(error = ?error, "metadata server unreachable for FCM credentials");
            credentials_unavailable("metadata server unreachable", true)
        })?;
    let status = response.status();
    if !status.is_success() {
        let body = match read_capped(response).await {
            Ok(body) => String::from_utf8_lossy(&body).into_owned(),
            Err(why) => format!("<{}>", why.describe()),
        };
        warn!(
            status = status.as_u16(),
            body = ?truncated(&body, METADATA_LOGGED_BODY_MAX),
            "metadata server refused an FCM credentials request"
        );
        return Err(credentials_unavailable(
            &format!("metadata status {}", status.as_u16()),
            status.is_server_error()
                || status == reqwest::StatusCode::TOO_MANY_REQUESTS
                || status == reqwest::StatusCode::REQUEST_TIMEOUT,
        ));
    }
    // Google's metadata server marks every response; something else answering
    // on the link-local address (off Google Cloud) does not.
    let flavored = response
        .headers()
        .get("metadata-flavor")
        .is_some_and(|value| value == "Google");
    if !flavored {
        warn!("an FCM credentials response did not come from a Google metadata server");
        return Err(credentials_unavailable(
            "not a Google metadata server",
            false,
        ));
    }
    read_capped(response).await.map_err(|why| {
        warn!(
            why = why.describe(),
            "metadata server sent an unreadable FCM credentials response"
        );
        credentials_unavailable(
            "malformed metadata response",
            matches!(why, BodyError::Read(_)),
        )
    })
}

/// Read a response body, refusing one larger than [`METADATA_BODY_MAX`].
async fn read_capped(mut response: reqwest::Response) -> Result<Vec<u8>, BodyError> {
    if response
        .content_length()
        .is_some_and(|length| length > METADATA_BODY_MAX as u64)
    {
        return Err(BodyError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(BodyError::Read)? {
        if body.len() + chunk.len() > METADATA_BODY_MAX {
            return Err(BodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Fail unless the metadata server issues tokens for `expected`.
async fn check_metadata_identity(
    client: &reqwest::Client,
    account_url: &str,
    expected: &str,
) -> Result<(), MetadataFailure> {
    let email = metadata_text(client, &format!("{account_url}/email")).await?;
    if email == expected {
        return Ok(());
    }
    warn!(
        expected,
        actual = ?truncated(&email, METADATA_LOGGED_BODY_MAX),
        "metadata server issues tokens for another identity than \
         FCM_SERVICE_ACCOUNT_EMAIL; refusing to send as it"
    );
    Err(credentials_unavailable(
        "unexpected metadata identity",
        false,
    ))
}

/// Fetch the workload's access token from the metadata server. With
/// `expected_email`, the identity is checked before the token is fetched and
/// again after, so a token issued while the binding changed is not kept.
async fn fetch_metadata_token(
    client: &reqwest::Client,
    account_url: &str,
    expected_email: Option<&str>,
) -> Result<TokenResponse, MetadataFailure> {
    if let Some(expected) = expected_email {
        check_metadata_identity(client, account_url, expected).await?;
    }
    let body = metadata_get(client, &format!("{account_url}/token")).await?;
    // Only the error's category and position are logged: serde quotes the
    // offending value, which here could be the token itself.
    let mut token: TokenResponse = serde_json::from_slice(&body).map_err(|error| {
        warn!(
            category = ?error.classify(),
            line = error.line(),
            column = error.column(),
            "metadata server sent an unreadable FCM token response"
        );
        credentials_unavailable("malformed metadata token response", false)
    })?;
    if token.access_token.is_empty() || token.expires_in <= 0 {
        warn!(
            expires_in = token.expires_in,
            "metadata server sent an FCM token response without a usable token"
        );
        return Err(credentials_unavailable(
            "malformed metadata token response",
            false,
        ));
    }
    if let Some(expected) = expected_email {
        check_metadata_identity(client, account_url, expected).await?;
    }
    token.expires_in = token.expires_in.min(METADATA_TOKEN_MAX_LIFETIME_SECS);
    Ok(token)
}

/// Read a plain-text metadata value, trimmed.
async fn metadata_text(client: &reqwest::Client, url: &str) -> Result<String, MetadataFailure> {
    let body = metadata_get(client, url).await?;
    String::from_utf8(body)
        .map(|text| text.trim().to_string())
        .map_err(|_| {
            warn!("metadata server sent a non-UTF-8 FCM credentials response");
            credentials_unavailable("malformed metadata response", false)
        })
}

/// The service account and scopes the metadata server reports.
async fn read_identity(
    client: &reqwest::Client,
    account_url: &str,
) -> Result<WorkloadIdentity, MetadataFailure> {
    let email = metadata_text(client, &format!("{account_url}/email")).await?;
    let scopes = metadata_text(client, &format!("{account_url}/scopes"))
        .await?
        .lines()
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
        .collect();
    Ok(WorkloadIdentity { email, scopes })
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
        assert!(matches!(
            cfg.credentials,
            FcmCredentials::Metadata {
                expected_email: None
            }
        ));
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
    fn a_malformed_key_json_error_never_quotes_the_key() {
        // A double-encoded secret: the whole service-account JSON as one JSON string.
        let double_encoded = serde_json::to_string(&service_account_json()).unwrap();
        let ConfigError::Invalid { reason, .. } =
            config(&[("FCM_SERVICE_ACCOUNT_JSON", &double_encoded)]).unwrap_err()
        else {
            panic!("expected an invalid-value error");
        };
        assert!(!reason.contains("PRIVATE KEY"), "{reason}");
        assert!(!reason.contains("push@brevity-proj"), "{reason}");
        assert!(
            reason.starts_with("not valid service-account JSON (Data error at line 1, column "),
            "{reason}"
        );
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

    #[test]
    fn expected_email_pins_the_metadata_identity_and_is_validated() {
        let cfg = config(&[
            ("FCM_PROJECT_ID", "pcf-push-devnet"),
            ("FCM_SERVICE_ACCOUNT_EMAIL", SENDER),
        ])
        .unwrap()
        .expect("configured");
        assert!(matches!(
            cfg.credentials,
            FcmCredentials::Metadata { expected_email: Some(ref email) } if email == SENDER
        ));
        // Blank counts as unset.
        let cfg = config(&[
            ("FCM_PROJECT_ID", "pcf-push-devnet"),
            ("FCM_SERVICE_ACCOUNT_EMAIL", " "),
        ])
        .unwrap()
        .expect("configured");
        assert!(matches!(
            cfg.credentials,
            FcmCredentials::Metadata {
                expected_email: None
            }
        ));

        for (pairs, key) in [
            // Without workload credentials it would silently do nothing.
            (
                vec![("FCM_SERVICE_ACCOUNT_EMAIL", SENDER)],
                "FCM_SERVICE_ACCOUNT_EMAIL",
            ),
            (
                vec![
                    (
                        "FCM_SERVICE_ACCOUNT_JSON",
                        service_account_json().leak() as &str,
                    ),
                    ("FCM_SERVICE_ACCOUNT_EMAIL", SENDER),
                ],
                "FCM_SERVICE_ACCOUNT_EMAIL",
            ),
            (
                vec![
                    (
                        "FCM_SERVICE_ACCOUNT_JSON",
                        service_account_json().leak() as &str,
                    ),
                    ("FCM_PROJECT_ID", "pcf-push-devnet"),
                    ("FCM_SERVICE_ACCOUNT_EMAIL", SENDER),
                ],
                "FCM_PROJECT_ID",
            ),
        ] {
            assert!(
                matches!(config(&pairs), Err(ConfigError::Invalid { key: k, .. }) if k == key),
                "{pairs:?}"
            );
        }
        for bad in [
            "fcm-push-sender",
            "fcm-push-sender@gmail.com",
            "Fcm@p.iam.gserviceaccount.com",
            "fcm@p.iam.gserviceaccount.com.evil.com",
            "fcm@.iam.gserviceaccount.com",
            "fcm@p..iam.gserviceaccount.com",
            "@p.iam.gserviceaccount.com",
            "fcm@p.iam.gserviceaccount.com\n",
            "a@b@p.iam.gserviceaccount.com",
        ] {
            assert!(
                matches!(
                    config(&[
                        ("FCM_PROJECT_ID", "pcf-push-devnet"),
                        ("FCM_SERVICE_ACCOUNT_EMAIL", bad)
                    ]),
                    Err(ConfigError::Invalid {
                        key: "FCM_SERVICE_ACCOUNT_EMAIL",
                        ..
                    })
                ),
                "{bad:?} should be refused"
            );
        }
    }

    const SENDER: &str = "fcm-push-sender@pcf-push-devnet.iam.gserviceaccount.com";

    /// A stand-in for the metadata server under `/sa` (`/token`, `/email`,
    /// `/scopes`), and for Google's token endpoint (`/oauth`) and FCM
    /// (`/v1/...`). It counts token requests and records whether every
    /// metadata request carried `Metadata-Flavor: Google` and no query string.
    struct Mock {
        token_hits: std::sync::atomic::AtomicUsize,
        well_formed: std::sync::atomic::AtomicBool,
        token_status: std::sync::atomic::AtomicU16,
        token_body: Mutex<String>,
        token_delay: Duration,
        flavored: bool,
        email: String,
        email_hits: std::sync::atomic::AtomicUsize,
        /// From this many `/email` requests on, answer with another identity.
        email_changes_after: Option<(usize, String)>,
        oauth_hits: std::sync::atomic::AtomicUsize,
        scopes: String,
        oauth: (u16, String),
        send: (u16, String),
    }

    impl Mock {
        fn new(status: u16, token: Value) -> Self {
            Self {
                token_hits: 0.into(),
                well_formed: true.into(),
                token_status: status.into(),
                token_body: Mutex::new(token.to_string()),
                token_delay: Duration::ZERO,
                flavored: true,
                email: SENDER.to_string(),
                email_hits: 0.into(),
                email_changes_after: None,
                oauth_hits: 0.into(),
                scopes: format!("{CLOUD_PLATFORM_SCOPE}\n"),
                oauth: (200, String::new()),
                send: (200, json!({"name": "projects/p/messages/1"}).to_string()),
            }
        }
    }

    async fn serve(mock: Mock) -> (String, Arc<Mock>) {
        use axum::extract::{Path, RawQuery, State};
        use axum::http::{header, HeaderMap, StatusCode};
        use axum::response::{IntoResponse, Response};
        use std::sync::atomic::Ordering;

        fn reply(status: u16, body: String) -> Response {
            (StatusCode::from_u16(status).unwrap(), body).into_response()
        }

        let mock = Arc::new(mock);
        let metadata = axum::routing::get(
            |State(mock): State<Arc<Mock>>,
             Path(item): Path<String>,
             RawQuery(query): RawQuery,
             headers: HeaderMap| async move {
                let flavored = headers
                    .get("metadata-flavor")
                    .is_some_and(|value| value == "Google");
                if !flavored || query.is_some() {
                    mock.well_formed.store(false, Ordering::SeqCst);
                }
                let mut response = match item.as_str() {
                    "token" => {
                        mock.token_hits.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(mock.token_delay).await;
                        let status =
                            StatusCode::from_u16(mock.token_status.load(Ordering::SeqCst)).unwrap();
                        if status.is_redirection() {
                            // Point somewhere that would succeed if followed.
                            (status, [(header::LOCATION, "/sa/email")], "").into_response()
                        } else {
                            let body = mock.token_body.lock().unwrap().clone();
                            (status, body).into_response()
                        }
                    }
                    "email" => {
                        let seen = mock.email_hits.fetch_add(1, Ordering::SeqCst);
                        match &mock.email_changes_after {
                            Some((after, other)) if seen >= *after => other.clone().into_response(),
                            _ => mock.email.clone().into_response(),
                        }
                    }
                    "scopes" => mock.scopes.clone().into_response(),
                    _ => StatusCode::NOT_FOUND.into_response(),
                };
                if mock.flavored {
                    response
                        .headers_mut()
                        .insert("metadata-flavor", "Google".parse().unwrap());
                }
                response
            },
        );
        let app = axum::Router::new()
            .route("/sa/{item}", metadata)
            .route(
                "/oauth",
                axum::routing::post(|State(mock): State<Arc<Mock>>| async move {
                    mock.oauth_hits.fetch_add(1, Ordering::SeqCst);
                    reply(mock.oauth.0, mock.oauth.1.clone())
                }),
            )
            .route(
                "/v1/projects/{project}/{action}",
                axum::routing::post(|State(mock): State<Arc<Mock>>| async move {
                    reply(mock.send.0, mock.send.1.clone())
                }),
            )
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), mock)
    }

    fn endpoints(base: &str, failure_hold: Duration) -> Endpoints {
        Endpoints {
            token: format!("{base}/oauth"),
            send_base: base.to_string(),
            metadata_account: format!("{base}/sa"),
            failure_hold,
        }
    }

    /// No failure hold, so sequential calls each fetch; the hold has its own test.
    fn provider_at(base: &str, pairs: &[(&str, &str)]) -> FcmProvider {
        let cfg = config(pairs).unwrap().expect("configured");
        FcmProvider::with_endpoints(cfg, endpoints(base, Duration::ZERO)).expect("provider")
    }

    fn metadata_provider(base: &str) -> FcmProvider {
        provider_at(base, &[("FCM_PROJECT_ID", "pcf-push-devnet")])
    }

    async fn metadata_server(status: u16, token: Value) -> (String, Arc<Mock>) {
        serve(Mock::new(status, token)).await
    }

    fn hits(mock: &Mock) -> usize {
        mock.token_hits.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn good_token() -> Value {
        json!({"access_token": "ya29.workload", "expires_in": 3599, "token_type": "Bearer"})
    }

    fn push() -> PushRequest {
        PushRequest {
            device_token: "dev-token".to_string(),
            push_id: "5d41402abc4b2a76b9719d911017c592".to_string(),
            message: "0xdead".to_string(),
            topic: None,
            voip: None,
        }
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
    async fn concurrent_callers_share_one_metadata_refresh() {
        let mut mock = Mock::new(200, good_token());
        mock.token_delay = Duration::from_millis(100);
        let (url, mock) = serve(mock).await;
        let provider = Arc::new(metadata_provider(&url));

        let calls: Vec<_> = (0..8)
            .map(|_| {
                let provider = provider.clone();
                tokio::spawn(async move { provider.access_token().await })
            })
            .collect();
        for call in calls {
            assert_eq!(call.await.unwrap().unwrap(), "ya29.workload");
        }
        assert_eq!(hits(&mock), 1, "one fetch serves every waiting caller");
    }

    #[tokio::test]
    async fn metadata_token_inside_the_refresh_buffer_is_refreshed() {
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
    async fn failed_refresh_falls_back_to_the_still_valid_token() {
        // Inside the refresh buffer but not yet expired.
        let (url, mock) = metadata_server(
            200,
            json!({"access_token": "ya29.still-valid", "expires_in": TOKEN_REFRESH_BUFFER_SECS / 2}),
        )
        .await;
        let provider = metadata_provider(&url);
        provider.access_token().await.unwrap();

        for transient in [503, 429, 408] {
            mock.token_status
                .store(transient, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                provider.access_token().await.unwrap(),
                "ya29.still-valid",
                "{transient} is ridden out"
            );
        }
        assert_eq!(hits(&mock), 4, "each call attempted a refresh");
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
            expires_at <= before + METADATA_TOKEN_MAX_LIFETIME_SECS + 1,
            "valid until {expires_at}, more than an hour after {before}"
        );
    }

    #[test]
    fn cached_token_arithmetic_saturates() {
        let token = CachedToken::new(String::new(), i64::MIN + 5, i64::MIN);
        assert_eq!(token.expires_at, i64::MIN);
        assert_eq!(token.refresh_at, i64::MIN);
        let token = CachedToken::new(String::new(), i64::MAX - 5, i64::MAX);
        assert_eq!(token.expires_at, i64::MAX);
        assert_eq!(token.refresh_at, i64::MAX - TOKEN_REFRESH_BUFFER_SECS);
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
    async fn response_without_the_metadata_flavor_header_is_refused() {
        let mut mock = Mock::new(200, good_token());
        mock.flavored = false;
        let (url, _mock) = serve(mock).await;
        let error = metadata_provider(&url)
            .access_token()
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "fcm credentials unavailable (not a Google metadata server)"
        );
    }

    #[tokio::test]
    async fn oversized_metadata_response_is_refused() {
        let huge = json!({"access_token": "x".repeat(METADATA_BODY_MAX), "expires_in": 3599});
        let (url, _mock) = metadata_server(200, huge).await;
        let error = metadata_provider(&url)
            .access_token()
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "fcm credentials unavailable (malformed metadata response)"
        );
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

    #[test]
    fn only_the_metadata_server_is_asked_for_a_token() {
        assert_eq!(
            METADATA_ACCOUNT_URL,
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default"
        );
        assert!(is_metadata_account(METADATA_ACCOUNT_URL, false));
        for url in [
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default",
            "https://169.254.169.254/computeMetadata/v1/instance/service-accounts/default",
            "http://169.254.169.254:8080/computeMetadata/v1/instance/service-accounts/default",
            "http://169.254.169.254.example.com/computeMetadata/v1/instance/service-accounts/default",
            "http://user@169.254.169.254/computeMetadata/v1/instance/service-accounts/default",
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/other",
            "http://127.0.0.1:8080/sa",
            "",
            "HTTP://169.254.169.254/computeMetadata/v1/instance/service-accounts/default",
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/",
            "http://169.254.169.254/computeMetadata/v1/instance%2Fservice-accounts/default",
        ] {
            assert!(!is_metadata_account(url, false), "{url}");
        }
        assert!(is_metadata_account("http://127.0.0.1:8080/sa", true));
        assert!(!is_metadata_account("https://127.0.0.1:8080/sa", true));
        for url in [
            "http://10.0.0.1/sa",
            "http://127.0.0.1@10.0.0.1/sa",
            "http://127.0.0.1.example.com/sa",
            "http://localhost/sa",
        ] {
            assert!(!is_metadata_account(url, true), "{url}");
        }
        let cfg = config(&[("FCM_PROJECT_ID", "example-project")])
            .unwrap()
            .expect("configured");
        assert!(matches!(
            FcmProvider::with_endpoints(cfg, endpoints("http://10.0.0.1", Duration::ZERO)),
            Err(FcmInitError::NotMetadataServer)
        ));
    }

    #[tokio::test]
    async fn unreachable_metadata_server_does_not_echo_the_endpoint() {
        // Bound but never listening: connections are refused, and the port
        // stays reserved so no other test's mock server can be given it.
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let url = format!("http://{}", socket.local_addr().unwrap());

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
    async fn token_for_an_unexpected_identity_is_refused() {
        let mut mock = Mock::new(200, good_token());
        mock.email = "123456789-compute@developer.gserviceaccount.com".to_string();
        let (url, mock) = serve(mock).await;
        let provider = provider_at(
            &url,
            &[
                ("FCM_PROJECT_ID", "pcf-push-devnet"),
                ("FCM_SERVICE_ACCOUNT_EMAIL", SENDER),
            ],
        );

        let error = provider.access_token().await.unwrap_err().to_string();
        assert_eq!(
            error,
            "fcm credentials unavailable (unexpected metadata identity)"
        );
        assert_eq!(hits(&mock), 0, "no token is fetched for the wrong identity");
    }

    #[tokio::test]
    async fn token_for_the_expected_identity_is_used() {
        let (url, mock) = metadata_server(200, good_token()).await;
        let provider = provider_at(
            &url,
            &[
                ("FCM_PROJECT_ID", "pcf-push-devnet"),
                ("FCM_SERVICE_ACCOUNT_EMAIL", SENDER),
            ],
        );
        assert_eq!(provider.access_token().await.unwrap(), "ya29.workload");
        assert_eq!(hits(&mock), 1);
    }

    #[tokio::test]
    async fn fcm_401_drops_the_cached_metadata_token() {
        let mut mock = Mock::new(200, good_token());
        mock.send = (
            401,
            json!({"error": {"code": 401, "status": "UNAUTHENTICATED", "message": "Request had invalid authentication credentials."}}).to_string(),
        );
        let (url, mock) = serve(mock).await;
        let provider = metadata_provider(&url);

        let error = provider.send(&push()).await.unwrap_err().to_string();
        assert_eq!(error, "Request had invalid authentication credentials.");
        provider.access_token().await.unwrap();
        assert_eq!(hits(&mock), 2, "the rejected token was not reused");
    }

    #[tokio::test]
    async fn check_reports_identity_and_scopes_and_warms_the_cache() {
        let (url, mock) = metadata_server(200, good_token()).await;
        let provider = metadata_provider(&url);

        let IdentityCheck::Ready(identity) =
            provider.check_workload_identity(3, Duration::ZERO).await
        else {
            panic!("expected a ready identity");
        };
        assert_eq!(identity.email, SENDER);
        assert_eq!(identity.scopes, vec![CLOUD_PLATFORM_SCOPE.to_string()]);
        assert!(mock.well_formed.load(std::sync::atomic::Ordering::SeqCst));

        provider.access_token().await.unwrap();
        assert_eq!(
            hits(&mock),
            1,
            "the check's token is reused by the first push"
        );
    }

    #[tokio::test]
    async fn check_flags_scopes_fcm_does_not_accept() {
        // What a VM or node service account with default access scopes reports.
        let mut mock = Mock::new(200, good_token());
        mock.scopes = "https://www.googleapis.com/auth/devstorage.read_only\n\
                       https://www.googleapis.com/auth/logging.write\n"
            .to_string();
        let (url, _mock) = serve(mock).await;
        let check = metadata_provider(&url)
            .check_workload_identity(3, Duration::ZERO)
            .await;
        let IdentityCheck::UnusableScopes(identity) = check else {
            panic!("expected unusable scopes, got {check:?}");
        };
        assert_eq!(identity.scopes.len(), 2);

        let fcm_only = WorkloadIdentity {
            email: String::new(),
            scopes: vec![FCM_SCOPE.to_string()],
        };
        assert!(fcm_only.can_send_fcm());
    }

    #[tokio::test]
    async fn check_retries_a_failing_token_then_reports_it() {
        let (url, mock) = metadata_server(503, json!("starting")).await;
        let check = metadata_provider(&url)
            .check_workload_identity(3, Duration::ZERO)
            .await;
        assert!(
            matches!(check, IdentityCheck::TokenUnavailable(_)),
            "{check:?}"
        );
        assert_eq!(hits(&mock), 3, "one fetch per attempt");
    }

    #[tokio::test]
    async fn check_separates_an_unreadable_identity_from_a_missing_token() {
        let mut mock = Mock::new(200, good_token());
        mock.scopes = "\u{0}".repeat(METADATA_BODY_MAX + 1);
        let (url, _mock) = serve(mock).await;
        let check = metadata_provider(&url)
            .check_workload_identity(1, Duration::ZERO)
            .await;
        assert!(
            matches!(check, IdentityCheck::IdentityUnreadable(_)),
            "{check:?}"
        );
    }

    #[tokio::test]
    async fn check_is_not_applicable_to_a_service_account_key() {
        assert!(matches!(
            provider().check_workload_identity(3, Duration::ZERO).await,
            IdentityCheck::NotApplicable
        ));
    }

    // The key path's client-visible strings, pinned to what they were before
    // the metadata source existed. They embed reqwest's own error wording, so a
    // reqwest upgrade that rewords it fails here: the client sees these strings.
    #[tokio::test]
    async fn key_path_token_exchange_errors_are_unchanged() {
        let body = json!({"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
            .to_string();
        let mut mock = Mock::new(200, good_token());
        mock.oauth = (400, body.clone());
        let (url, _mock) = serve(mock).await;
        let provider = provider_at(
            &url,
            &[("FCM_SERVICE_ACCOUNT_JSON", &service_account_json())],
        );
        assert_eq!(
            provider.send(&push()).await.unwrap_err().to_string(),
            format!("fcm token exchange rejected (400): {body}")
        );

        let mut mock = Mock::new(200, good_token());
        mock.oauth = (200, "not json".to_string());
        let (url, _mock) = serve(mock).await;
        let provider = provider_at(
            &url,
            &[("FCM_SERVICE_ACCOUNT_JSON", &service_account_json())],
        );
        assert_eq!(
            provider.send(&push()).await.unwrap_err().to_string(),
            "fcm token response: error decoding response body"
        );

        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let url = format!("http://{}", socket.local_addr().unwrap());
        let provider = provider_at(
            &url,
            &[("FCM_SERVICE_ACCOUNT_JSON", &service_account_json())],
        );
        assert_eq!(
            provider.send(&push()).await.unwrap_err().to_string(),
            format!("fcm token exchange failed: error sending request for url ({url}/oauth)")
        );
        drop(socket);
    }

    #[tokio::test]
    async fn key_path_sends_with_its_token_and_reports_fcm_verdicts() {
        let mut mock = Mock::new(200, good_token());
        mock.oauth = (
            200,
            json!({"access_token": "ya29.key", "expires_in": 3599}).to_string(),
        );
        let (url, _mock) = serve(mock).await;
        let provider = provider_at(
            &url,
            &[("FCM_SERVICE_ACCOUNT_JSON", &service_account_json())],
        );
        assert_eq!(
            provider.send(&push()).await.unwrap(),
            fcm_success(Some("projects/p/messages/1".to_string()))
        );

        let mut mock = Mock::new(200, good_token());
        mock.oauth = (
            200,
            json!({"access_token": "ya29.key", "expires_in": 3599}).to_string(),
        );
        mock.send = (
            404,
            r#"{"error":{"code":404,"status":"NOT_FOUND","message":"Requested entity was not found.","details":[{"errorCode":"UNREGISTERED"}]}}"#.to_string(),
        );
        let (url, _mock) = serve(mock).await;
        let provider = provider_at(
            &url,
            &[("FCM_SERVICE_ACCOUNT_JSON", &service_account_json())],
        );
        assert_eq!(
            provider.send(&push()).await.unwrap_err().to_string(),
            "Requested entity was not found."
        );
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_failed_refresh() {
        let mut mock = Mock::new(503, json!("unavailable"));
        mock.token_delay = Duration::from_millis(200);
        let (url, mock) = serve(mock).await;
        let provider = Arc::new(metadata_provider(&url));

        let calls: Vec<_> = (0..8)
            .map(|_| {
                let provider = provider.clone();
                tokio::spawn(async move { provider.access_token().await })
            })
            .collect();
        for call in calls {
            assert_eq!(
                call.await.unwrap().unwrap_err().to_string(),
                "fcm credentials unavailable (metadata status 503)"
            );
        }
        assert_eq!(
            hits(&mock),
            1,
            "waiters adopt the failure instead of repeating it"
        );
    }

    #[tokio::test]
    async fn a_failure_answers_for_the_hold_then_is_retried() {
        let (url, mock) = metadata_server(503, json!("unavailable")).await;
        let cfg = config(&[("FCM_PROJECT_ID", "pcf-push-devnet")])
            .unwrap()
            .expect("configured");
        let provider =
            FcmProvider::with_endpoints(cfg, endpoints(&url, Duration::from_secs(1))).unwrap();

        provider.access_token().await.unwrap_err();
        provider.access_token().await.unwrap_err();
        assert_eq!(hits(&mock), 1, "inside the hold the failure is reused");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        provider.access_token().await.unwrap_err();
        assert_eq!(hits(&mock), 2, "after the hold the server is asked again");
    }

    #[tokio::test]
    async fn a_refusal_inside_the_refresh_buffer_is_not_ridden_out() {
        let (url, mock) = metadata_server(
            200,
            json!({"access_token": "ya29.still-valid", "expires_in": TOKEN_REFRESH_BUFFER_SECS / 2}),
        )
        .await;
        let provider = metadata_provider(&url);
        provider.access_token().await.unwrap();

        mock.token_status
            .store(403, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            provider.access_token().await.unwrap_err().to_string(),
            "fcm credentials unavailable (metadata status 403)",
            "a refusal is not transient, so the cached token is not served"
        );
    }

    #[tokio::test]
    async fn an_expired_token_is_never_served_when_refresh_fails() {
        let (url, _mock) = metadata_server(503, json!("unavailable")).await;
        let provider = metadata_provider(&url);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        *provider.token.lock().unwrap() = Some(CachedToken::new(
            "ya29.expired".to_string(),
            now - 7200,
            3600,
        ));

        assert_eq!(
            provider.access_token().await.unwrap_err().to_string(),
            "fcm credentials unavailable (metadata status 503)"
        );
    }

    #[tokio::test]
    async fn identity_change_during_a_fetch_discards_the_token() {
        let mut mock = Mock::new(200, good_token());
        mock.email_changes_after = Some((
            1,
            "123456789-compute@developer.gserviceaccount.com".to_string(),
        ));
        let (url, mock) = serve(mock).await;
        let provider = provider_at(
            &url,
            &[
                ("FCM_PROJECT_ID", "pcf-push-devnet"),
                ("FCM_SERVICE_ACCOUNT_EMAIL", SENDER),
            ],
        );

        assert_eq!(
            provider.access_token().await.unwrap_err().to_string(),
            "fcm credentials unavailable (unexpected metadata identity)"
        );
        assert_eq!(
            hits(&mock),
            1,
            "the token was fetched between the two checks"
        );
        assert!(provider.token.lock().unwrap().is_none(), "and not kept");
    }

    #[tokio::test]
    async fn key_path_keeps_its_token_after_an_fcm_401() {
        let mut mock = Mock::new(200, good_token());
        mock.oauth = (
            200,
            json!({"access_token": "ya29.key", "expires_in": 3599}).to_string(),
        );
        mock.send = (
            401,
            json!({"error": {"code": 401, "status": "UNAUTHENTICATED", "message": "Request had invalid authentication credentials."}}).to_string(),
        );
        let (url, mock) = serve(mock).await;
        let provider = provider_at(
            &url,
            &[("FCM_SERVICE_ACCOUNT_JSON", &service_account_json())],
        );

        provider.send(&push()).await.unwrap_err();
        provider.access_token().await.unwrap();
        assert_eq!(
            mock.oauth_hits.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the key path caches exactly as before"
        );
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
