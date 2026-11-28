// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Access tokens for the workload's own Google identity, from the metadata
//! server (GKE Workload Identity, or a Compute Engine instance's service
//! account). No credential is held by the process.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use secrecy::SecretString;
use serde::Deserialize;

/// The workload's default service account's token. Addressed by IP so the
/// lookup is never answered by a cluster DNS search domain. No `scopes`
/// parameter: the GKE metadata server does not document one, and the IAM
/// Credentials API this token calls accepts the default `cloud-platform`
/// scope.
pub(crate) const METADATA_TOKEN_URL: &str =
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token";
/// The metadata server is link-local: a connection that does not open at once
/// means it is not there (yet: it takes a few seconds in a new pod).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// A token response is well under a kilobyte; anything larger is refused.
const BODY_MAX: usize = 64 * 1024;
/// Metadata tokens live at most an hour; a longer claim is not trusted.
const MAX_LIFETIME_SECS: u64 = 3600;
/// Refetch when less than this is left, Google's guidance for metadata-server
/// tokens (3 min 45 s).
const REFRESH_BUFFER: Duration = Duration::from_secs(225);

/// Why no token could be had. The text is generic; detail goes to the log.
#[derive(Debug, thiserror::Error)]
#[error("{why}")]
pub(crate) struct TokenError {
    pub(crate) why: &'static str,
    /// Unreachable or 5xx: likely to pass.
    pub(crate) transient: bool,
}

impl TokenError {
    fn new(why: &'static str, transient: bool) -> Self {
        Self { why, transient }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

struct Cached {
    token: SecretString,
    /// Monotonic, so a wall-clock step cannot keep a token past its life.
    refresh_at: Instant,
}

/// A cached source of the workload's access tokens.
pub(crate) struct WorkloadTokens {
    client: reqwest::Client,
    url: String,
    cached: Mutex<Option<Cached>>,
    /// One fetch at a time; callers that queue behind it take its token.
    refresh: tokio::sync::Mutex<()>,
}

/// Why a token source could not be built.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BuildError {
    #[error("workload tokens are only fetched from the metadata server")]
    NotMetadataServer,
    #[error("http client: {0}")]
    Client(#[from] reqwest::Error),
}

/// The plain-HTTP token request may only go to Google's link-local metadata
/// server, so nothing can point it at another host or path. Test builds also
/// allow a loopback mock server.
fn is_metadata_server(url: &str, allow_loopback: bool) -> bool {
    url == METADATA_TOKEN_URL
        || (allow_loopback
            && reqwest::Url::parse(url)
                .is_ok_and(|url| url.scheme() == "http" && url.host_str() == Some("127.0.0.1")))
}

impl WorkloadTokens {
    pub(crate) fn new(url: &str) -> Result<Self, BuildError> {
        if !is_metadata_server(url, cfg!(test)) {
            return Err(BuildError::NotMetadataServer);
        }
        // The token comes back over plain HTTP from a node-local endpoint:
        // never through a proxy from the environment, never via a redirect.
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            url: url.to_string(),
            cached: Mutex::new(None),
            refresh: tokio::sync::Mutex::new(()),
        })
    }

    fn cached(&self) -> Option<SecretString> {
        self.cached
            .lock()
            .expect("token lock")
            .as_ref()
            .filter(|cached| Instant::now() < cached.refresh_at)
            .map(|cached| cached.token.clone())
    }

    /// Forget the cached token, if it is still `rejected`, so the next call
    /// fetches a new one: the API refused it before it was due to expire.
    pub(crate) fn invalidate(&self, rejected: &SecretString) {
        use secrecy::ExposeSecret as _;
        let mut cached = self.cached.lock().expect("token lock");
        if cached
            .as_ref()
            .is_some_and(|c| c.token.expose_secret() == rejected.expose_secret())
        {
            cached.take();
        }
    }

    /// A valid access token, fetched when the cached one is due for refresh.
    pub(crate) async fn token(&self) -> Result<SecretString, TokenError> {
        if let Some(token) = self.cached() {
            return Ok(token);
        }
        let _refreshing = self.refresh.lock().await;
        if let Some(token) = self.cached() {
            return Ok(token);
        }
        let fetched_at = Instant::now();
        let token = self.fetch().await?;
        // Positive by `fetch`; capped at an hour.
        let lifetime = Duration::from_secs(token.expires_in.unsigned_abs().min(MAX_LIFETIME_SECS));
        let token_secret = SecretString::from(token.access_token);
        *self.cached.lock().expect("token lock") = Some(Cached {
            token: token_secret.clone(),
            refresh_at: fetched_at + lifetime.saturating_sub(REFRESH_BUFFER),
        });
        Ok(token_secret)
    }

    async fn fetch(&self) -> Result<TokenResponse, TokenError> {
        let mut response = self
            .client
            .get(&self.url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(error = ?error, "metadata server unreachable for a workload token");
                TokenError::new("metadata server unreachable", true)
            })?;
        let status = response.status();
        if !status.is_success() {
            tracing::warn!(
                status = status.as_u16(),
                "metadata server refused a workload token"
            );
            return Err(TokenError::new(
                "metadata server refused a token",
                status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS,
            ));
        }
        // Google's metadata server marks every response; something else
        // answering on the link-local address does not.
        if response
            .headers()
            .get("metadata-flavor")
            .is_none_or(|value| value != "Google")
        {
            tracing::warn!("a workload token response did not come from a Google metadata server");
            return Err(TokenError::new("not a Google metadata server", false));
        }
        if response
            .content_length()
            .is_some_and(|length| length > BODY_MAX as u64)
        {
            return Err(TokenError::new("malformed metadata token response", false));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            tracing::warn!(error = ?error, "reading a workload token response failed");
            TokenError::new("metadata server unreachable", true)
        })? {
            if body.len() + chunk.len() > BODY_MAX {
                return Err(TokenError::new("malformed metadata token response", false));
            }
            body.extend_from_slice(&chunk);
        }
        // Category and position only: serde quotes the offending value, which
        // here could be the token itself.
        let token: TokenResponse = serde_json::from_slice(&body).map_err(|error| {
            tracing::warn!(
                category = ?error.classify(),
                line = error.line(),
                column = error.column(),
                "metadata server sent an unreadable workload token"
            );
            TokenError::new("malformed metadata token response", false)
        })?;
        if token.access_token.is_empty() || token.expires_in <= 0 {
            return Err(TokenError::new("malformed metadata token response", false));
        }
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use secrecy::ExposeSecret as _;

    use super::*;

    struct Mock {
        hits: AtomicUsize,
        status: u16,
        flavored: bool,
        body: String,
        delay: Duration,
    }

    fn mock(body: serde_json::Value) -> Mock {
        Mock {
            hits: 0.into(),
            status: 200,
            flavored: true,
            body: body.to_string(),
            delay: Duration::ZERO,
        }
    }

    async fn serve(mock: Mock) -> (String, Arc<Mock>) {
        let mock = Arc::new(mock);
        let app = axum::Router::new()
            .route(
                "/token",
                axum::routing::get(|State(mock): State<Arc<Mock>>| async move {
                    let hit = mock.hits.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(mock.delay).await;
                    let body = mock.body.replace("{hit}", &hit.to_string());
                    let mut response: Response =
                        (StatusCode::from_u16(mock.status).unwrap(), body).into_response();
                    if mock.flavored {
                        response
                            .headers_mut()
                            .insert("metadata-flavor", "Google".parse().unwrap());
                    }
                    response
                }),
            )
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/token"), mock)
    }

    fn hits(mock: &Mock) -> usize {
        mock.hits.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn a_token_is_cached_and_shared_by_concurrent_callers() {
        let mut m = mock(serde_json::json!({"access_token": "ya29.t{hit}", "expires_in": 3599}));
        m.delay = Duration::from_millis(100);
        let (url, mock) = serve(m).await;
        let tokens = Arc::new(WorkloadTokens::new(&url).unwrap());
        let calls: Vec<_> = (0..6)
            .map(|_| {
                let tokens = tokens.clone();
                tokio::spawn(async move { tokens.token().await.unwrap() })
            })
            .collect();
        for call in calls {
            assert_eq!(call.await.unwrap().expose_secret(), "ya29.t0");
        }
        assert_eq!(hits(&mock), 1);
    }

    #[tokio::test]
    async fn a_token_inside_the_refresh_buffer_is_refetched() {
        let (url, mock) = serve(mock(serde_json::json!({
            "access_token": "ya29.t{hit}",
            "expires_in": REFRESH_BUFFER.as_secs(),
        })))
        .await;
        let tokens = WorkloadTokens::new(&url).unwrap();
        assert_eq!(tokens.token().await.unwrap().expose_secret(), "ya29.t0");
        assert_eq!(tokens.token().await.unwrap().expose_secret(), "ya29.t1");
        assert_eq!(hits(&mock), 2);
    }

    #[tokio::test]
    async fn an_invalidated_token_is_refetched_but_a_newer_one_is_kept() {
        let (url, mock) = serve(mock(
            serde_json::json!({"access_token": "ya29.t{hit}", "expires_in": 3599}),
        ))
        .await;
        let tokens = WorkloadTokens::new(&url).unwrap();
        let first = tokens.token().await.unwrap();
        tokens.invalidate(&first);
        let second = tokens.token().await.unwrap();
        assert_eq!(second.expose_secret(), "ya29.t1");
        // A stale rejection of the first token leaves the second in place.
        tokens.invalidate(&first);
        assert_eq!(tokens.token().await.unwrap().expose_secret(), "ya29.t1");
        assert_eq!(hits(&mock), 2);
    }

    #[tokio::test]
    async fn untrusted_or_unusable_responses_are_refused() {
        let mut unflavored = mock(serde_json::json!({"access_token": "x", "expires_in": 60}));
        unflavored.flavored = false;
        let huge =
            mock(serde_json::json!({"access_token": "x".repeat(BODY_MAX), "expires_in": 60}));
        let mut refused = mock(serde_json::json!("no"));
        refused.status = 403;
        let mut starting = mock(serde_json::json!("no"));
        starting.status = 503;
        for (m, why, transient) in [
            (unflavored, "not a Google metadata server", false),
            (huge, "malformed metadata token response", false),
            (
                mock(serde_json::json!({"access_token": "x", "expires_in": 0})),
                "malformed metadata token response",
                false,
            ),
            (
                mock(serde_json::json!({"access_token": "", "expires_in": 60})),
                "malformed metadata token response",
                false,
            ),
            (
                mock(serde_json::json!("ya29.bare-string")),
                "malformed metadata token response",
                false,
            ),
            (refused, "metadata server refused a token", false),
            (starting, "metadata server refused a token", true),
        ] {
            let (url, _) = serve(m).await;
            let error = WorkloadTokens::new(&url)
                .unwrap()
                .token()
                .await
                .unwrap_err();
            assert_eq!((error.why, error.transient), (why, transient));
        }
    }

    #[test]
    fn only_the_metadata_server_is_asked_for_a_token() {
        assert_eq!(
            METADATA_TOKEN_URL,
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
        );
        assert!(is_metadata_server(METADATA_TOKEN_URL, false));
        for url in [
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "https://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
            "http://169.254.169.254:8080/computeMetadata/v1/instance/service-accounts/default/token",
            "http://169.254.169.254.example.com/computeMetadata/v1/instance/service-accounts/default/token",
            "http://user@169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/other/token",
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token?x=1",
            "http://127.0.0.1:8080/token",
            "",
            "HTTP://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token/",
            "http://169.254.169.254/computeMetadata/v1/instance%2Fservice-accounts/default/token",
        ] {
            assert!(!is_metadata_server(url, false), "{url}");
        }
        assert!(is_metadata_server("http://127.0.0.1:8080/token", true));
        assert!(!is_metadata_server("https://127.0.0.1:8080/token", true));
        for url in [
            "http://10.0.0.1/token",
            "http://127.0.0.1@10.0.0.1/token",
            "http://127.0.0.1.example.com/token",
            "http://localhost/token",
        ] {
            assert!(!is_metadata_server(url, true), "{url}");
        }
        assert!(matches!(
            WorkloadTokens::new("http://10.0.0.1/token"),
            Err(BuildError::NotMetadataServer)
        ));
    }

    #[tokio::test]
    async fn an_unreachable_metadata_server_is_transient() {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let url = format!("http://{}/token", socket.local_addr().unwrap());
        let error = WorkloadTokens::new(&url)
            .unwrap()
            .token()
            .await
            .unwrap_err();
        assert_eq!(
            (error.why, error.transient),
            ("metadata server unreachable", true)
        );
        drop(socket);
    }
}
