// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Cloudflare Realtime TURN credential issuance.
//!
//! Cloudflare mints both halves of a TURN credential, so — unlike the coturn
//! REST-API construction this replaced — there is no shared secret and nothing
//! to compute locally. Every `/issue` call fetches a fresh credential, which is
//! what keeps callers mutually unlinkable: Cloudflare hands each one its own
//! opaque username rather than everyone sharing one.
//!
//! The cost of that is an upstream on the hot path, so the last successful
//! response is kept in memory and served if Cloudflare is unreachable. A cached
//! credential has a fixed expiry, so it is served only while enough of its life
//! remains to be worth having, and the `ttl` reported to the caller is the
//! remaining life rather than the configured one.
//!
//! `paritytech/devhost` (`crates/host-core/src/turn.rs`) calls the same API,
//! but as a single consumer: it refreshes one long-lived credential in the
//! background and shares it process-wide. An issuer cannot do that without
//! collapsing every caller onto one username, so the only thing borrowed here
//! is its failure backoff — see [`Breaker`].

use std::sync::{Mutex, RwLock};
use std::time::Duration;

const DEFAULT_BASE_URL: &str = "https://rtc.live.cloudflare.com/v1";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

const MIN_USEFUL_REMAINING: u64 = 60;

const FAILURE_THRESHOLD: u32 = 3;

const FAILURE_COOLDOWN: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum CloudflareError {
    /// The request never produced a usable response.
    /// Retryable, and the trigger for falling back to cache.
    #[error("cloudflare request failed: {0}")]
    Unreachable(String),
    #[error("cloudflare rejected the request: {0}")]
    Rejected(String),
    /// A 2xx whose body was not the documented shape.
    #[error("cloudflare response malformed: {0}")]
    Malformed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IceCredentials {
    pub servers: Vec<String>,
    pub username: String,
    pub password: String,
    /// Unix seconds at which this credential stops working.
    pub expires_at: u64,
}

impl IceCredentials {
    pub fn remaining(&self, now: u64) -> u64 {
        self.expires_at.saturating_sub(now)
    }
}

/// Consecutive-failure tracker.
#[derive(Debug, Default)]
struct Breaker {
    consecutive_failures: u32,
    /// Unix seconds before which upstream attempts are skipped.
    skip_until: u64,
}

pub struct Client {
    http: reqwest::Client,
    key_id: String,
    api_token: String,
    base_url: String,
    ttl_secs: u64,
    /// Minimum life a cached credential must have left to be served.
    min_useful_remaining: u64,
    /// Last successful response, served when Cloudflare is unreachable.
    last_good: RwLock<Option<IceCredentials>>,
    breaker: Mutex<Breaker>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("key_id", &self.key_id)
            .field("api_token", &"<redacted>")
            .field("base_url", &self.base_url)
            .field("ttl_secs", &self.ttl_secs)
            .finish()
    }
}

impl Client {
    pub fn new(
        key_id: String,
        api_token: String,
        ttl_secs: u64,
        base_url: Option<String>,
    ) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|err| format!("building HTTP client: {err}"))?;
        Ok(Self {
            http,
            key_id,
            api_token,
            base_url: base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
            ttl_secs,
            min_useful_remaining: min_useful_remaining(ttl_secs),
            last_good: RwLock::new(None),
            breaker: Mutex::new(Breaker::default()),
        })
    }

    /// Fetch a fresh credential
    pub async fn issue(&self, now: u64) -> Result<IceCredentials, CloudflareError> {
        if self.in_cooldown(now) {
            if let Some(cached) = self.cached(now) {
                tracing::debug!(
                    remaining_secs = cached.remaining(now),
                    "cloudflare in failure cooldown; serving cached TURN credential"
                );
                return Ok(cached);
            }
        }

        match self.fetch(now).await {
            Ok(fresh) => {
                self.store(&fresh);
                self.record_success();
                Ok(fresh)
            }
            Err(err @ CloudflareError::Rejected(_)) => {
                tracing::error!(error = %err, "cloudflare rejected TURN issuance");
                Err(err)
            }
            Err(err) => {
                let tripped = self.record_failure(now);
                match self.cached(now) {
                    Some(cached) => {
                        tracing::warn!(
                            error = %err,
                            tripped,
                            remaining_secs = cached.remaining(now),
                            "cloudflare unreachable; serving cached TURN credential"
                        );
                        Ok(cached)
                    }
                    None => {
                        tracing::error!(
                            error = %err,
                            "cloudflare unreachable and no usable cache"
                        );
                        Err(err)
                    }
                }
            }
        }
    }

    fn cached(&self, now: u64) -> Option<IceCredentials> {
        let guard = self.last_good.read().ok()?;
        guard
            .as_ref()
            .filter(|cached| cached.remaining(now) >= self.min_useful_remaining)
            .cloned()
    }

    fn store(&self, credentials: &IceCredentials) {
        if let Ok(mut guard) = self.last_good.write() {
            *guard = Some(credentials.clone());
        }
    }

    fn in_cooldown(&self, now: u64) -> bool {
        self.breaker
            .lock()
            .map(|breaker| now < breaker.skip_until)
            .unwrap_or(false)
    }

    fn record_success(&self) {
        if let Ok(mut breaker) = self.breaker.lock() {
            *breaker = Breaker::default();
        }
    }

    fn record_failure(&self, now: u64) -> bool {
        let Ok(mut breaker) = self.breaker.lock() else {
            return false;
        };
        breaker.consecutive_failures = breaker.consecutive_failures.saturating_add(1);
        if breaker.consecutive_failures >= FAILURE_THRESHOLD {
            breaker.skip_until = now + FAILURE_COOLDOWN;
            true
        } else {
            false
        }
    }

    async fn fetch(&self, now: u64) -> Result<IceCredentials, CloudflareError> {
        let url = format!(
            "{}/turn/keys/{}/credentials/generate-ice-servers",
            self.base_url, self.key_id
        );
        let response = self
            .http
            .post(&url)
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({ "ttl": self.ttl_secs }))
            .send()
            .await
            .map_err(|err| CloudflareError::Unreachable(err.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let message = format!("status {status}");
            // 408 and 429 are the two 4xx that say "later", not "never".
            return Err(
                if status.is_client_error()
                    && !matches!(
                        status,
                        reqwest::StatusCode::REQUEST_TIMEOUT
                            | reqwest::StatusCode::TOO_MANY_REQUESTS
                    )
                {
                    CloudflareError::Rejected(message)
                } else {
                    CloudflareError::Unreachable(message)
                },
            );
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|err| CloudflareError::Malformed(err.to_string()))?;

        parse_response(&body, now, self.ttl_secs).map_err(CloudflareError::Malformed)
    }
}

fn min_useful_remaining(ttl_secs: u64) -> u64 {
    MIN_USEFUL_REMAINING.min((ttl_secs / 4).max(1))
}

fn parse_response(
    body: &serde_json::Value,
    now: u64,
    requested_ttl: u64,
) -> Result<IceCredentials, String> {
    let entries = match body.get("iceServers") {
        Some(serde_json::Value::Array(entries)) => entries,
        Some(_) => return Err("iceServers is not an array".to_string()),
        None => return Err("response has no iceServers".to_string()),
    };

    let mut servers: Vec<String> = Vec::new();
    let mut credential: Option<(String, String)> = None;
    for entry in entries {
        for url in entry_urls(entry) {
            if !servers.contains(&url) {
                servers.push(url);
            }
        }
        if credential.is_none() {
            if let (Some(username), Some(password)) = (
                entry.get("username").and_then(serde_json::Value::as_str),
                entry.get("credential").and_then(serde_json::Value::as_str),
            ) {
                credential = Some((username.to_string(), password.to_string()));
            }
        }
    }

    if servers.is_empty() {
        return Err("iceServers carried no URLs".to_string());
    }
    let (username, password) = credential.ok_or("iceServers carried no TURN credential")?;

    let ttl = body
        .get("ttl")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(requested_ttl);

    Ok(IceCredentials {
        servers,
        username,
        password,
        expires_at: now + ttl,
    })
}

fn entry_urls(entry: &serde_json::Value) -> Vec<String> {
    match entry.get("urls") {
        Some(serde_json::Value::String(url)) => vec![url.clone()],
        Some(serde_json::Value::Array(urls)) => urls
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn cloudflare_body() -> serde_json::Value {
        json!({
            "iceServers": [
                { "urls": ["stun:stun.cloudflare.com:3478"] },
                {
                    "urls": [
                        "turn:turn.cloudflare.com:3478?transport=udp",
                        "turn:turn.cloudflare.com:3478?transport=tcp",
                        "turns:turn.cloudflare.com:5349?transport=tcp"
                    ],
                    "username": "cf-user",
                    "credential": "cf-secret"
                }
            ]
        })
    }

    #[test]
    fn flattens_every_url_in_response_order_and_takes_the_credential() {
        let credentials = parse_response(&cloudflare_body(), 1_000, 86_400).expect("parses");
        assert_eq!(
            credentials.servers,
            vec![
                "stun:stun.cloudflare.com:3478",
                "turn:turn.cloudflare.com:3478?transport=udp",
                "turn:turn.cloudflare.com:3478?transport=tcp",
                "turns:turn.cloudflare.com:5349?transport=tcp",
            ]
        );
        assert_eq!(credentials.username, "cf-user");
        assert_eq!(credentials.password, "cf-secret");
    }

    #[test]
    fn urls_may_be_a_bare_string() {
        let body = json!({
            "iceServers": [{
                "urls": "turn:turn.cloudflare.com:3478?transport=udp",
                "username": "u",
                "credential": "p"
            }]
        });
        let credentials = parse_response(&body, 0, 60).expect("parses");
        assert_eq!(
            credentials.servers,
            vec!["turn:turn.cloudflare.com:3478?transport=udp"]
        );
    }

    #[test]
    fn repeated_urls_across_entries_are_listed_once() {
        let body = json!({
            "iceServers": [
                { "urls": ["stun:stun.cloudflare.com:3478"] },
                {
                    "urls": ["stun:stun.cloudflare.com:3478", "turn:turn.cloudflare.com:3478"],
                    "username": "u",
                    "credential": "p"
                }
            ]
        });
        let credentials = parse_response(&body, 0, 60).expect("parses");
        assert_eq!(
            credentials.servers,
            vec![
                "stun:stun.cloudflare.com:3478",
                "turn:turn.cloudflare.com:3478"
            ]
        );
    }

    #[test]
    fn expiry_prefers_the_granted_ttl_over_the_requested_one() {
        let mut body = cloudflare_body();
        body["ttl"] = json!(3_600);
        assert_eq!(
            parse_response(&body, 1_000, 86_400)
                .expect("parses")
                .expires_at,
            4_600
        );
        // Absent `ttl`: fall back to what we asked for.
        assert_eq!(
            parse_response(&cloudflare_body(), 1_000, 86_400)
                .expect("parses")
                .expires_at,
            87_400
        );
    }

    #[test]
    fn rejects_bodies_that_cannot_relay() {
        // No iceServers at all.
        assert!(parse_response(&json!({}), 0, 60).is_err());
        // Not an array: the documented shape is the only one accepted.
        assert!(parse_response(&json!({ "iceServers": "nope" }), 0, 60).is_err());
        let object = json!({ "iceServers": { "urls": ["turn:t:3478"], "username": "u",
                                             "credential": "p" } });
        assert!(parse_response(&object, 0, 60).is_err());
        // Present but empty.
        assert!(parse_response(&json!({ "iceServers": [] }), 0, 60).is_err());
        // Entries with no urls.
        assert!(parse_response(&json!({ "iceServers": [{ "username": "u" }] }), 0, 60).is_err());
        // STUN only: a successful call with nothing to relay through.
        let stun_only = json!({ "iceServers": [{ "urls": ["stun:stun.cloudflare.com:3478"] }] });
        assert!(parse_response(&stun_only, 0, 60).is_err());
        // A username with no credential is not half a credential.
        let half = json!({ "iceServers": [{ "urls": ["turn:t:3478"], "username": "u" }] });
        assert!(parse_response(&half, 0, 60).is_err());
    }

    #[test]
    fn remaining_life_saturates_at_zero() {
        let credentials = parse_response(&cloudflare_body(), 1_000, 100).expect("parses");
        assert_eq!(credentials.remaining(1_000), 100);
        assert_eq!(credentials.remaining(1_050), 50);
        assert_eq!(credentials.remaining(9_999), 0);
    }

    const SECRET: &str = "cf-api-token-do-not-log";

    fn client() -> Client {
        Client::new("key".to_string(), SECRET.to_string(), 3_600, None).expect("builds")
    }

    #[test]
    fn the_cache_serves_only_while_useful_life_remains() {
        let client = client();
        let credentials = parse_response(&cloudflare_body(), 1_000, 3_600).expect("parses");
        client.store(&credentials);

        assert_eq!(client.cached(1_000), Some(credentials.clone()));
        // Exactly at the floor: still worth serving.
        assert!(client
            .cached(credentials.expires_at - MIN_USEFUL_REMAINING)
            .is_some());
        // A second past it: too short to negotiate with.
        assert!(client
            .cached(credentials.expires_at - MIN_USEFUL_REMAINING + 1)
            .is_none());
        assert!(client.cached(credentials.expires_at + 1).is_none());
    }

    #[test]
    fn a_short_ttl_still_has_a_usable_cache() {
        let client = Client::new("key".to_string(), SECRET.to_string(), 40, None).expect("builds");
        assert_eq!(client.min_useful_remaining, 10);
        let credentials = parse_response(&cloudflare_body(), 1_000, 40).expect("parses");
        client.store(&credentials);
        assert!(client.cached(1_000).is_some());
        assert!(client.cached(credentials.expires_at - 10).is_some());
        assert!(client.cached(credentials.expires_at - 9).is_none());
    }

    #[test]
    fn the_floor_never_reaches_the_ttl_it_is_measured_against() {
        for ttl in [1_u64, 2, 3, 4, 59, 60, 240, 241, 3_600] {
            let floor = min_useful_remaining(ttl);
            assert!(floor >= 1, "ttl {ttl}");
            assert!(floor <= ttl, "ttl {ttl}");
            assert!(floor <= MIN_USEFUL_REMAINING, "ttl {ttl}");
        }
        assert_eq!(min_useful_remaining(3_600), MIN_USEFUL_REMAINING);
    }

    #[test]
    fn a_client_error_is_not_retryable_and_a_server_error_is() {
        let classify = |status: reqwest::StatusCode| {
            status.is_client_error()
                && !matches!(
                    status,
                    reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::TOO_MANY_REQUESTS
                )
        };
        assert!(classify(reqwest::StatusCode::UNAUTHORIZED));
        assert!(classify(reqwest::StatusCode::FORBIDDEN));
        assert!(classify(reqwest::StatusCode::NOT_FOUND));
        assert!(!classify(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(!classify(reqwest::StatusCode::REQUEST_TIMEOUT));
        assert!(!classify(reqwest::StatusCode::BAD_GATEWAY));
    }

    #[test]
    fn an_empty_cache_yields_nothing() {
        assert!(client().cached(1_000).is_none());
    }

    #[test]
    fn the_cooldown_trips_only_on_the_threshold_failure() {
        let client = client();
        for attempt in 1..FAILURE_THRESHOLD {
            assert!(!client.record_failure(1_000), "attempt {attempt}");
            assert!(!client.in_cooldown(1_000), "attempt {attempt}");
        }
        assert!(client.record_failure(1_000));
        assert!(client.in_cooldown(1_000));
    }

    #[test]
    fn the_cooldown_lapses_and_lets_one_request_through() {
        let client = client();
        for _ in 0..FAILURE_THRESHOLD {
            client.record_failure(1_000);
        }
        assert!(client.in_cooldown(1_000 + FAILURE_COOLDOWN - 1));
        assert!(!client.in_cooldown(1_000 + FAILURE_COOLDOWN));
    }

    #[test]
    fn a_success_clears_the_failure_run() {
        let client = client();
        for _ in 0..FAILURE_THRESHOLD {
            client.record_failure(1_000);
        }
        assert!(client.in_cooldown(1_000));

        client.record_success();
        assert!(!client.in_cooldown(1_000));
        // The run restarts from zero: one failure must not re-trip it.
        assert!(!client.record_failure(1_000));
    }

    #[tokio::test]
    async fn a_cooldown_with_no_cache_still_attempts_upstream() {
        // Nothing to skip to, so `issue` must try rather than fail blind. The
        // base URL is unroutable, so the attempt fails and surfaces the error.
        let client = Client::new(
            "key".to_string(),
            SECRET.to_string(),
            3_600,
            Some("http://127.0.0.1:1/v1".to_string()),
        )
        .expect("builds");
        for _ in 0..FAILURE_THRESHOLD {
            client.record_failure(1_000);
        }
        assert!(client.in_cooldown(1_000));
        assert!(client.issue(1_000).await.is_err());
    }

    #[test]
    fn the_api_token_stays_out_of_debug_output() {
        let rendered = format!("{:?}", client());
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }
}
