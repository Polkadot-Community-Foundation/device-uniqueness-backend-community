// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! What `/api/v1/turn/issue` does when Cloudflare misbehaves.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
use turn::{AppState, Config};

const JWT_SEED: [u8; 32] = [3u8; 32];
const ACCOUNT: &str = "0x1a2b3c4d5e6f70818293a4b5c6d7e8f9000102030405060708090a0b0c0d0e0f";
const GRANTED_TTL: u64 = 1800;

/// A Cloudflare stand-in whose health can be flipped mid-test, counting every
/// request it receives so a test can prove the client stopped calling.
struct Stub {
    base_url: String,
    healthy: Arc<AtomicBool>,
    hits: Arc<AtomicUsize>,
}

impl Stub {
    fn fail(&self) {
        self.healthy.store(false, Ordering::SeqCst);
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

fn spawn_stub(healthy: bool) -> Stub {
    #[derive(Clone)]
    struct State {
        healthy: Arc<AtomicBool>,
        hits: Arc<AtomicUsize>,
    }

    let state = State {
        healthy: Arc::new(AtomicBool::new(healthy)),
        hits: Arc::new(AtomicUsize::new(0)),
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
    listener.set_nonblocking(true).expect("nonblocking");
    let base_url = format!("http://{}", listener.local_addr().expect("stub addr"));
    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");

    let router = axum::Router::new()
        .route(
            "/turn/keys/{key_id}/credentials/generate-ice-servers",
            axum::routing::post(
                |axum::extract::State(state): axum::extract::State<State>| async move {
                    state.hits.fetch_add(1, Ordering::SeqCst);
                    if !state.healthy.load(Ordering::SeqCst) {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    axum::Json(serde_json::json!({
                        "iceServers": [
                            { "urls": ["stun:stun.cloudflare.com:3478"] },
                            {
                                "urls": ["turn:turn.cloudflare.com:3478?transport=udp"],
                                "username": "stub-username",
                                "credential": "stub-credential"
                            }
                        ],
                        "ttl": GRANTED_TTL
                    }))
                    .into_response()
                },
            ),
        )
        .with_state(state.clone());

    tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });

    Stub {
        base_url,
        healthy: state.healthy,
        hits: state.hits,
    }
}

use axum::response::IntoResponse as _;

fn app(stub: &Stub) -> axum::Router {
    let jwt = jwt_verify::Jwt::new(&JWT_SEED, "test-issuer".to_string());
    turn::routes(AppState::new(Config {
        bind_addr: "127.0.0.1:0".parse().expect("valid addr"),
        ttl_secs: GRANTED_TTL,
        provider: turn::config::ProviderConfig::Cloudflare {
            key_id: "test-key-id".to_string(),
            api_token: "test-api-token".to_string(),
            base_url: Some(stub.base_url.clone()),
        },
        jwt_verifier: jwt.verifier().clone(),
        // High enough that the rate limiter never masks what is being tested.
        rate_limit: 1_000,
        rate_window: Duration::from_secs(60),
        proof: None,
    }))
}

fn token() -> String {
    jwt_verify::Jwt::new(&JWT_SEED, "test-issuer".to_string()).issue(
        ACCOUNT,
        true,
        None,
        Duration::from_secs(3_600),
    )
}

async fn issue(app: &axum::Router) -> (StatusCode, Option<String>, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/turn/issue")
        .header("authorization", format!("Bearer {}", token()))
        .body(Body::empty())
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, retry_after, json)
}

#[tokio::test]
async fn a_dead_upstream_with_no_cache_is_a_503_with_retry_after() {
    let stub = spawn_stub(false);
    let app = app(&stub);

    let (status, retry_after, json) = issue(&app).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
    assert_eq!(retry_after.as_deref(), Some("5"));
    // The caller learns nothing about the upstream.
    assert_eq!(
        json["error"],
        serde_json::json!("Credentials are temporarily unavailable.")
    );
    assert!(json.get("username").is_none(), "{json}");
    assert!(stub.hits() >= 1, "the request should have been attempted");
}

#[tokio::test]
async fn a_warm_cache_is_served_when_the_upstream_dies() {
    let stub = spawn_stub(true);
    let app = app(&stub);

    let (status, _, fresh) = issue(&app).await;
    assert_eq!(status, StatusCode::CREATED, "{fresh}");
    assert_eq!(fresh["ttl"], serde_json::json!(GRANTED_TTL));

    stub.fail();

    let (status, retry_after, cached) = issue(&app).await;
    assert_eq!(status, StatusCode::CREATED, "{cached}");
    assert_eq!(retry_after, None, "a served credential is not a retry");
    // Same credential, because it is literally the previous response.
    assert_eq!(cached["username"], fresh["username"]);
    assert_eq!(cached["password"], fresh["password"]);
    assert_eq!(cached["servers"], fresh["servers"]);
    // Its life is the life it had left, never more than the granted TTL.
    let ttl = cached["ttl"].as_u64().expect("ttl");
    assert!(ttl <= GRANTED_TTL, "cached ttl {ttl} exceeds granted");
}

#[tokio::test]
async fn a_dead_upstream_stops_being_called_once_the_cooldown_trips() {
    let stub = spawn_stub(true);
    let app = app(&stub);

    // Warm the cache, then take the upstream away.
    let (status, _, _) = issue(&app).await;
    assert_eq!(status, StatusCode::CREATED);
    stub.fail();

    for _ in 0..12 {
        let (status, _, json) = issue(&app).await;
        assert_eq!(status, StatusCode::CREATED, "{json}");
    }
    let after_first_burst = stub.hits();

    for _ in 0..12 {
        let (status, _, json) = issue(&app).await;
        assert_eq!(status, StatusCode::CREATED, "{json}");
    }
    assert_eq!(
        stub.hits(),
        after_first_burst,
        "the client kept calling a dead upstream"
    );
    assert_eq!(
        after_first_burst, 4,
        "expected one warm call plus the failure budget"
    );
}
