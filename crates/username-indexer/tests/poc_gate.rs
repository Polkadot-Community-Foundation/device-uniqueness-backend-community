// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use http_body_util::BodyExt as _;
use http_common::{rate_limiter, RateLimiter};
use tower::ServiceExt as _;
use username_indexer::poc::puzzle::{checksum_hex, derive_secret};
use username_indexer::poc::solution::{leading_zero_bits, mine};
use username_indexer::poc::{now_millis, Poc, Solution};
use username_indexer::{AppState, Freshness, PeopleChain};
use uuid::Uuid;

const IKM: &str = "test-poc-ikm";
const DIFFICULTY: u8 = 8;
const VALIDITY_WINDOW_SECS: i64 = 90;
const JWT_SEED: [u8; 32] = [7u8; 32];
const SUBJECT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

async fn dead_chain_client() -> PeopleChain {
    use subxt_rpcs::client::mock_rpc_client::Json;
    use subxt_rpcs::client::{MockRpcClient, RpcClient};

    let mock = MockRpcClient::builder()
        .method_handler("chain_getBlockHash", |_params| async {
            Json(serde_json::json!(format!("0x{}", "00".repeat(32))))
        })
        .build();
    let rpc = RpcClient::new(mock);
    let backend = subxt::backend::LegacyBackend::builder().build(rpc.clone());
    let client = subxt::OnlineClient::<chain_types::PeopleConfig>::from_backend(Arc::new(backend))
        .await
        .expect("offline client from mock backend");
    PeopleChain::from_parts(client, rpc)
}

async fn app(gate: bool) -> axum::Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://nobody@127.0.0.1:1/nothing")
        .expect("lazy pool");
    let state = AppState::new(
        pool,
        dead_chain_client().await,
        Freshness::new(),
        RateLimiter::new(rate_limiter::Config::default().set_max_burst(1000)).unwrap(),
    );
    let state = if gate {
        state.with_poc(Poc::new(
            derive_secret(IKM),
            DIFFICULTY,
            jwt_verify::Verifier::from_public_key(
                None,
                &SigningKey::from_bytes(&JWT_SEED).verifying_key().to_bytes(),
            ),
        ))
    } else {
        state
    };
    username_indexer::routes(state)
}

struct Observed {
    status: u16,
    content_type: Option<String>,
    body: String,
}

impl Observed {
    async fn from(response: axum::response::Response) -> Self {
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        Self {
            status,
            content_type,
            body: String::from_utf8_lossy(&body).to_string(),
        }
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).expect("json body")
    }
}

async fn search(gate: bool, headers: &[(&str, String)]) -> Observed {
    let mut request = Request::builder()
        .method("GET")
        .uri("/api/v1/usernames/search?prefix=a");
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let response = app(gate)
        .await
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    Observed::from(response).await
}

fn mint_token(exp_offset_secs: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
        + exp_offset_secs;
    let key = SigningKey::from_bytes(&JWT_SEED);
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(format!(
        r#"{{"accountId":"{SUBJECT}","sub":"{SUBJECT}","exp":{exp}}}"#
    ));
    let payload = format!("{header}.{claims}");
    let signature = URL_SAFE_NO_PAD.encode(key.sign(payload.as_bytes()).to_bytes());
    format!("{payload}.{signature}")
}

fn solved_header(timestamp_ms: i64, difficulty: u8) -> String {
    let secret = derive_secret(IKM);
    let session_id = Uuid::new_v4();
    let counter = mine(session_id, timestamp_ms, difficulty);
    Solution::new(
        session_id,
        timestamp_ms,
        difficulty,
        counter,
        checksum_hex(&secret, session_id, timestamp_ms, difficulty),
    )
    .to_header()
}

#[tokio::test]
async fn issues_a_puzzle_this_server_can_verify() {
    let response = app(true)
        .await
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/poc/issue")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let observed = Observed::from(response).await;

    assert_eq!(observed.status, 201);
    assert_eq!(
        observed.content_type.as_deref(),
        Some("application/json"),
        "issuance is plain JSON"
    );
    let body = observed.json();
    assert_eq!(body["difficulty"], serde_json::json!(DIFFICULTY));
    let session_id =
        Uuid::parse_str(body["sessionId"].as_str().expect("sessionId")).expect("uuid session id");
    let timestamp = body["timestamp"].as_i64().expect("timestamp millis");
    assert_eq!(
        body["checksum"].as_str().expect("checksum"),
        checksum_hex(&derive_secret(IKM), session_id, timestamp, DIFFICULTY),
        "the checksum must be recomputable from the configured secret"
    );
}

#[tokio::test]
async fn wrong_method_on_search_is_404_with_the_gate_on() {
    for method in ["PUT", "POST", "DELETE", "PATCH"] {
        let response = app(true)
            .await
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/api/v1/usernames/search?prefix=a")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let observed = Observed::from(response).await;
        assert_eq!(observed.status, 404, "{method} must not hit the gate");
        assert_eq!(observed.json(), serde_json::json!({ "error": "Not found" }));
    }
}

#[tokio::test]
async fn dropped_username_endpoints_are_404_with_the_gate_on() {
    for uri in ["/api/v1/usernames", "/api/v1/usernames/alice.1"] {
        let response = app(true)
            .await
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let observed = Observed::from(response).await;
        assert_eq!(observed.status, 404, "{uri} must not hit the gate");
        assert_eq!(observed.json(), serde_json::json!({ "error": "Not found" }));
    }
}

#[tokio::test]
async fn health_endpoints_are_never_gated() {
    for uri in ["/livez", "/healthcheck"] {
        let response = app(true)
            .await
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            response.status().as_u16(),
            200,
            "{uri} must stay reachable with the gate on"
        );
    }
}

#[tokio::test]
async fn issue_route_is_absent_when_the_gate_is_disabled() {
    let response = app(false)
        .await
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/poc/issue")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let observed = Observed::from(response).await;

    assert_eq!(observed.status, 404);
    assert_eq!(observed.json(), serde_json::json!({ "error": "Not found" }));
}

#[tokio::test]
async fn disabled_gate_leaves_anonymous_search_untouched() {
    let observed = search(false, &[]).await;
    assert_eq!(observed.status, 500);
    assert_eq!(
        observed.json(),
        serde_json::json!({ "error": "Internal server error. Please try again." })
    );
}

#[tokio::test]
async fn anonymous_search_without_a_proof_is_402() {
    let observed = search(true, &[]).await;
    assert_eq!(observed.status, 402);
    assert_eq!(observed.content_type.as_deref(), Some("application/json"));
    assert_eq!(
        observed.json(),
        serde_json::json!({
            "error": "Proof of compute required. Request a puzzle from POST /api/v1/poc/issue and present the solved proof in the Proof-Of-Compute header."
        })
    );
}

#[tokio::test]
async fn malformed_proof_header_is_400() {
    let observed = search(true, &[("proof-of-compute", "not base64!!".to_string())]).await;
    assert_eq!(observed.status, 400);
    assert_eq!(observed.content_type.as_deref(), Some("application/json"));
    assert_eq!(
        observed.json(),
        serde_json::json!({ "error": "The Proof-Of-Compute header is malformed." })
    );
}

#[tokio::test]
async fn foreign_checksum_is_402() {
    let session_id = Uuid::new_v4();
    let timestamp = now_millis();
    let forged = Solution::new(
        session_id,
        timestamp,
        DIFFICULTY,
        mine(session_id, timestamp, DIFFICULTY),
        checksum_hex(
            &derive_secret("some-other-server"),
            session_id,
            timestamp,
            DIFFICULTY,
        ),
    )
    .to_header();

    let observed = search(true, &[("proof-of-compute", forged)]).await;
    assert_eq!(observed.status, 402);
    assert_eq!(
        observed.json()["error"],
        serde_json::json!(
            "The proof checksum does not match; the puzzle was not issued by this server."
        )
    );
}

#[tokio::test]
async fn expired_puzzle_is_402() {
    let stale = now_millis() - (VALIDITY_WINDOW_SECS + 1) * 1_000;
    let observed = search(
        true,
        &[("proof-of-compute", solved_header(stale, DIFFICULTY))],
    )
    .await;
    assert_eq!(observed.status, 402);
    assert_eq!(
        observed.json()["error"],
        serde_json::json!("The proof of compute puzzle has expired; request a new one.")
    );
}

#[tokio::test]
async fn unsolved_puzzle_is_402() {
    let secret = derive_secret(IKM);
    let session_id = Uuid::new_v4();
    let timestamp = now_millis();
    assert!(leading_zero_bits(session_id, timestamp, 0) < 32);
    let unsolved = Solution::new(
        session_id,
        timestamp,
        32,
        0,
        checksum_hex(&secret, session_id, timestamp, 32),
    )
    .to_header();

    let observed = search(true, &[("proof-of-compute", unsolved)]).await;
    assert_eq!(observed.status, 402);
    assert_eq!(
        observed.json()["error"],
        serde_json::json!("The proof of compute solution does not meet the required difficulty.")
    );
}

#[tokio::test]
async fn valid_bearer_bypasses_the_puzzle() {
    let observed = search(
        true,
        &[("authorization", format!("Bearer {}", mint_token(3_600)))],
    )
    .await;
    assert_eq!(observed.status, 500);
    assert_eq!(
        observed.json(),
        serde_json::json!({ "error": "Internal server error. Please try again." })
    );
}

#[tokio::test]
async fn invalid_bearer_falls_through_to_the_puzzle_requirement() {
    for header in [
        "Bearer not-a-jwt".to_string(),
        format!("Bearer {}", mint_token(-3_600)),
        "Basic dXNlcjpwYXNz".to_string(),
    ] {
        let observed = search(true, &[("authorization", header.clone())]).await;
        assert_eq!(observed.status, 402, "expected 402 for {header}");
        assert_eq!(
            observed.json()["error"],
            serde_json::json!("Proof of compute required. Request a puzzle from POST /api/v1/poc/issue and present the solved proof in the Proof-Of-Compute header.")
        );
    }
}
