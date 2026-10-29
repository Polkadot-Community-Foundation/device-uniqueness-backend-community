// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;
use turn::config::{Config, ProofConfig};
use turn::AppState;

const PRODUCT: &str = "dim2.paseo";

fn app(proof: bool) -> axum::Router {
    let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    turn::routes(AppState::new(Config {
        bind_addr: "127.0.0.1:0".parse().expect("valid addr"),
        ttl_secs: 1800,
        provider: turn::config::ProviderConfig::Cloudflare {
            key_id: "test-key-id".to_string(),
            api_token: "test-api-token".to_string(),
            base_url: Some(spawn_cloudflare_stub()),
        },
        jwt_verifier: jwt_verify::Verifier::from_public_key(None, key.verifying_key().as_bytes()),
        rate_limit: 100,
        rate_window: Duration::from_secs(60),
        proof: proof.then(|| ProofConfig {
            rpc_url: "ws://unused.invalid".to_string(),
            genesis: [7u8; 32],
            contexts: [(
                PRODUCT.to_string(),
                turn::proof::context::product_context(PRODUCT, 0),
            )]
            .into_iter()
            .collect(),
            concurrency: 1,
        }),
    }))
}

async fn send(app: &axum::Router, request: Request<Body>) -> axum::http::Response<Body> {
    app.clone().oneshot(request).await.expect("response")
}

#[tokio::test]
async fn preflight_is_answered_on_the_proof_route() {
    let app = app(true);

    let response = send(
        &app,
        Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/turn/issue-with-proof")
            .header("origin", "https://dim2.example")
            .header("access-control-request-method", "POST")
            .header(
                "access-control-request-headers",
                "authorization,content-type",
            )
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let headers = response.headers();
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .expect("allow-origin"),
        "*"
    );
    assert_eq!(
        headers
            .get("access-control-allow-methods")
            .expect("allow-methods"),
        "POST,OPTIONS"
    );
    assert_eq!(
        headers
            .get("access-control-allow-headers")
            .expect("allow-headers"),
        "authorization,content-type"
    );
}

#[tokio::test]
async fn responses_carry_allow_origin_so_a_browser_can_read_them() {
    let app = app(true);

    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/turn/issue-with-proof")
            .header("origin", "https://dim2.example")
            .header("content-type", "application/json")
            .body(Body::from("{nope"))
            .expect("request"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .expect("allow-origin"),
        "*"
    );
}

#[tokio::test]
async fn the_jwt_route_stays_out_of_the_browser() {
    let app = app(true);

    let response = send(
        &app,
        Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/turn/issue")
            .header("origin", "https://dim2.example")
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());

    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/turn/issue")
            .header("origin", "https://dim2.example")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
}

#[tokio::test]
async fn the_layered_rejections_stay_readable_too() {
    let app = app(true);

    let response = send(
        &app,
        Request::builder()
            .method("GET")
            .uri("/api/v1/turn/issue-with-proof")
            .header("origin", "https://dim2.example")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .expect("allow-origin"),
        "*"
    );

    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/turn/issue-with-proof")
            .header("origin", "https://dim2.example")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"productId":"{PRODUCT}","proof":"0x{}"}}"#,
                "aa".repeat(8 * 1024)
            )))
            .expect("request"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .expect("allow-origin"),
        "*"
    );
}

#[tokio::test]
async fn the_preflight_does_not_answer_for_a_route_that_is_not_mounted() {
    let response = send(
        &app(false),
        Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/turn/issue-with-proof")
            .header("origin", "https://dim2.example")
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// A stand-in for Cloudflare Realtime TURN, bound on a loopback port.
fn spawn_cloudflare_stub() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("stub addr");
    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
    let router = axum::Router::new().route(
        "/turn/keys/{key_id}/credentials/generate-ice-servers",
        axum::routing::post(|| async {
            axum::Json(serde_json::json!({
                "iceServers": [
                    { "urls": ["stun:stun.cloudflare.com:3478"] },
                    {
                        "urls": [
                            "turn:turn.cloudflare.com:3478?transport=udp",
                            "turns:turn.cloudflare.com:5349?transport=tcp"
                        ],
                        "username": "stub-username",
                        "credential": "stub-credential"
                    }
                ],
                "ttl": 1800
            }))
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    format!("http://{addr}")
}
