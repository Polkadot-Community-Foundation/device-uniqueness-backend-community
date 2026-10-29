// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! The `TURN_PROVIDER=coturn` path: credentials computed here, from a secret
//! shared with a relay the operator runs.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
use turn::config::ProviderConfig;
use turn::credentials::{Algorithm, Issuer};
use turn::{AppState, Config};

const JWT_SEED: [u8; 32] = [3u8; 32];
const ACCOUNT: &str = "0x1a2b3c4d5e6f70818293a4b5c6d7e8f9000102030405060708090a0b0c0d0e0f";
const SECRET: &[u8] = b"relay-shared-secret";
const TTL: u64 = 1800;
const RELAY_SERVERS: [&str; 2] = [
    "stun:stun.example.org:3478",
    "turn:turn.example.org:3478?transport=udp",
];

fn app(algorithm: Algorithm) -> axum::Router {
    let jwt = jwt_verify::Jwt::new(&JWT_SEED, "test-issuer".to_string());
    turn::routes(AppState::new(Config {
        bind_addr: "127.0.0.1:0".parse().expect("valid addr"),
        ttl_secs: TTL,
        provider: ProviderConfig::Coturn {
            secret: SECRET.to_vec(),
            algorithm,
            realm: "example.org".to_string(),
            ice_servers: RELAY_SERVERS.iter().map(|s| s.to_string()).collect(),
        },
        jwt_verifier: jwt.verifier().clone(),
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

async fn issue(app: &axum::Router) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/turn/issue")
        .header("authorization", format!("Bearer {}", token()))
        .body(Body::empty())
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

#[tokio::test]
async fn the_username_is_the_relay_rest_api_form() {
    let (status, json) = issue(&app(Algorithm::Sha1)).await;
    assert_eq!(status, StatusCode::CREATED, "{json}");

    let username = json["username"].as_str().expect("username");
    let (expiry, id) = username.split_once(':').expect("expiry:id");
    // The relay reads the expiry out of the username, so it must be the real
    // one: issuance time plus the configured TTL, not a rounded or fixed value.
    let expiry: u64 = expiry.parse().expect("numeric expiry");
    let expected = now_unix() + TTL;
    assert!(
        expiry.abs_diff(expected) <= 2,
        "expiry {expiry} is not now+{TTL} ({expected})"
    );
    // Eight random bytes, lowercase hex.
    assert_eq!(id.len(), 16, "id half: {id}");
    assert!(id
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
}

#[tokio::test]
async fn the_password_is_the_hmac_the_relay_will_recompute() {
    for algorithm in [
        Algorithm::Sha1,
        Algorithm::Sha256,
        Algorithm::Sha384,
        Algorithm::Sha512,
    ] {
        let (status, json) = issue(&app(algorithm)).await;
        assert_eq!(status, StatusCode::CREATED, "{algorithm:?}: {json}");

        let username = json["username"].as_str().expect("username");
        let expected = Issuer::new(SECRET.to_vec(), algorithm, TTL).password_for(username);
        assert_eq!(
            json["password"].as_str().expect("password"),
            expected,
            "{algorithm:?} password is not the HMAC over the username"
        );
    }
}

#[tokio::test]
async fn the_configured_ice_servers_are_echoed_verbatim() {
    let (_, json) = issue(&app(Algorithm::Sha1)).await;
    assert_eq!(json["servers"], serde_json::json!(RELAY_SERVERS));
}

#[tokio::test]
async fn the_ttl_is_the_configured_one_because_credentials_are_minted_to_order() {
    let (_, json) = issue(&app(Algorithm::Sha1)).await;
    assert_eq!(json["ttl"], serde_json::json!(TTL));
}

#[tokio::test]
async fn every_request_gets_its_own_random_id() {
    let app = app(Algorithm::Sha1);
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..8 {
        let (status, json) = issue(&app).await;
        assert_eq!(status, StatusCode::CREATED, "{json}");
        let username = json["username"].as_str().expect("username").to_string();
        let id = username.split_once(':').expect("expiry:id").1.to_string();
        assert!(ids.insert(id), "an id repeated: {username}");
    }
}

#[tokio::test]
async fn issuance_needs_no_network() {
    let (status, json) = issue(&app(Algorithm::Sha1)).await;
    assert_eq!(status, StatusCode::CREATED, "{json}");
    assert!(json["password"].as_str().is_some());
}
