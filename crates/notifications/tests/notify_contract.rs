// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use http_common::rate_limiter;
use serde_json::{json, Value};

use notifications::{
    routes, AppState, ProviderError, PushOutcome, PushProvider, RateLimiter, RecordingProvider,
    Verifier,
};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

const IOS_TOKEN: &str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const FCM_TOKEN: &str = "cnynQ0YWTKKe62TJmpG0RU:APA91bHgMg0yBE2DzIKlQeQY8oILclw3qBA7EQDaeFTPdiMxFgHdBGRwn8bbNex-LbPvraRs-8KZMO_D0hu2utYtyRV3U1xNefgi7Q_TYL4442wiBfYRtFo";
const PUSH_ID: &str = "5d41402abc4b2a76b9719d911017c592";
const MESSAGE: &str = "1234567890abcdef";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn mint(signing: &SigningKey) -> String {
    let exp = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;
    let header = B64.encode(json!({ "alg": "EdDSA", "typ": "JWT" }).to_string());
    let payload = B64.encode(json!({ "accountId": "0xabc", "exp": exp }).to_string());
    let signing_input = format!("{header}.{payload}");
    let sig = signing.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
}

async fn spawn(apns: Arc<dyn PushProvider>, fcm: Arc<dyn PushProvider>) -> String {
    spawn_limited(apns, fcm, 1000).await
}

async fn spawn_limited(
    apns: Arc<dyn PushProvider>,
    fcm: Arc<dyn PushProvider>,
    limit: u32,
) -> String {
    let verifier = Verifier::from_public_key(None, signing_key().verifying_key().as_bytes());
    let limiter = RateLimiter::new(rate_limiter::Config::default().set_max_burst(limit))
        .expect("rate limiter config validated during startup");
    let state = AppState::new(verifier, apns, fcm, limiter);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, routes(state)).await.unwrap();
    });
    format!("http://{addr}")
}

fn ios_success() -> Arc<RecordingProvider> {
    Arc::new(RecordingProvider::new(Ok(PushOutcome {
        success: true,
        sent: Some(1),
        failed: Some(0),
        ..PushOutcome::default()
    })))
}

fn android_success() -> Arc<RecordingProvider> {
    Arc::new(RecordingProvider::new(Ok(PushOutcome {
        success: true,
        message_id: Some("mock-message-id".to_string()),
        ..PushOutcome::default()
    })))
}

#[tokio::test]
async fn rejects_requests_without_a_bearer_token() {
    let base = spawn(ios_success(), android_success()).await;
    let res = reqwest::Client::new()
        .post(format!("{base}/api/v1/notify"))
        .json(&json!({ "deviceToken": IOS_TOKEN, "pushId": PUSH_ID, "message": MESSAGE }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    assert_eq!(res.headers()["content-type"], "application/json");
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["error"],
        "Missing Authorization header. Include a valid Bearer token."
    );
}

#[tokio::test]
async fn rejects_invalid_bodies_with_field_errors() {
    let base = spawn(ios_success(), android_success()).await;
    let res = reqwest::Client::new()
        .post(format!("{base}/api/v1/notify"))
        .bearer_auth(mint(&signing_key()))
        .json(&json!({ "deviceToken": IOS_TOKEN, "pushId": PUSH_ID }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_eq!(res.headers()["content-type"], "application/json");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "The request body contains invalid values.");
    assert_eq!(body["fields"][0]["field"], "message");
    assert_eq!(
        body["fields"][0]["message"],
        "expected string, received nothing"
    );
}

#[tokio::test]
async fn delivers_ios_and_forwards_the_flat_payload() {
    let apns = ios_success();
    let base = spawn(apns.clone(), android_success()).await;
    let res = reqwest::Client::new()
        .post(format!("{base}/api/v1/notify"))
        .bearer_auth(mint(&signing_key()))
        .json(&json!({
            "deviceToken": IOS_TOKEN, "pushId": PUSH_ID, "message": MESSAGE, "voip": true,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["platform"], "ios");
    assert_eq!(body["sent"], 1);

    let forwarded = apns.last_request().expect("apns received the payload");
    assert_eq!(forwarded.device_token, IOS_TOKEN);
    assert_eq!(forwarded.push_id, PUSH_ID);
    assert_eq!(forwarded.message, MESSAGE);
    assert_eq!(forwarded.voip, Some(true));
}

#[tokio::test]
async fn delivers_android_from_an_fcm_token() {
    let fcm = android_success();
    let base = spawn(ios_success(), fcm.clone()).await;
    let res = reqwest::Client::new()
        .post(format!("{base}/api/v1/notify"))
        .bearer_auth(mint(&signing_key()))
        .json(&json!({ "deviceToken": FCM_TOKEN, "pushId": PUSH_ID, "message": MESSAGE }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["platform"], "android");
    assert_eq!(body["messageId"], "mock-message-id");
    assert_eq!(fcm.last_request().unwrap().device_token, FCM_TOKEN);
}

#[tokio::test]
async fn explicit_platform_hint_overrides_token_detection() {
    let fcm = android_success();
    let base = spawn(ios_success(), fcm.clone()).await;
    let res = reqwest::Client::new()
        .post(format!("{base}/api/v1/notify"))
        .bearer_auth(mint(&signing_key()))
        .json(&json!({
            "deviceToken": IOS_TOKEN, "pushId": PUSH_ID, "message": MESSAGE, "platform": "android",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["platform"], "android");
    assert!(
        fcm.last_request().is_some(),
        "android provider was selected by hint"
    );
}

#[tokio::test]
async fn provider_failure_stays_200_with_success_false() {
    let apns = Arc::new(RecordingProvider::new(Err(ProviderError::Delivery(
        "Network error".to_string(),
    ))));
    let base = spawn(apns, android_success()).await;
    let res = reqwest::Client::new()
        .post(format!("{base}/api/v1/notify"))
        .bearer_auth(mint(&signing_key()))
        .json(&json!({ "deviceToken": IOS_TOKEN, "pushId": PUSH_ID, "message": MESSAGE }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["success"], false);
    assert_eq!(body["errors"][0]["device"], IOS_TOKEN);
    assert_eq!(body["errors"][0]["response"], "Network error");
}

#[tokio::test]
async fn rate_limits_the_authenticated_subject_with_429() {
    let base = spawn_limited(ios_success(), android_success(), 1).await;
    let client = reqwest::Client::new();
    let send = || {
        client
            .post(format!("{base}/api/v1/notify"))
            .bearer_auth(mint(&signing_key()))
            .json(&json!({ "deviceToken": IOS_TOKEN, "pushId": PUSH_ID, "message": MESSAGE }))
            .send()
    };

    assert_eq!(send().await.unwrap().status(), 200);
    let limited = send().await.unwrap();
    assert_eq!(limited.status(), 429);
    assert_eq!(limited.headers()["content-type"], "application/json");
    assert!(limited.headers().contains_key("retry-after"));
    let body: Value = limited.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.starts_with("Rate limit exceeded.")),
        "{body}"
    );
}

#[tokio::test]
async fn malformed_json_is_a_json_400() {
    let base = spawn(ios_success(), android_success()).await;
    let res = reqwest::Client::new()
        .post(format!("{base}/api/v1/notify"))
        .bearer_auth(mint(&signing_key()))
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_eq!(res.headers()["content-type"], "application/json");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "Malformed JSON in request body");
}

#[tokio::test]
async fn readiness_needs_no_external_dependency() {
    let base = spawn(ios_success(), android_success()).await;
    let res = reqwest::get(format!("{base}/readyz")).await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["status"], "ready");
    assert_eq!(body["service"], "notifications");
}
