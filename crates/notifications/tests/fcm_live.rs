// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use notifications::{FcmConfig, FcmProvider, PushProvider, PushRequest};

#[tokio::test]
#[ignore = "hits Google's live FCM servers; needs FCM_SERVICE_ACCOUNT_JSON, or FCM_PROJECT_ID on Google Cloud"]
async fn fcm_auth_and_connectivity_smoke() {
    let Some(config) = FcmConfig::from_env().expect("valid FCM config") else {
        eprintln!(
            "neither FCM_SERVICE_ACCOUNT_JSON nor FCM_PROJECT_ID configured; skipping live smoke"
        );
        return;
    };
    let project = config.project_id.clone();
    let provider = FcmProvider::new(config).expect("build FCM provider");

    let request = PushRequest {
        device_token: "fake-device-token-not-a-real-fcm-registration-token".to_string(),
        push_id: "5d41402abc4b2a76b9719d911017c592".to_string(),
        message: "0xdeadbeef".to_string(),
        topic: None,
        voip: None,
    };

    let outcome = provider
        .send(&request)
        .await
        .unwrap_or_else(|error| panic!("FCM request failed before a token verdict: {error}"));

    if outcome.success {
        eprintln!("FCM accepted the push (unexpected for a dummy token, but auth is valid)");
        return;
    }

    let error = outcome
        .errors
        .as_ref()
        .and_then(|errors| errors.first())
        .expect("a failure should carry an error");
    let http = error
        .status
        .as_ref()
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let fcm_status = error
        .response
        .as_ref()
        .and_then(|value| value.get("status"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<none>");
    eprintln!(
        "FCM project={project} http={http} status={fcm_status} — token exchange + credentials accepted, token rejected as expected"
    );

    assert!(
        http != 401 && http != 403 && !matches!(fcm_status, "PERMISSION_DENIED" | "UNAUTHENTICATED"),
        "FCM rejected the credentials (http={http}, status={fcm_status}); check the service-account key, project, and that the FCM API is enabled"
    );
}
