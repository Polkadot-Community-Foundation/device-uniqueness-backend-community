// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use notifications::{FcmConfig, FcmProvider, PushProvider, PushRequest};

/// Text that marks a refusal of the caller rather than of the device token:
/// the FCM v1 `error.status` values for 401/403, the provider's fallback for an
/// unparseable 401/403 body, and the messages Google attaches to them.
const AUTH_ERROR_MARKERS: &[&str] = &[
    "UNAUTHENTICATED",
    "PERMISSION_DENIED",
    "(status 401)",
    "(status 403)",
    "authentication credential",
    "Permission '",
    "SenderId mismatch",
];

#[tokio::test]
#[ignore = "hits Google's live FCM servers; needs real FCM_SERVICE_ACCOUNT_JSON"]
async fn fcm_auth_and_connectivity_smoke() {
    let Some(config) = FcmConfig::from_env().expect("valid FCM config") else {
        eprintln!("FCM_SERVICE_ACCOUNT_JSON not configured; skipping live smoke");
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

    // The provider returns `Err` for every FCM rejection, so a dummy token is
    // expected to come back as an error. What matters is which stage produced
    // it: one raised before FCM gave a verdict, or FCM refusing the caller.
    let error = match provider.send(&request).await {
        Ok(_) => {
            eprintln!("FCM accepted the push (unexpected for a dummy token, but auth is valid)");
            return;
        }
        Err(error) => error.to_string(),
    };

    assert!(
        !error.starts_with("fcm "),
        "FCM request failed before a token verdict: {error}"
    );
    assert!(
        !AUTH_ERROR_MARKERS
            .iter()
            .any(|marker| error.contains(marker)),
        "FCM rejected the credentials ({error}); check the service account, its \
         cloudmessaging.messages.create grant on {project}, and that the FCM API is enabled"
    );
    eprintln!(
        "FCM project={project}: credentials accepted, dummy token rejected as expected ({error})"
    );
}
