// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use notifications::{FcmConfig, FcmProvider, PushProvider, PushRequest};

/// FCM's `error.message` when it rejects a malformed device token
/// (400 INVALID_ARGUMENT), which is what the dummy token below gets. The
/// provider reports FCM's `error.message` as its error text. NOT_FOUND is left
/// out on purpose: its "Requested entity was not found." is Google's generic
/// 404 text, not specific to a device token.
const TOKEN_VERDICTS: &[&str] = &["registration token is not a valid FCM registration token"];

/// Whether the provider's error is FCM rejecting the device token.
///
/// An allowlist on purpose: anything else, including a failure before FCM
/// answered (the provider's own `fcm …` errors), a refusal of the caller in any
/// wording, quota or a server error, is no proof that the credentials work, so
/// it fails the smoke. A reworded verdict also fails, loudly, with the text.
fn is_token_verdict(error: &str) -> bool {
    !error.starts_with("fcm ") && TOKEN_VERDICTS.iter().any(|verdict| error.contains(verdict))
}

#[tokio::test]
#[ignore = "hits Google's live FCM servers; needs real FCM_SERVICE_ACCOUNT_JSON"]
async fn fcm_auth_and_connectivity_smoke() {
    let Some(config) = FcmConfig::from_env().expect("valid FCM config") else {
        eprintln!("FCM_SERVICE_ACCOUNT_JSON not configured; skipping live smoke");
        return;
    };
    let provider = FcmProvider::new(config).expect("build FCM provider");

    let request = PushRequest {
        device_token: "fake-device-token-not-a-real-fcm-registration-token".to_string(),
        push_id: "5d41402abc4b2a76b9719d911017c592".to_string(),
        message: "0xdeadbeef".to_string(),
        topic: None,
        voip: None,
    };

    // The provider returns `Err` for every FCM rejection, so a dummy token is
    // expected to come back as an error; only FCM's verdict on the token
    // proves the credentials were accepted.
    let error = match provider.send(&request).await {
        Ok(_) => {
            eprintln!("FCM accepted the push (unexpected for a dummy token, but auth is valid)");
            return;
        }
        Err(error) => error.to_string(),
    };

    assert!(
        is_token_verdict(&error),
        "FCM gave no verdict on the dummy token, so the credentials are unproven: {error}. \
         If this refuses the caller, check the service account, its \
         cloudmessaging.messages.create grant on the project, and that the FCM API is enabled; \
         if it is a quota, server or network error, retry; if it is FCM's verdict on the token \
         in new wording, update TOKEN_VERDICTS"
    );
    eprintln!("FCM credentials accepted, dummy token rejected as expected ({error})");
}

#[test]
fn only_a_token_verdict_counts_as_accepted_credentials() {
    assert!(is_token_verdict(
        "The registration token is not a valid FCM registration token"
    ));
    for other in [
        // Raised by the provider before FCM answered, even when the text it
        // carries happens to contain a verdict.
        "fcm token exchange rejected (400): The registration token is not a valid FCM registration token",
        "fcm token exchange rejected (400): {\"error\":\"invalid_grant\"}",
        "fcm token exchange failed: error sending request",
        "fcm request failed: operation timed out",
        // A refusal of the caller, in the wordings Google uses.
        "Request had invalid authentication credentials. Expected OAuth 2 access token.",
        "Request had insufficient authentication scopes.",
        "The caller does not have permission",
        "Permission 'cloudmessaging.messages.create' denied on resource",
        "Firebase Cloud Messaging API has not been used in project 1 before or it is disabled.",
        "SenderId mismatch",
        // Google's generic 404, which says nothing about the device token.
        "Requested entity was not found.",
        // Quota and server errors, and the provider's fallback for a bodyless reply.
        "Quota exceeded for quota metric 'Messages'",
        "Internal error encountered.",
        "The service is currently unavailable.",
        "FCM rejected the push (status 503)",
        "FCM rejected the push (status 401)",
        "",
    ] {
        assert!(!is_token_verdict(other), "{other:?} is not a token verdict");
    }
}
