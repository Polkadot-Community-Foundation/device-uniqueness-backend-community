// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::http::error::{AppError, AppResult, FieldError};
use crate::http::state::AppState;
use crate::platform::{self, Platform};
use crate::provider::{ProviderError, PushOutcome, PushRequest};
use http_common::AuthSubject;

/// Route component of the rate-limit key (kept explicit so the key is
/// `route:subject`, not subject alone, if more authenticated routes are added).
const NOTIFY_ROUTE: &str = "/api/v1/notify";

/// Validated `POST /api/v1/notify` request, built by [`validate_body`].
#[derive(Debug)]
struct NotifyRequest {
    device_token: String,
    push_id: String,
    platform: Option<Platform>,
    bundler_id: Option<String>,
    message: String,
    voip: Option<bool>,
}

/// Frozen `POST /api/v1/notify` response body.
#[derive(Debug, Serialize)]
pub struct NotifyResponse {
    pub success: bool,
    pub platform: Platform,
    /// Number of notifications sent, when the provider reports it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent: Option<u32>,
    /// Number of failed notifications, when the provider reports it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed: Option<u32>,
    /// Provider message id, when returned (FCM).
    #[serde(rename = "messageId", skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<PushError>>,
}

/// One per-device push error, matching the frozen response shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushError {
    pub device: String,
    /// APNs environment, when the provider distinguishes dev/prod.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Provider status (string or number), when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<serde_json::Value>,
    /// Raw provider response, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
}

impl NotifyResponse {
    fn from_outcome(platform: Platform, outcome: PushOutcome) -> Self {
        Self {
            success: outcome.success,
            platform,
            sent: outcome.sent,
            failed: outcome.failed,
            message_id: outcome.message_id,
            errors: outcome.errors,
        }
    }

    fn provider_failure(platform: Platform, device_token: &str, error: &ProviderError) -> Self {
        Self {
            success: false,
            platform,
            sent: None,
            failed: None,
            message_id: None,
            errors: Some(vec![PushError {
                device: device_token.to_string(),
                environment: None,
                status: None,
                response: Some(serde_json::Value::String(error.to_string())),
            }]),
        }
    }
}

/// Handle `POST /api/v1/notify`.
///
/// Order mirrors the sibling services: verified JWT (`401` problem details) →
/// body parse (`400` plain text on malformed JSON) → body validation (`400`
/// problem details with per-field `errors`) → per-subject rate limit (`429`
/// with `Retry-After`). Beyond that the relay always answers `200`: on provider
/// failure it preserves the legacy `success: false` body instead of an error
/// status.
#[utoipa::path(
    post,
    path = "/api/v1/notify",
    tag = "Notifications",
    security(("bearer_jwt" = [])),
    request_body = crate::openapi::NotifyRequestDoc,
    responses(
        (status = 200, description = "Relay accepted the request. The push result is echoed \
verbatim from the provider — including the legacy behavior of returning `200` with \
`success: false` on provider failure, so a non-200 status never signals a delivery failure.",
         body = crate::openapi::NotifyResponseDoc),
        (status = 400, description = "Body validation failed (RFC 9457 problem details with \
per-field `errors`); or plain-text `Malformed JSON in request body` when the body is not JSON."),
        (status = 401, description = "Missing/malformed `Authorization` header or failed token \
verification (RFC 9457 problem details)."),
        (status = 429, description = "Per-subject rate limit exceeded (RFC 9457 problem details, \
with `Retry-After`)."),
    )
)]
pub async fn handle(
    State(state): State<AppState>,
    auth: AuthSubject,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> AppResult<Json<NotifyResponse>> {
    let Json(body) = body.map_err(|_| AppError::MalformedJson)?;
    let request = validate_body(&body).map_err(AppError::InvalidBody)?;

    // Abuse control keyed on the authenticated subject + route (never raw IP).
    let rate_key = format!("{NOTIFY_ROUTE}:{}", auth.subject);
    let () = state
        .limiter
        .allow(rate_key)
        .await
        .map_err(|err| AppError::RateLimited {
            retry_after_secs: err.wait_time_from(state.limiter.current_time()).as_secs(),
        })?;

    let platform = platform::detect(&request.device_token, request.platform);
    let push = PushRequest {
        device_token: request.device_token,
        push_id: request.push_id,
        message: request.message,
        topic: request.bundler_id,
        voip: request.voip,
    };

    let provider = match platform {
        Platform::Ios => &state.apns,
        Platform::Android => &state.fcm,
    };

    match provider.send(&push).await {
        Ok(outcome) => Ok(Json(NotifyResponse::from_outcome(platform, outcome))),
        // Legacy quirk preserved: on failure the reported platform is the client
        // hint (or Android), not the auto-detected value.
        Err(error) => {
            let reported = request.platform.unwrap_or(Platform::Android);
            Ok(Json(NotifyResponse::provider_failure(
                reported,
                &push.device_token,
                &error,
            )))
        }
    }
}

/// Validate the request against the frozen `PushSendRequest` schema, reproducing
/// the legacy zod v4 messages and pointers. The three required string fields
/// (`deviceToken`, `pushId`, `message`) are validated in schema order and their
/// errors collected; the optional fields (`platform`, `bundlerId`, `voip`) are
/// parsed best-effort — a wrong-typed optional is ignored rather than rejected,
/// since the shipping clients never send them malformed and there is no golden
/// capture pinning their error shapes.
fn validate_body(body: &serde_json::Value) -> Result<NotifyRequest, Vec<FieldError>> {
    if !body.is_object() {
        return Err(vec![FieldError {
            message: http_common::error::expected("object", http_common::error::type_name(body)),
            field: "".to_string(),
        }]);
    }

    let mut errors = Vec::new();
    let device_token = required_string(
        body,
        "deviceToken",
        "deviceToken",
        valid_device_token,
        "Must be a valid device token",
        &mut errors,
    );
    let push_id = required_string(
        body,
        "pushId",
        "pushId",
        valid_push_id,
        "Must be a 32 or 64 character hexadecimal hash",
        &mut errors,
    );
    let message = required_string(
        body,
        "message",
        "message",
        valid_hex_message,
        "Must be a valid hexadecimal string",
        &mut errors,
    );

    let platform = body
        .get("platform")
        .and_then(|value| serde_json::from_value::<Platform>(value.clone()).ok());
    let bundler_id = body
        .get("bundlerId")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let voip = body.get("voip").and_then(serde_json::Value::as_bool);

    match (device_token, push_id, message) {
        (Some(device_token), Some(push_id), Some(message)) if errors.is_empty() => {
            Ok(NotifyRequest {
                device_token,
                push_id,
                platform,
                bundler_id,
                message,
                voip,
            })
        }
        _ => Err(errors),
    }
}

/// Validate a required string field: absent/non-string yields the zod type
/// error, a present-but-malformed value yields `message`; the raw value is
/// returned either way so later fields are still checked (matching zod, which
/// collects every issue).
fn required_string(
    body: &serde_json::Value,
    key: &str,
    pointer: &str,
    is_valid: impl Fn(&str) -> bool,
    message: &str,
    errors: &mut Vec<FieldError>,
) -> Option<String> {
    match body.get(key) {
        Some(serde_json::Value::String(value)) => {
            if !is_valid(value) {
                errors.push(FieldError {
                    message: message.to_string(),
                    field: pointer.to_string(),
                });
            }
            Some(value.clone())
        }
        other => {
            errors.push(FieldError {
                message: http_common::error::expected(
                    "string",
                    http_common::error::received_name(other),
                ),
                field: pointer.to_string(),
            });
            None
        }
    }
}

/// `^[a-zA-Z0-9_\-+/=:]{64,326}$`
fn valid_device_token(token: &str) -> bool {
    let len = token.len();
    (DEVICE_TOKEN_MIN..=DEVICE_TOKEN_MAX).contains(&len)
        && token.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'/' | b'=' | b':')
        })
}

/// `^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{64}$`
fn valid_push_id(push_id: &str) -> bool {
    matches!(push_id.len(), 32 | 64) && push_id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `^(0x)?[a-fA-F0-9]+$` with a max length of 8192.
fn valid_hex_message(message: &str) -> bool {
    if message.len() > MAX_MESSAGE_LEN {
        return false;
    }
    let body = message.strip_prefix("0x").unwrap_or(message);
    !body.is_empty() && body.bytes().all(|b| b.is_ascii_hexdigit())
}

const MAX_MESSAGE_LEN: usize = 8192;
const DEVICE_TOKEN_MIN: usize = 64;
const DEVICE_TOKEN_MAX: usize = 326;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const IOS_TOKEN: &str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const PUSH_ID: &str = "5d41402abc4b2a76b9719d911017c592";

    #[test]
    fn accepts_a_well_formed_body() {
        let request = validate_body(&json!({
            "deviceToken": IOS_TOKEN, "pushId": PUSH_ID, "message": "0x1234abcd",
        }))
        .expect("valid");
        assert_eq!(request.device_token, IOS_TOKEN);
        assert_eq!(request.push_id, PUSH_ID);
    }

    #[test]
    fn missing_required_fields_report_zod_pointers_in_schema_order() {
        let errors = validate_body(&json!({})).unwrap_err();
        let pointers: Vec<&str> = errors.iter().map(|e| e.field.as_str()).collect();
        assert_eq!(pointers, vec!["deviceToken", "pushId", "message"]);
        assert_eq!(errors[0].message, "expected string, received nothing");
    }

    #[test]
    fn malformed_fields_report_the_custom_regex_messages() {
        let errors = validate_body(&json!({
            "deviceToken": "too-short", "pushId": PUSH_ID, "message": "nothex",
        }))
        .unwrap_err();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].field, "deviceToken");
        assert_eq!(errors[0].message, "Must be a valid device token");
        assert_eq!(errors[1].field, "message");
        assert_eq!(errors[1].message, "Must be a valid hexadecimal string");
    }

    #[test]
    fn wrong_type_reports_the_zod_type_error() {
        let errors = validate_body(&json!({
            "deviceToken": 5, "pushId": PUSH_ID, "message": "abcd",
        }))
        .unwrap_err();
        assert_eq!(errors[0].field, "deviceToken");
        assert_eq!(errors[0].message, "expected string, received number");
    }

    #[test]
    fn non_object_body_reports_the_root_pointer() {
        let errors = validate_body(&json!([1, 2])).unwrap_err();
        assert_eq!(errors[0].field, "");
        assert_eq!(errors[0].message, "expected object, received array");
    }

    #[test]
    fn push_id_accepts_32_and_64_hex_only() {
        assert!(valid_push_id(PUSH_ID));
        assert!(valid_push_id(&"a".repeat(64)));
        assert!(!valid_push_id(&"a".repeat(40)));
        assert!(!valid_push_id("zzzz402abc4b2a76b9719d911017c592"));
    }

    #[test]
    fn message_allows_optional_0x_prefix() {
        assert!(valid_hex_message("1234abcd"));
        assert!(valid_hex_message("0x1234ABCD"));
        assert!(!valid_hex_message("0x"));
        assert!(!valid_hex_message(&format!(
            "0x{}",
            "a".repeat(MAX_MESSAGE_LEN)
        )));
    }

    #[test]
    fn apns_success_serializes_with_counts_and_no_message_id() {
        let outcome = PushOutcome {
            success: true,
            sent: Some(1),
            failed: Some(0),
            message_id: None,
            errors: None,
        };
        let body =
            serde_json::to_value(NotifyResponse::from_outcome(Platform::Ios, outcome)).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "success": true, "platform": "ios", "sent": 1, "failed": 0 })
        );
    }

    #[test]
    fn fcm_success_serializes_with_message_id_and_no_failed() {
        let outcome = PushOutcome {
            success: true,
            sent: Some(1),
            failed: None,
            message_id: Some("projects/p/messages/1".to_string()),
            errors: None,
        };
        let body =
            serde_json::to_value(NotifyResponse::from_outcome(Platform::Android, outcome)).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "success": true, "platform": "android", "sent": 1,
                "messageId": "projects/p/messages/1",
            })
        );
    }

    #[test]
    fn provider_failure_serializes_as_the_generic_fallback() {
        let response = NotifyResponse::provider_failure(
            Platform::Android,
            IOS_TOKEN,
            &ProviderError::Delivery("token_invalid".to_string()),
        );
        let body = serde_json::to_value(response).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "success": false,
                "platform": "android",
                "errors": [{ "device": IOS_TOKEN, "response": "token_invalid" }],
            })
        );
    }

    #[test]
    fn provider_failure_body_matches_legacy_shape() {
        let response = NotifyResponse::provider_failure(
            Platform::Ios,
            IOS_TOKEN,
            &ProviderError::Delivery("Network error".to_string()),
        );
        assert!(!response.success);
        assert_eq!(response.platform, Platform::Ios);
        let errors = response.errors.expect("errors present");
        assert_eq!(errors[0].device, IOS_TOKEN);
        assert_eq!(
            errors[0].response,
            Some(serde_json::Value::String("Network error".to_string()))
        );
    }
}
