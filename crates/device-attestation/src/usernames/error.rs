// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
pub use http_common::FieldError;
use serde_json::json;

/// A usernames handler error mapped to its HTTP response.
#[derive(Debug, thiserror::Error)]
pub enum UsernamesError {
    #[error("rate limited")]
    RateLimited { retry_after_secs: u64 },
    #[error("invalid request body")]
    InvalidBody(Vec<FieldError>),
    #[error("invalid query parameters")]
    InvalidQuery(Vec<FieldError>),
    #[error("invalid request header")]
    InvalidHeader(Vec<FieldError>),
    #[error("malformed JSON body")]
    MalformedJson,
    #[error("preferred digits taken")]
    PreferredDigitsTaken {
        /// The requested two-digit suffix.
        digits: String,
        base: String,
    },
    #[error("no digits available")]
    NoDigitsAvailable { base: String },
    /// The selected `base.digits` was taken concurrently (409).
    #[error("username already taken")]
    UsernameTaken {
        base: String,
        /// The selected two-digit suffix.
        digits: String,
    },
    /// The `dotns.reservedUsername` full-person name is owned, or its
    /// reservation queue is full (409).
    ///
    /// Carries the name the claim asked to *reserve*, which is what was
    /// checked — not the base of the lite username, which the runtime never
    /// looks at for this leg.
    #[error("full name unavailable")]
    FullNameUnavailable { reserved: String },
    /// The authenticated account has no queued registration (404, new
    /// `/api/v1/registration/queue` surface).
    #[error("no queue entry")]
    NoQueueEntry,
    /// The submitted `lifetimePoUDVoucher` cannot be redeemed (400, new
    /// eligibility surface; a voucher failure rejects the
    /// claim, it never falls through to another lane).
    #[error("voucher not redeemable")]
    Voucher(crate::eligibility::VoucherError),
    /// The authenticated account has no active payment request (404, new
    /// `/api/v1/usernames/payment-status` surface).
    #[error("no active payment request")]
    NoPaymentRequest,
    #[error("registration persistence failed")]
    PersistenceFailed,
    /// Hard-mode DeviceCheck required a usable `Device-Token-iOS` and none
    /// was present (401).
    #[error("device token required")]
    DeviceTokenRequired,
    /// Hard-mode DeviceCheck could not reach Apple to resolve the device
    /// (502).
    #[error("device check unavailable")]
    DeviceCheckUnavailable,
    /// The free-registration slot could not be marked used at Apple after a
    /// successful gate. An upstream (Apple) write failure, so a 503 rather
    /// than a generic 500 — the mark failure is an upstream problem the
    /// client can retry.
    #[error("device registration failed")]
    DeviceRegistrationFailed,
    /// Widevine device evidence failed structural validation — partial
    /// fields, bad base64, wrong field sizes (enforced dedup mode; 400).
    /// The reason is logged at the reject site, never returned.
    #[error("device evidence malformed")]
    DeviceEvidenceMalformed,
    /// Widevine device evidence failed verification — chain policy, the
    /// cert-bound evidence hash, or a spent challenge (enforced dedup
    /// mode; 403). Retryable once with a fresh challenge. The reason is
    /// logged at the reject site, never returned.
    #[error("device evidence invalid")]
    DeviceEvidenceInvalid,
    /// The Widevine dedup gate could not be evaluated (attestation CRL
    /// unavailable). Infrastructure, not a device failure — a 503 the
    /// client retries.
    #[error("device evidence verification unavailable")]
    DeviceEvidenceUnavailable,
    /// Unexpected internal failure; logged, surfaced opaquely (500).
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for UsernamesError {
    fn into_response(self) -> Response {
        match self {
            UsernamesError::RateLimited { retry_after_secs } => {
                http_common::error::rate_limited(retry_after_secs)
            }
            UsernamesError::InvalidBody(errors) => http_common::error::invalid_body(&errors),
            UsernamesError::InvalidQuery(errors) => http_common::error::invalid_query(&errors),
            UsernamesError::InvalidHeader(errors) => http_common::error::invalid_header(&errors),
            UsernamesError::MalformedJson => (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Malformed JSON in request body" })),
            )
                .into_response(),
            UsernamesError::PreferredDigitsTaken { digits, base } => (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": format!("Preferred digits {digits} already taken for username {base}")
                })),
            )
                .into_response(),
            UsernamesError::NoDigitsAvailable { base } => (
                StatusCode::CONFLICT,
                Json(json!({ "error": format!("No digits available for username {base}.") })),
            )
                .into_response(),
            // No "re-submit without dotns.reservedUsername" escape hatch: every
            // client reserves unconditionally and none is planned that does
            // not, so the only advice a caller can act on is another name.
            UsernamesError::FullNameUnavailable { reserved } => (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": format!(
                        "The full name {reserved} is not available to reserve. \
                         Choose another name."
                    )
                })),
            )
                .into_response(),
            UsernamesError::UsernameTaken { base, digits } => (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": format!(
                        "Username {base}.{digits} already taken. Please try different digits."
                    )
                })),
            )
                .into_response(),
            UsernamesError::NoQueueEntry => (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "No queue entry found" })),
            )
                .into_response(),
            UsernamesError::Voucher(reason) => {
                use crate::eligibility::VoucherError;
                let message = match reason {
                    VoucherError::Unknown => "Voucher not found",
                    VoucherError::Spent => "Voucher already used",
                    VoucherError::Expired => "Voucher expired",
                };
                (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
            }
            UsernamesError::NoPaymentRequest => (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "No active payment request" })),
            )
                .into_response(),
            UsernamesError::PersistenceFailed => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to persist username registration" })),
            )
                .into_response(),
            UsernamesError::DeviceTokenRequired => (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "A valid Device-Token-iOS header is required." })),
            )
                .into_response(),
            UsernamesError::DeviceCheckUnavailable => (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "iOS DeviceCheck verification failed" })),
            )
                .into_response(),
            UsernamesError::DeviceRegistrationFailed => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "Failed to mark iOS device as registered with Apple DeviceCheck"
                })),
            )
                .into_response(),
            UsernamesError::DeviceEvidenceMalformed => (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "DEVICE_EVIDENCE_MALFORMED",
                    "message": "device evidence malformed"
                })),
            )
                .into_response(),
            UsernamesError::DeviceEvidenceInvalid => (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "DEVICE_EVIDENCE_INVALID",
                    "message": "device evidence invalid"
                })),
            )
                .into_response(),
            UsernamesError::DeviceEvidenceUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "DEVICE_EVIDENCE_UNAVAILABLE",
                    "message": "device evidence verification unavailable"
                })),
            )
                .into_response(),
            UsernamesError::Internal(err) => http_common::error::internal(&err),
        }
    }
}

impl From<sqlx::Error> for UsernamesError {
    fn from(err: sqlx::Error) -> Self {
        UsernamesError::Internal(err.into())
    }
}

/// Map an evidence rejection to its enforced-mode HTTP outcome
/// (`Malformed` → 400, `Invalid` → 403). Soft mode never converts —
/// it logs the verdict instead.
impl From<crate::widevine::EvidenceError> for UsernamesError {
    fn from(err: crate::widevine::EvidenceError) -> Self {
        use crate::widevine::EvidenceError;
        match err {
            EvidenceError::Malformed(_) => UsernamesError::DeviceEvidenceMalformed,
            EvidenceError::Invalid(_) => UsernamesError::DeviceEvidenceInvalid,
        }
    }
}

pub type UsernamesResult<T> = Result<T, UsernamesError>;
