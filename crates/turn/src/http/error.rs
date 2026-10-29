// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
pub use http_common::FieldError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("rate limited")]
    RateLimited { retry_after_secs: u64 },
    #[error("invalid request body")]
    InvalidBody(Vec<FieldError>),
    #[error("malformed JSON body")]
    MalformedJson,
    /// Proof-route request rejected before verification (400).
    #[error("bad proof request")]
    BadProofRequest(&'static str),
    /// Proof verification failed — not a member, wrong context/message, or
    /// tampered proof (403). Deliberately unspecific.
    #[error("proof rejected")]
    ProofRejected,
    /// Proof verification cannot run right now — no root snapshot yet (503).
    #[error("proof verification unavailable")]
    ProofUnavailable(&'static str),
    /// Every verification slot stayed busy for the bounded wait (503 with
    /// `Retry-After`).
    #[error("proof verification saturated")]
    ProofBusy,
    #[error("proof verification failed internally")]
    ProofInternal,
    /// Cloudflare could not be reached and no cached credential was usable
    #[error("credential upstream unavailable")]
    UpstreamUnavailable,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::RateLimited { retry_after_secs } => {
                http_common::error::rate_limited(retry_after_secs)
            }
            AppError::InvalidBody(errors) => http_common::error::invalid_body(&errors),
            AppError::MalformedJson => http_common::error::malformed_json(),
            AppError::BadProofRequest(detail) => http_common::error::bad_request(detail),
            AppError::ProofRejected => http_common::error::message(
                StatusCode::FORBIDDEN,
                "The supplied proof was not accepted.",
            ),
            AppError::ProofUnavailable(detail) => {
                http_common::error::message(StatusCode::SERVICE_UNAVAILABLE, detail)
            }
            AppError::ProofBusy => {
                let mut response = http_common::error::message(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "All verification slots are busy.",
                );
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
                response
            }
            AppError::UpstreamUnavailable => {
                let mut response = http_common::error::message(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Credentials are temporarily unavailable.",
                );
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, header::HeaderValue::from_static("5"));
                response
            }
            AppError::ProofInternal => http_common::error::message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Proof verification failed internally.",
            ),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
