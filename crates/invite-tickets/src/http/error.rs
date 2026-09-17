// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
pub use http_common::FieldError;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("rate limited")]
    RateLimited { retry_after_secs: u64 },
    #[error("invalid request body")]
    InvalidBody(Vec<FieldError>),
    #[error("malformed JSON body")]
    MalformedJson,
    /// No `available` ticket in the pool at the pre-check (422).
    #[error("pool exhausted")]
    PoolExhausted,
    /// The pre-check saw tickets but the claim transaction found none (409).
    #[error("ticket race lost")]
    TicketRaceLost,
    /// Unexpected internal failure; logged, surfaced opaquely (500).
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::RateLimited { retry_after_secs } => {
                http_common::error::rate_limited(retry_after_secs)
            }
            AppError::InvalidBody(errors) => http_common::error::invalid_body(&errors),
            AppError::MalformedJson => http_common::error::malformed_json(),
            AppError::PoolExhausted => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "Pool exhausted" })),
            )
                .into_response(),
            AppError::TicketRaceLost => (
                StatusCode::CONFLICT,
                Json(json!({ "error": "Ticket race lost" })),
            )
                .into_response(),
            AppError::Internal(err) => http_common::error::internal(&err),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::Internal(err.into())
    }
}
