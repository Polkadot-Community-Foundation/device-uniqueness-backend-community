// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};

use super::error::AppError;
use super::state::AppState;

/// Reject requests over the per-route/per-IP limit.
pub async fn rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let key = format!("{}:{}", req.uri().path(), state.limiter.client_ip(&req));
    if state.limiter.allow(key).await.is_err() {
        return AppError::RateLimited.into_response();
    }
    next.run(req).await
}
