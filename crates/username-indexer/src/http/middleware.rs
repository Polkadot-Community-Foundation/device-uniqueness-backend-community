// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};

use super::error::AppError;
use super::state::AppState;
use crate::poc::Rejection;

/// Reject public read requests over the per-IP limit.
///
/// Keyed on the best-effort client IP and deliberately doing no signature work:
/// it must be the cheapest layer on the route so a client that has exhausted its
/// window cannot force JWT verification or puzzle hashing. The 429 renders the
/// shared JSON envelope with `Retry-After`.
pub async fn rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Err(err) = state.limiter.allow(state.limiter.client_ip(&req)).await {
        return AppError::RateLimited {
            retry_after_secs: err.wait_time_from(state.limiter.current_time()).as_secs(),
        }
        .into_response();
    }
    next.run(req).await
}

/// Admit a public read when the caller presents **either** a valid
/// device-attestation JWT **or** a fresh, solved proof-of-compute puzzle.
///
/// Pass-through when the gate is disabled (`state.poc` is `None`), which is the
/// shipping default. A bearer token that fails verification is treated as
/// *anonymous* rather than rejected: search must stay a public route, so this
/// middleware never emits a `401`.
pub async fn poc_gate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(poc) = state.poc.clone() else {
        return next.run(req).await;
    };

    if bearer_token(&req).is_some_and(|token| poc.jwt().verify(token).is_ok()) {
        return next.run(req).await;
    }

    let Some(header) = req
        .headers()
        .get(crate::poc::solution::HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return AppError::Poc(Rejection::Missing).into_response();
    };

    let solution = match crate::poc::Solution::parse_header(header) {
        Ok(solution) => solution,
        Err(rejection) => return AppError::Poc(rejection).into_response(),
    };

    match poc
        .verify(&state.pool, &solution, crate::poc::now_millis())
        .await
    {
        Ok(Ok(())) => next.run(req).await,
        Ok(Err(rejection)) => AppError::Poc(rejection).into_response(),
        Err(error) => AppError::Internal(error.into()).into_response(),
    }
}

fn bearer_token(req: &Request) -> Option<&str> {
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let mut parts = header.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some("Bearer"), Some(token), None) if !token.is_empty() => Some(token),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use http_common::{rate_limiter::Config as RateLimiterConfig, RateLimiter};

    #[tokio::test]
    async fn allows_up_to_limit_then_denies() {
        let limiter = RateLimiter::new(RateLimiterConfig::default().set_max_burst(3)).unwrap();
        assert!(limiter.allow("1.2.3.4".to_owned()).await.is_ok());
        assert!(limiter.allow("1.2.3.4".to_owned()).await.is_ok());
        assert!(limiter.allow("1.2.3.4".to_owned()).await.is_ok());
        assert!(limiter.allow("1.2.3.4".to_owned()).await.is_err());
    }

    #[tokio::test]
    async fn tracks_keys_independently() {
        let limiter = RateLimiter::new(RateLimiterConfig::default().set_max_burst(1)).unwrap();
        assert!(limiter.allow("1.1.1.1".to_owned()).await.is_ok());
        assert!(limiter.allow("1.1.1.1".to_owned()).await.is_err());
        assert!(limiter.allow("2.2.2.2".to_owned()).await.is_ok());
    }
}
