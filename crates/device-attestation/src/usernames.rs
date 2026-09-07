// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub mod available;
pub mod error;
pub mod register;

use std::collections::BTreeSet;

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{
        header::{HeaderMap, HeaderValue},
        StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use http_common::error::not_found;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

use crate::{
    chain::{
        outbox,
        people::{BaseState, ReservationState},
    },
    http::state::AppState,
};

use self::error::{UsernamesError, UsernamesResult};

const MIN_BASE_LEN: usize = 6;

/// Maximum base-username length
/// (`MAX_USERNAME_LENGTH - N_USERNAME_DIGITS - 1`).
pub(crate) const MAX_BASE_LEN: usize = 29;

/// Base-username rules, shared by the read and write paths so they can't
/// disagree: length 6..=29, lowercase ASCII letters.
fn is_valid_base(base: &str) -> bool {
    (MIN_BASE_LEN..=MAX_BASE_LEN).contains(&base.len())
        && base.bytes().all(|b| b.is_ascii_lowercase())
}

/// The free discriminators for a base: `1..=99` minus the taken set (`00` is
/// never offered). Shared so availability, registration, and the payment
/// watcher's confirmation-time re-selection agree on what's free.
pub(crate) fn available_digits(taken: &BTreeSet<u8>) -> Vec<u8> {
    (1..=99u8).filter(|d| !taken.contains(d)).collect()
}

fn merge_discriminators(mut chain: BTreeSet<u8>, outbox: BTreeSet<u8>) -> BTreeSet<u8> {
    chain.extend(outbox);
    chain
}

pub(crate) async fn base_state(state: &AppState, base: &str) -> UsernamesResult<BaseState> {
    let (chain, pending) = tokio::try_join!(
        async {
            state
                .chain
                .base_state(base)
                .await
                .map_err(UsernamesError::from)
        },
        async {
            outbox::allocated_discriminators(&state.pool, base)
                .await
                .map_err(UsernamesError::from)
        },
    )?;
    Ok(BaseState {
        taken: merge_discriminators(chain.taken, pending),
        ..chain
    })
}

pub(crate) async fn reservation_state(
    state: &AppState,
    name: &str,
) -> UsernamesResult<ReservationState> {
    state
        .chain
        .reservation_state(name)
        .await
        .map_err(UsernamesError::from)
}

/// Subject-keyed rate limit for the authenticated usernames surface (never
/// IP — the CGNAT postmortem). Renders the 429 with `Retry-After`.
pub(crate) fn check_rate_limit(state: &AppState, subject: &str) -> UsernamesResult<()> {
    let key = format!("/api/v1/usernames:{subject}");
    if state.limiter.allow(&key) {
        return Ok(());
    }
    Err(UsernamesError::RateLimited {
        retry_after_secs: state.config.auth_rate_window.as_secs(),
    })
}

/// Parse the request body as JSON, content type ignored. Unparseable → 400.
pub(crate) fn parse_json_body(body: &Bytes) -> UsernamesResult<Value> {
    serde_json::from_slice(body).map_err(|_| UsernamesError::MalformedJson)
}

/// Build the `/usernames` router.
///
/// Method fallbacks keep wrong-method requests on the JSON 404; the collection
/// root also answers CORS preflights. `/payment-status` mounts only with the
/// payment lane enabled, the same contract as `/registration/queue`.
pub fn router(payment_enabled: bool) -> Router<AppState> {
    let root = Router::new()
        .route(
            "/",
            post(register::register)
                .options(collection_preflight)
                .fallback(not_found),
        )
        .layer(axum::middleware::from_fn(allow_any_origin));
    let routes = root.route("/available", post(available::check).fallback(not_found));
    if payment_enabled {
        routes.route(
            "/payment-status",
            axum::routing::get(crate::payment::status).fallback(not_found),
        )
    } else {
        routes
    }
}

/// Stamp `access-control-allow-origin: *` on every collection-root response,
/// Origin header or not.
async fn allow_any_origin(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

/// The collection-root preflight: `204` with the CORS
/// defaults (the allow-origin header is stamped by [`allow_any_origin`]).
async fn collection_preflight(headers: HeaderMap) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    let out = response.headers_mut();
    out.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET,HEAD,PUT,POST,DELETE,PATCH"),
    );
    if let Some(requested) = headers.get(axum::http::header::ACCESS_CONTROL_REQUEST_HEADERS) {
        out.insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            requested.clone(),
        );
    }
    out.insert(
        axum::http::header::VARY,
        HeaderValue::from_static("Access-Control-Request-Headers"),
    );
    response
}

/// `{ attester }` — the on-chain attester authority public key.
#[derive(Serialize, ToSchema)]
pub struct AttesterResponse {
    /// `0x`-hex sr25519 public key the backend writes registrations as.
    #[schema(example = "0xe4cd20d6d1e0e119d63a943afd2d7496fbbb0ac8e7cd99c3c5f16b63a68e7432")]
    attester: String,
}

/// `GET /api/v1/attester` — the attester authority public key (`0x`+hex, public).
#[utoipa::path(
    get,
    path = "/api/v1/attester",
    tag = "Discovery",
    responses(
        (status = 200, description = "The on-chain attester account the backend writes as.", body = AttesterResponse,
         example = json!({ "attester": "0xe4cd20d6d1e0e119d63a943afd2d7496fbbb0ac8e7cd99c3c5f16b63a68e7432" }))
    )
)]
pub async fn attester(State(state): State<AppState>) -> Json<AttesterResponse> {
    Json(AttesterResponse {
        attester: format!("0x{}", hex::encode(state.config.attester_account)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn attester_response_keeps_the_mobile_wire_shape() {
        let response = AttesterResponse {
            attester: "0x86aac84d".to_string(),
        };

        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({ "attester": "0x86aac84d" })
        );
    }

    #[test]
    fn base_validation_shared_by_read_and_write_paths() {
        assert!(is_valid_base("alicexyz"));
        assert!(is_valid_base(&"a".repeat(MAX_BASE_LEN)));
        assert!(!is_valid_base("short"));
        assert!(!is_valid_base("Alicexyz"));
        assert!(!is_valid_base("alice123"));
        assert!(!is_valid_base(&"a".repeat(MAX_BASE_LEN + 1)));
    }

    #[test]
    fn available_excludes_taken_and_zero() {
        let taken: BTreeSet<u8> = [1u8, 2, 99].into_iter().collect();
        let available = available_digits(&taken);
        assert!(!available.contains(&0));
        assert!(!available.contains(&1));
        assert!(!available.contains(&99));
        assert!(available.contains(&3));
        assert_eq!(available.len(), 99 - 3);
    }

    #[test]
    fn allocation_union_keeps_chain_and_outbox_digits() {
        let chain: BTreeSet<u8> = [1, 2].into_iter().collect();
        let outbox: BTreeSet<u8> = [2, 3].into_iter().collect();
        assert_eq!(
            merge_discriminators(chain, outbox),
            [1, 2, 3].into_iter().collect()
        );
    }

    #[test]
    fn body_parses_as_json_regardless_of_content_type() {
        assert!(parse_json_body(&Bytes::from_static(b"{\"usernames\":[]}")).is_ok());
        assert!(matches!(
            parse_json_body(&Bytes::from_static(b"{not json")),
            Err(UsernamesError::MalformedJson)
        ));
        assert!(matches!(
            parse_json_body(&Bytes::new()),
            Err(UsernamesError::MalformedJson)
        ));
    }
}
