// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub mod error;
pub mod state;

use std::str::FromStr as _;
use std::time::Duration;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use http_common::error::not_found;
use http_common::{health, layers, AuthSubject};
use time::OffsetDateTime;

use self::error::{AppError, AppResult, FieldError};
use self::state::AppState;
use crate::sign::TicketKeypair;
use crate::tickets::{self, Dim};

/// Transient-DB retry budget, mirroring the legacy shell's `dbRetry`
/// (3 retries, 200ms base, ×2 back-off; the legacy jitter is dropped as an
/// implementation detail — it shaped load, not the wire contract).
const DB_RETRIES: u32 = 3;
const DB_RETRY_BASE: Duration = Duration::from_millis(200);

/// This service's own paths and nothing else: no health routes, no service-wide
/// fallback, no middleware stack. That is what makes it mergeable with its
/// siblings in the `all-in-one` role.
///
/// The in-prefix `fallback(not_found)` stays here: it is this surface's own
/// wrong-method dialect and must win inside `/api/v1/invitation-ticket` however
/// the router is assembled.
pub fn router(state: AppState) -> Router {
    let api = Router::new().route("/claim", post(claim_ticket).fallback(not_found));
    Router::new()
        .nest("/api/v1/invitation-ticket", api)
        .with_state(state)
}

/// Assemble the full standalone service: [`router`] plus health at root, the
/// service-wide JSON 404, and the production middleware stack.
pub fn routes(state: AppState) -> Router {
    let health = health::router("invite-tickets", readiness).with_state(state.clone());
    layers::standard_layers(
        Router::new()
            .merge(health)
            .merge(router(state))
            .fallback(not_found),
    )
}

/// Readiness gates on Postgres only — the claim path never touches the People
/// Chain (registration is the pool maintainer's job), so a chain outage must
/// not take the API out of rotation.
pub async fn readiness(state: AppState) -> health::Readiness {
    if let Err(err) = sqlx::query("SELECT 1").execute(&state.pool).await {
        tracing::warn!(error = ?err, "readiness check failed: database unavailable");
        return Err("db");
    }
    Ok(&["db"])
}

/// Enforce the per-subject fixed window; `429` with `Retry-After` on excess.
async fn check_rate_limit(state: &AppState, subject: String) -> Result<(), AppError> {
    state
        .limiter
        .allow(subject)
        .await
        .map_err(|err| AppError::RateLimited {
            retry_after_secs: err.wait_time_from(state.limiter.current_time()).as_secs(),
        })
}

/// Retry a transient-failure-prone DB operation with exponential back-off,
/// mirroring the legacy shell's `dbRetry` posture: infra errors are retried
/// then surfaced as a 500; domain outcomes (`Ok`) are never retried.
async fn retry_db<T, F, Fut>(mut op: F) -> Result<T, sqlx::Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    let mut delay = DB_RETRY_BASE;
    let mut attempt = 0;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) if attempt < DB_RETRIES => {
                tracing::warn!(error = ?err, attempt, "transient DB failure; retrying");
                tokio::time::sleep(delay).await;
                delay *= 2;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Validated `POST /api/v1/invitation-ticket/claim` body.
#[derive(Debug)]
struct ClaimRequest {
    who: String,
    /// The decoded 32-byte account id of `who` — the exact signature payload.
    who_account: subxt::utils::AccountId32,
    dim: Dim,
}

/// Validate the request body (`who`: non-empty valid-SS58 string, `dim`:
/// `Game | ProofOfInk`). Checks are non-aborting, so an empty `who` reports
/// both the min-length failure and the SS58 failure.
fn validate_body(body: &serde_json::Value) -> Result<ClaimRequest, Vec<FieldError>> {
    if !body.is_object() {
        return Err(vec![FieldError {
            message: http_common::error::expected("object", http_common::error::type_name(body)),
            field: "".to_string(),
        }]);
    }

    let mut errors = Vec::new();

    let who = match body.get("who") {
        Some(serde_json::Value::String(s)) => {
            if s.is_empty() {
                errors.push(FieldError {
                    message: http_common::error::MUST_NOT_BE_EMPTY.to_string(),
                    field: "who".to_string(),
                });
            }
            match subxt::utils::AccountId32::from_str(s) {
                Ok(account) => Some((s.clone(), account)),
                Err(_) => {
                    errors.push(FieldError {
                        message: "Invalid SS58 address format".to_string(),
                        field: "who".to_string(),
                    });
                    None
                }
            }
        }
        other => {
            errors.push(FieldError {
                message: http_common::error::expected(
                    "string",
                    http_common::error::received_name(other),
                ),
                field: "who".to_string(),
            });
            None
        }
    };

    // One uniform message for every bad `dim` — missing, null, wrong type,
    // or an unknown literal.
    let dim = match body.get("dim") {
        Some(serde_json::Value::String(s)) => Dim::from_str(s).ok(),
        _ => None,
    };
    if dim.is_none() {
        errors.push(FieldError {
            message: "expected one of \"Game\"|\"ProofOfInk\"".to_string(),
            field: "dim".to_string(),
        });
    }

    match (who, dim) {
        (Some((who, who_account)), Some(dim)) if errors.is_empty() => Ok(ClaimRequest {
            who,
            who_account,
            dim,
        }),
        _ => Err(errors),
    }
}

/// Claim an invitation ticket for a DIM, returning a signature (JWT-gated).
#[utoipa::path(
    post,
    path = "/api/v1/invitation-ticket/claim",
    tag = "Invitation Tickets",
    security(("bearer_jwt" = [])),
    request_body = crate::openapi::ClaimRequest,
    responses(
        (status = 200, description = "Ticket claimed: the oldest `available` ticket of the \
`(dim, network)` pool, atomically flipped to `claimed`, with an sr25519 signature by the \
ticket key over the claimant's decoded 32-byte account id.",
         body = crate::openapi::ClaimResponse),
        (status = 400, description = "Body validation failed (with per-field `fields`), or \
`Malformed JSON in request body` when the body is not JSON.",
         example = json!({
             "error": "The request body contains invalid values.",
             "fields": [{ "field": "who", "message": "Invalid SS58 address format" }]
         })),
        (status = 401, description = "Missing/malformed `Authorization` header or failed token \
verification.",
         example = json!({
             "error": "Token verification failed. The token may be expired or malformed."
         })),
        (status = 409, description = "Ticket race lost — a concurrent request claimed the \
contended ticket.",
         example = json!({ "error": "Ticket race lost" })),
        (status = 422, description = "Pool exhausted — no `available` ticket in the \
`(dim, network)` pool.",
         example = json!({ "error": "Pool exhausted" })),
        (status = 429, description = "Per-subject rate limit exceeded (with `Retry-After`).",
         example = json!({ "error": "Rate limit exceeded. Please retry after 60 seconds." })),
        (status = 500, description = "Unexpected internal failure (opaque).",
         example = json!({ "error": "Internal server error. Please try again." })),
    )
)]
pub(crate) async fn claim_ticket(
    State(state): State<AppState>,
    auth: AuthSubject,
    body: axum::body::Bytes,
) -> AppResult<Json<serde_json::Value>> {
    // The content type is ignored; anything that is not parseable JSON is a
    // 400.
    let body: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| AppError::MalformedJson)?;
    let request = validate_body(&body).map_err(AppError::InvalidBody)?;
    check_rate_limit(&state, auth.subject).await?;

    let dim = request.dim;
    let network = state.config.network;
    let now = OffsetDateTime::now_utc();

    // A cheap pre-check first — an empty pool is 422 before any locking is
    // attempted.
    let available = retry_db(|| tickets::count_available(&state.pool, dim, network)).await?;
    if available == 0 {
        tracing::debug!(
            dim = dim.as_str(),
            network = network.as_str(),
            "pool exhausted — no available tickets"
        );
        return Err(AppError::PoolExhausted);
    }

    // The atomic grab. `None` after a non-empty pre-check is the ticket race
    // (even if the pool has actually drained in between).
    let ticket =
        retry_db(|| tickets::claim_oldest(&state.pool, dim, network, &request.who, now)).await?;
    let Some(ticket) = ticket else {
        tracing::debug!(
            dim = dim.as_str(),
            network = network.as_str(),
            "ticket claimed by concurrent request"
        );
        return Err(AppError::TicketRaceLost);
    };

    // A stored secret that fails to load is a data defect — the legacy shell
    // `orDie`d here too (500), never a 4xx.
    let keypair = TicketKeypair::from_stored_secret(&ticket.private_key)
        .map_err(|e| AppError::Internal(e.into()))?;
    let signature = keypair.sign(&request.who_account.0);

    let remaining = retry_db(|| tickets::count_available(&state.pool, dim, network)).await?;

    tracing::info!(
        dim = dim.as_str(),
        network = network.as_str(),
        remaining,
        "ticket claimed successfully"
    );
    Ok(Json(tickets::claim_response(
        &ticket,
        &signature,
        dim,
        network,
        &request.who,
        now,
        remaining,
    )))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const VALID_WHO: &str = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";

    #[test]
    fn accepts_valid_body() {
        let body = json!({ "who": VALID_WHO, "dim": "Game" });
        let parsed = validate_body(&body).expect("valid");
        assert_eq!(parsed.dim, Dim::Game);
        assert_eq!(parsed.who, VALID_WHO);
        assert_eq!(
            parsed.who_account,
            subxt::utils::AccountId32::from_str(VALID_WHO).expect("valid")
        );
    }

    #[test]
    fn rejects_missing_fields_with_pointers() {
        let errors = validate_body(&json!({})).unwrap_err();
        let pointers: Vec<&str> = errors.iter().map(|e| e.field.as_str()).collect();
        assert_eq!(pointers, vec!["who", "dim"]);
        assert_eq!(errors[0].message, "expected string, received nothing");
        assert_eq!(errors[1].message, "expected one of \"Game\"|\"ProofOfInk\"");
    }

    #[test]
    fn rejects_invalid_ss58_with_the_refine_message() {
        let errors = validate_body(&json!({ "who": "not-an-address", "dim": "Game" })).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "Invalid SS58 address format");
        assert_eq!(errors[0].field, "who");
    }

    #[test]
    fn rejects_ss58_with_a_corrupted_checksum() {
        let corrupted = format!("{}z", &VALID_WHO[..VALID_WHO.len() - 1]);
        let errors = validate_body(&json!({ "who": corrupted, "dim": "Game" })).unwrap_err();
        assert_eq!(errors[0].message, "Invalid SS58 address format");
    }

    #[test]
    fn empty_who_reports_both_min_length_and_ss58_failures() {
        let errors = validate_body(&json!({ "who": "", "dim": "Game" })).unwrap_err();
        let details: Vec<&str> = errors.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(
            details,
            vec!["must not be empty", "Invalid SS58 address format",]
        );
    }

    #[test]
    fn rejects_unknown_dim_with_the_uniform_option_message() {
        let errors = validate_body(&json!({ "who": VALID_WHO, "dim": "Chess" })).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "expected one of \"Game\"|\"ProofOfInk\"");
        assert_eq!(errors[0].field, "dim");
    }

    #[test]
    fn rejects_wrong_types() {
        let errors = validate_body(&json!({ "who": 5, "dim": 7 })).unwrap_err();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].message, "expected string, received number");
    }

    #[test]
    fn rejects_non_object_bodies_at_the_root_pointer() {
        let errors = validate_body(&json!([1, 2])).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field, "");
        assert_eq!(errors[0].message, "expected object, received array");
    }
}
