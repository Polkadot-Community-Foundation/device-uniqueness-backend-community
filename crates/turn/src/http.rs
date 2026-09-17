// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub mod error;
pub mod proof_routes;
pub mod state;

use axum::extract::{Request, State};
use axum::http::header::{HeaderMap, HeaderValue};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use http_common::error::not_found;
use http_common::{health, layers, AuthSubject};

use self::error::{AppError, AppResult, FieldError};
use self::state::AppState;

/// This service's own paths and nothing else: no health routes, no service-wide
/// fallback, no middleware stack — that is what makes it mergeable in the
/// `all-in-one` role. The in-prefix `fallback(not_found)` stays here: it is this
/// surface's wrong-method dialect and must win inside `/api/v1/turn`.
///
/// The proof routes mount only when proof-authorized issuance is enabled; a hex
/// proof is ~1.6 KB, so an 8 KB cap bounds every legitimate request. Only
/// `/issue-with-proof` is browser-callable.
///
/// Layer order is load-bearing: the body cap goes on while `post` is the only
/// endpoint so it caps that handler alone, and CORS goes on last so it covers
/// the POST, the preflight, and the wrong-method fallback alike.
pub fn router(state: AppState) -> Router {
    let mut api = Router::new().route("/issue", post(issue_credentials).fallback(not_found));
    if state.proof.is_some() {
        api = api.route(
            "/issue-with-proof",
            post(proof_routes::issue_with_proof)
                .layer(axum::extract::DefaultBodyLimit::max(8 * 1024))
                .options(preflight)
                .fallback(not_found)
                .layer(axum::middleware::from_fn(allow_any_origin)),
        );
    }
    Router::new().nest("/api/v1/turn", api).with_state(state)
}

/// Stamp `access-control-allow-origin: *` on every proof-route response,
/// Origin header or not.
async fn allow_any_origin(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

/// The preflight: `204` with the allowed methods and whatever headers the
/// browser asked for (the allow-origin header is stamped by
/// [`allow_any_origin`]).
async fn preflight(headers: HeaderMap) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    let out = response.headers_mut();
    out.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST,OPTIONS"),
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

/// Assemble the full standalone service: [`router`] plus health at root, the
/// service-wide JSON 404, and the production middleware stack.
pub fn routes(state: AppState) -> Router {
    let health = health::router("turn", readiness).with_state(state.clone());
    layers::standard_layers(
        Router::new()
            .merge(health)
            .merge(router(state))
            .fallback(not_found),
    )
}

/// Stateless service: nothing to gate readiness on — if the process serves,
/// it can mint.
pub async fn readiness(_state: AppState) -> health::Readiness {
    Ok(&[])
}

async fn check_rate_limit(state: &AppState, subject: String) -> Result<(), AppError> {
    state
        .limiter
        .allow(subject)
        .await
        .map_err(|err| AppError::RateLimited {
            retry_after_secs: err.wait_time_from(state.limiter.current_time()).as_secs(),
        })
}

/// Validate the request body: an object whose optional `regionHint` is a
/// string or null. The value itself is ignored (reserved).
fn validate_body(body: &serde_json::Value) -> Result<(), Vec<FieldError>> {
    if !body.is_object() {
        return Err(vec![FieldError {
            message: http_common::error::expected("object", http_common::error::type_name(body)),
            field: "".to_string(),
        }]);
    }
    match body.get("regionHint") {
        None | Some(serde_json::Value::Null) | Some(serde_json::Value::String(_)) => Ok(()),
        Some(other) => Err(vec![FieldError {
            message: http_common::error::expected("string", http_common::error::type_name(other)),
            field: "regionHint".to_string(),
        }]),
    }
}

/// Issue short-lived TURN credentials for WebRTC ICE negotiation (JWT-gated).
#[utoipa::path(
    post,
    path = "/api/v1/turn/issue",
    tag = "TURN",
    security(("bearer_jwt" = [])),
    request_body = crate::openapi::IssueRequest,
    responses(
        (status = 201, description = "Credentials minted: `username` is \
`{unixExpiry}:{hexId}` (expiry = now + TTL), `password` is the base64 HMAC over `username` \
under the secret shared with the TURN relay (the coturn REST-API construction), `servers` \
echoes the configured ICE server list.",
         body = crate::openapi::IssueResponse),
        (status = 400, description = "Body validation failed (with per-field `fields`), or \
`Malformed JSON in request body` when a body is present but not JSON. An empty body is \
accepted — every field is optional.",
         example = json!({
             "error": "The request body contains invalid values.",
             "fields": [{ "field": "regionHint", "message": "expected string, received number" }]
         })),
        (status = 401, description = "Missing/malformed `Authorization` header or failed token \
verification.",
         example = json!({
             "error": "Token verification failed. The token may be expired or malformed."
         })),
        (status = 429, description = "Per-subject rate limit exceeded (with `Retry-After`).",
         example = json!({ "error": "Rate limit exceeded. Please retry after 60 seconds." })),
    )
)]
pub(crate) async fn issue_credentials(
    State(state): State<AppState>,
    auth: AuthSubject,
    body: axum::body::Bytes,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    // The content type is ignored; an empty body is an empty command, since
    // every field is optional. Anything else must parse as JSON.
    if !body.is_empty() {
        let body: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| AppError::MalformedJson)?;
        validate_body(&body).map_err(AppError::InvalidBody)?;
    }

    let () = check_rate_limit(&state, auth.subject).await?;

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    let mut id = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    let credentials = state.issuer.issue(now_unix, id);

    tracing::info!(ttl_secs = state.config.ttl_secs, "TURN credentials issued");
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "servers": state.config.ice_servers,
            "username": credentials.username,
            "password": credentials.password,
            "ttl": state.config.ttl_secs,
        })),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn accepts_absent_null_and_string_region_hints() {
        assert!(validate_body(&json!({})).is_ok());
        assert!(validate_body(&json!({ "regionHint": null })).is_ok());
        assert!(validate_body(&json!({ "regionHint": "eu-west" })).is_ok());
    }

    #[test]
    fn rejects_non_string_region_hints() {
        let errors = validate_body(&json!({ "regionHint": 5 })).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field, "regionHint");
        assert_eq!(errors[0].message, "expected string, received number");
    }

    #[test]
    fn rejects_non_object_bodies_at_the_root_pointer() {
        for (body, received) in [
            (json!([1, 2]), "array"),
            (json!("nope"), "string"),
            (json!(null), "null"),
        ] {
            let errors = validate_body(&body).unwrap_err();
            assert_eq!(errors[0].field, "");
            assert_eq!(
                errors[0].message,
                format!("expected object, received {received}")
            );
        }
    }
}
