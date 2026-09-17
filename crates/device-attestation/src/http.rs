// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub mod error;
pub mod health;
pub mod middleware;
pub mod state;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use http_common::error::not_found;
use http_common::layers;

use self::state::AppState;
use crate::{auth, queue, usernames};

/// Assemble the full router: health + JWKS at root, the `/api/v1` surface
/// below, wrapped in the shared production middleware stack (request id →
/// tracing → timeout). Unmatched paths fall back to the JSON `404`.
pub fn routes(state: AppState) -> Router {
    let health = health::router().with_state(state.clone());
    layers::standard_layers(
        Router::new()
            .merge(health)
            .merge(router(state))
            .fallback(not_found),
    )
}

/// This service's own paths and nothing else: no health routes, no service-wide
/// fallback, no middleware stack. That is what makes it mergeable with its
/// siblings in the `all-in-one` role.
///
/// Device attestation owns the *global* fallback in the deployed route table — the edge's
/// `handle { }` block sends everything unclaimed here — so a merged router's
/// service-wide `not_found` is this service's dialect, not a new one.
pub fn router(state: AppState) -> Router {
    let api_v1 = Router::new()
        .nest("/auth", auth::router(state.clone()))
        .route("/attester", get(usernames::attester))
        .nest("/usernames", usernames::router());
    let api_v1 = if state.config.queue_enabled {
        api_v1.route(
            "/registration/queue",
            get(queue::status).fallback(not_found),
        )
    } else {
        api_v1
    };

    Router::new()
        .route("/.well-known/jwks.json", get(jwks))
        .nest("/api/v1", api_v1)
        .with_state(state)
}

/// Publish the Ed25519 public key so siblings can verify tokens.
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    tag = "Discovery",
    responses(
        (status = 200, description = "JWT verification keyset (Ed25519 / OKP).",
         body = serde_json::Value,
         example = json!({ "keys": [ {
             "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
             "kid": "...", "x": "..."
         } ] }))
    )
)]
pub(crate) async fn jwks(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::to_value(state.jwt.jwks()).expect("invalid fragment"))
}
