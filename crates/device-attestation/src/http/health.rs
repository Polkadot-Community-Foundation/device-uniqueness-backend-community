// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;

use super::state::AppState;
use crate::chain::asset_hub::AssetHub;

/// Build the health router (mounted at the root, not under `/api/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/healthcheck", get(healthcheck))
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
}

/// A liveness/health status body: `{ status, service }`.
#[derive(Serialize, ToSchema)]
pub(crate) struct Status {
    /// Coarse status word, e.g. `ok`, `alive`, `ready`.
    status: &'static str,
    /// Service name emitting the status.
    service: &'static str,
}

/// Process health probe. No dependencies checked.
#[utoipa::path(
    get,
    path = "/healthcheck",
    tag = "Liveness & Readiness",
    responses(
        (status = 200, description = "Process is up. No dependencies checked.", body = Status,
         example = json!({ "status": "ok", "service": "device-attestation" }))
    )
)]
pub(crate) async fn healthcheck() -> Json<Status> {
    Json(Status {
        status: "ok",
        service: "device-attestation",
    })
}

/// Kubernetes liveness probe — "should this pod be restarted".
#[utoipa::path(
    get,
    path = "/livez",
    tag = "Liveness & Readiness",
    responses(
        (status = 200, description = "Process is alive.", body = Status,
         example = json!({ "status": "alive", "service": "device-attestation" }))
    )
)]
pub(crate) async fn livez() -> Json<Status> {
    Json(Status {
        status: "alive",
        service: "device-attestation",
    })
}

/// Kubernetes readiness probe — checks the `db`, `chain` and `asset_hub` subsystems.
#[utoipa::path(
    get,
    path = "/readyz",
    tag = "Liveness & Readiness",
    responses(
        (status = 200, description = "Instance can take traffic; db, People Chain and Asset Hub reachable.",
         body = serde_json::Value,
         example = json!({ "status": "ready", "service": "device-attestation", "db": "up", "chain": "up", "asset_hub": "up" })),
        (status = 503, description = "A required subsystem is unavailable.",
         body = serde_json::Value,
         example = json!({ "status": "unavailable", "service": "device-attestation", "db": "down" }))
    )
)]
pub(crate) async fn readyz(State(state): State<AppState>) -> Response {
    match api_probe(
        state.pool.clone(),
        state.chain.clone(),
        state.asset_hub.clone(),
    )
    .await
    {
        Err(down) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "unavailable", "service": "device-attestation", down: "down" })),
        )
            .into_response(),
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "status": "ready",
                "service": "device-attestation",
                "db": "up",
                "chain": "up",
                "asset_hub": "up",
            })),
        )
            .into_response(),
    }
}

/// The API's dependency probe: [`probe`], then the Asset Hub RPC that
/// availability and registration read `LiteLabelOwner` from. Behind the API's
/// `/readyz` and readiness gauge (and `all-in-one`'s), so an unreachable Asset
/// Hub takes the instance out of rotation instead of answering `500`.
pub async fn api_probe(
    pool: sqlx::PgPool,
    chain: crate::PeopleChain,
    asset_hub: AssetHub,
) -> http_common::health::Readiness {
    probe(pool, chain).await?;
    if let Err(err) = asset_hub.health().await {
        tracing::warn!(error = ?err, "readiness check failed: Asset Hub unavailable");
        return Err("asset_hub");
    }
    Ok(&["db", "chain", "asset_hub"])
}

/// The dependency probe behind `/readyz` and the readiness gauges: Postgres,
/// then the People Chain RPC. Shared with the workers' gauge probe so the two
/// can never disagree.
pub async fn probe(
    pool: sqlx::PgPool,
    chain: crate::PeopleChain,
) -> http_common::health::Readiness {
    if let Err(err) = sqlx::query("SELECT 1").execute(&pool).await {
        tracing::warn!(error = ?err, "readiness check failed: database unavailable");
        return Err("db");
    }
    if let Err(err) = chain.health().await {
        tracing::warn!(error = ?err, "readiness check failed: People Chain unavailable");
        return Err("chain");
    }
    Ok(&["db", "chain"])
}
