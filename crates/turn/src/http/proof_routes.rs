// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use super::error::{AppError, AppResult};
use super::state::{AppState, PERMIT_WAIT};
use crate::proof::message::FreshnessError;
use crate::proof::roots::PersonhoodCollection;
use crate::proof::verify::{self, VerifyError};

/// Proof-redemption request.
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct IssueWithProofBody {
    /// The product the proof was made for. Its context is the one the proof
    /// is verified under, so a product proves under its own identifier. Must
    /// be one this deployment accepts.
    #[serde(rename = "productId")]
    #[schema(rename = "productId", example = "vox.dot")]
    product_id: String,
    /// Hex-encoded 32-byte collection id from the proof's TrUAPI
    /// `ringLocation`. Only the canonical People Lite and People collections
    /// are accepted.
    #[schema(example = "0x706f703a706f6c6b61646f742e6e6574776f726b2f70656f706c652d6c697465")]
    collection: String,
    /// Ring-VRF proof over the derived message (hex), exactly as the host
    /// returns it — raw signature bytes, with no SCALE length prefix.
    proof: String,
    /// Ring containing the proving member, used to locate the root.
    #[serde(rename = "ringIndex")]
    #[schema(rename = "ringIndex", example = 0)]
    ring_index: u32,
    /// Revision of that ring the proof was made against, as the host reports
    /// it. Only that revision's root is tried, so a revision this deployment
    /// no longer holds is refused without verifying anything.
    #[serde(rename = "ringRevision")]
    #[schema(rename = "ringRevision", example = 3)]
    ring_revision: u32,
    /// Client Unix seconds, bound into the proved message. Must be within the
    /// server's accepted skew.
    #[schema(example = 1_784_757_652_u64)]
    timestamp: u64,
}

/// Redeem a personhood proof for the same credentials as `/turn/issue`.
#[utoipa::path(
    post,
    path = "/api/v1/turn/issue-with-proof",
    tag = "TURN",
    request_body = IssueWithProofBody,
    responses(
        (status = 201, description = "Proof accepted; returns servers, username, password, and the \
configured TTL. Credentials expire `ttl` seconds after issuance; no alias appears in the response.",
         body = crate::openapi::IssueResponse),
        (status = 400, description = "Unparseable body, invalid hex, a collection outside the \
canonical People Lite/People allowlist, a proof that is not a single-context ring-VRF signature, \
a product this deployment does not accept, or a timestamp outside the accepted skew."),
        (status = 403, description = "The proof did not verify against the named ring root \
under that product's context — including when `(ringIndex, ringRevision)` is outside the roots \
this deployment still holds (deliberately unspecific)."),
        (status = 429, description = "This person's redemption limit was exceeded (with \
`Retry-After`)."),
        (status = 503, description = "Verification unavailable: no ring-root snapshot yet (chain \
unreachable since boot), the bounded waiter queue is full, or all verification slots remained busy \
for the bounded wait. Saturation responses include `Retry-After`."),
    )
)]
pub(crate) async fn issue_with_proof(
    State(state): State<AppState>,
    body: Result<Json<IssueWithProofBody>, axum::extract::rejection::JsonRejection>,
) -> AppResult<(StatusCode, Json<serde_json::Value>)> {
    let proof_state = state
        .proof
        .as_deref()
        .expect("proof route is mounted only when proof state is present");

    let Json(body) = body.map_err(|_| AppError::BadProofRequest("invalid request body"))?;
    let context = *proof_state
        .contexts
        .get(&body.product_id)
        .ok_or(AppError::BadProofRequest("product is not accepted"))?;
    let collection = PersonhoodCollection::from_hex(&body.collection)
        .ok_or(AppError::BadProofRequest("collection is not accepted"))?;
    let proof_bytes = hex::decode(body.proof.trim_start_matches("0x"))
        .map_err(|_| AppError::BadProofRequest("proof is not valid hex"))?;
    if proof_bytes.len() != verify::PROOF_LEN {
        return Err(AppError::BadProofRequest("proof is not a ring-VRF proof"));
    }

    let now = now_unix();
    proof_state
        .freshness
        .check(body.timestamp, now)
        .map_err(|FreshnessError::OutsideWindow| {
            AppError::BadProofRequest("timestamp outside the accepted window")
        })?;
    let message = proof_state.freshness.message(body.timestamp);

    let snapshot = proof_state
        .roots
        .get(collection)
        .snapshot(crate::config::PROOF_MAX_ROOT_AGE)
        .ok_or(AppError::ProofUnavailable("ring roots not yet available"))?;
    if !snapshot
        .roots
        .iter()
        .any(|root| root.ring_index == body.ring_index && root.revision == body.ring_revision)
    {
        return Err(AppError::ProofRejected);
    }

    let permit = match proof_state.permits.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            let waiter = proof_state
                .waiters
                .clone()
                .try_acquire_owned()
                .map_err(|_| AppError::ProofBusy)?;
            let permit =
                tokio::time::timeout(PERMIT_WAIT, proof_state.permits.clone().acquire_owned())
                    .await
                    .map_err(|_| AppError::ProofBusy)?
                    .map_err(|_| AppError::ProofInternal)?;
            drop(waiter);
            permit
        }
    };

    let alias = verify::verify(
        snapshot,
        proof_bytes,
        context.to_vec(),
        message.to_vec(),
        body.ring_index,
        body.ring_revision,
        permit,
    )
    .await
    .map_err(|error| match error {
        VerifyError::Malformed => AppError::BadProofRequest("proof is not a ring-VRF proof"),
        VerifyError::Rejected => AppError::ProofRejected,
        VerifyError::Internal => AppError::ProofInternal,
    })?;

    // Keep the alias confined to private throttle and keyed-derivation inputs.
    let () = proof_state
        .alias_limiter
        .allow(hex::encode(alias))
        .await
        .map_err(|err| AppError::RateLimited {
            retry_after_secs: err.wait_time_from(state.limiter.current_time()).as_secs(),
        })?;

    let credentials = state
        .issuer
        .issue_for_proof(now_unix(), &body.product_id, alias.as_ref());

    tracing::info!(
        ttl_secs = state.config.ttl_secs,
        "TURN credentials issued via proof"
    );
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

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}
