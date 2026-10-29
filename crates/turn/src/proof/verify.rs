// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use verifiable::ring::bandersnatch::BandersnatchSha512Ell2;
use verifiable::ring::bandersnatch::BandersnatchVrfVerifiable;
use verifiable::ring::ring_signature_size;
use verifiable::Alias;
use verifiable::GenerateVerifiable as _;

use super::roots::Snapshot;

type Proof = <BandersnatchVrfVerifiable as verifiable::GenerateVerifiable>::Proof;

/// Byte length of the proofs this route accepts.
///
/// The `Proof` type is bounded by the largest *multi*-context signature, so
/// the bound alone admits payloads this route can never verify. Every proof
/// here carries exactly one context, which fixes the length.
pub const PROOF_LEN: usize = ring_signature_size::<BandersnatchSha512Ell2>(1);

/// Why a proof was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// Proof bytes were longer than a ring-VRF signature can be.
    #[error("malformed proof")]
    Malformed,
    /// The proof verified against none of the accepted roots.
    #[error("proof rejected")]
    Rejected,
    /// The blocking verification task failed internally.
    #[error("proof verification failed internally")]
    Internal,
}

/// Verify a proof over `(context, message)` and return its contextual alias.
///
/// `(ring_index, ring_revision)` names one held root; a pair the server does not
/// hold is rejected without verifying anything. The alias is a throttle key only
/// — keep it out of responses, credentials, logs, and metrics.
pub async fn verify(
    snapshot: Snapshot,
    proof_bytes: Vec<u8>,
    context: Vec<u8>,
    message: Vec<u8>,
    ring_index: u32,
    ring_revision: u32,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Alias, VerifyError> {
    let result = tokio::task::spawn_blocking(move || {
        let proof = Proof::try_from(proof_bytes).map_err(|_| VerifyError::Malformed)?;

        let root = snapshot
            .roots
            .iter()
            .find(|root| root.ring_index == ring_index && root.revision == ring_revision)
            .ok_or(VerifyError::Rejected)?;

        let _permit = permit;
        BandersnatchVrfVerifiable::validate(
            snapshot.domain,
            &proof,
            &root.members,
            &context,
            &message,
        )
        .map_err(|_| VerifyError::Rejected)
    })
    .await;
    match result {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, "proof verification task failed");
            Err(VerifyError::Internal)
        }
    }
}
