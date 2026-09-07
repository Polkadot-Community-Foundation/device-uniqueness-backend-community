// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Widevine device-uniqueness evidence on `POST /api/v1/usernames` (PoUD):
//! one free registration per physical Android device.
//!
//! Wire spec v1 — `attestationChain`, `deviceChallenge`, `deviceId`, present
//! together or not at all. The client attests a key whose
//! `attestationChallenge` is
//! `SHA-256(domain ‖ challenge ‖ candidate ‖ deviceId)`; the backend
//! recomputes that hash from the JWT subject and the request fields and
//! verifies the chain against it, so the TEE-signed certificate is the
//! binding signature.
//!
//! `deviceId` is `SHA-256("dub/poud/widevine-id/v1" ‖ rawId)`, computed on
//! the device. That derivation is frozen — changing it re-identifies the
//! whole fleet. Only `HMAC-SHA256(k, "poud:v1" ‖ deviceId)` is stored
//! ([`store`]), so a dump cannot be tested against candidate ids.
//!
//! Measured L1 is a protocol invariant, not a wire field: the attested app
//! builds evidence only from an `HW_SECURE_ALL` session.
//!
//! `WIDEVINE_DEDUP_ENABLED` recognises the fields (soft mode: verify and log
//! only); `WIDEVINE_DEDUP_ENFORCE` makes the routing live.

pub mod store;

use std::collections::HashSet;

use base64::Engine as _;
use hmac::Mac as _;
use secrecy::ExposeSecret as _;
use serde_json::Value;
use sha2::Digest as _;

use crate::auth::key_attest;
use crate::config::{Config, WidevineConfig};

/// Domain tag of the attestation-challenge preimage.
pub const DOMAIN: &str = "dub/poud/android/v1";

/// HMAC domain-separation context.
const HMAC_CONTEXT: &[u8] = b"poud:v1";

/// `attestationChain` bounds — the same limits as the `/auth/token` contract.
const MIN_CHAIN_ENTRIES: usize = 2;
const MAX_CHAIN_ENTRIES: usize = 10;
const MAX_ENTRY_CHARS: usize = 8192;

/// Why device evidence was rejected. In enforced mode the route maps
/// `Malformed` to `DEVICE_EVIDENCE_MALFORMED` (400) and `Invalid` to
/// `DEVICE_EVIDENCE_INVALID` (403); in soft mode both are logged verdicts.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    /// Structural failure: partial fields, bad base64, wrong field sizes.
    #[error("malformed device evidence: {0}")]
    Malformed(String),
    /// Verification failure: chain policy, or the cert-bound evidence hash
    /// (challenge / account / deviceId).
    #[error("invalid device evidence: {0}")]
    Invalid(String),
}

/// The three wire fields, decoded but not yet verified.
pub struct RawEvidence {
    /// Leaf-first DER chain from `attestationChain`.
    pub chain_der: Vec<Vec<u8>>,
    /// The `/auth/challenges` value from `deviceChallenge`.
    pub challenge: [u8; 32],
    /// The client-hashed device pseudonym from `deviceId`.
    pub device_id: [u8; 32],
}

/// Extract the evidence fields from the (already parsed) request body.
/// `Ok(None)` = no evidence; partial presence or bound violations are
/// [`EvidenceError::Malformed`].
pub fn extract(body: &Value) -> Result<Option<RawEvidence>, EvidenceError> {
    let chain = body.get("attestationChain");
    let challenge = body.get("deviceChallenge");
    let device_id = body.get("deviceId");
    let (chain, challenge, device_id) = match (chain, challenge, device_id) {
        (None, None, None) => return Ok(None),
        (Some(c), Some(ch), Some(d)) => (c, ch, d),
        _ => {
            return Err(EvidenceError::Malformed(
                "attestationChain, deviceChallenge and deviceId \
                 must be present together"
                    .to_string(),
            ))
        }
    };

    let b64 = base64::engine::general_purpose::STANDARD;

    let entries = chain.as_array().ok_or_else(|| {
        EvidenceError::Malformed("attestationChain must be an array of strings".to_string())
    })?;
    if entries.len() < MIN_CHAIN_ENTRIES || entries.len() > MAX_CHAIN_ENTRIES {
        return Err(EvidenceError::Malformed(format!(
            "attestationChain has {} entries, expected {MIN_CHAIN_ENTRIES}..={MAX_CHAIN_ENTRIES}",
            entries.len()
        )));
    }
    let chain_der = entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let raw = entry.as_str().ok_or_else(|| {
                EvidenceError::Malformed(format!("attestationChain[{i}] must be a string"))
            })?;
            if raw.len() > MAX_ENTRY_CHARS {
                return Err(EvidenceError::Malformed(format!(
                    "attestationChain[{i}] exceeds {MAX_ENTRY_CHARS} chars"
                )));
            }
            b64.decode(raw.trim()).map_err(|_| {
                EvidenceError::Malformed(format!("attestationChain[{i}] is not valid base64"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let decode32 = |field: &'static str, value: &Value| -> Result<[u8; 32], EvidenceError> {
        value
            .as_str()
            .ok_or_else(|| EvidenceError::Malformed(format!("{field} must be a string")))
            .and_then(|raw| {
                b64.decode(raw.trim())
                    .map_err(|_| EvidenceError::Malformed(format!("{field} is not valid base64")))
            })?
            .try_into()
            .map_err(|_| EvidenceError::Malformed(format!("{field} must be exactly 32 bytes")))
    };
    let challenge = decode32("deviceChallenge", challenge)?;
    let device_id = decode32("deviceId", device_id)?;

    Ok(Some(RawEvidence {
        chain_der,
        challenge,
        device_id,
    }))
}

/// Fully verified device evidence, ready for the dedup gate.
pub struct VerifiedEvidence {
    /// Evidence challenge — the caller consumes it (single-use) from the
    /// challenge store before acting on the evidence.
    pub challenge: [u8; 32],
    /// The stored pseudonym: `HMAC-SHA256(k, "poud:v1" ‖ deviceId)`.
    pub hmac: [u8; 32],
}

/// Everything [`verify`] needs besides the evidence itself. No IO — the
/// caller fetches the CRL and supplies the clock.
pub struct VerifyParams<'a> {
    /// Service config (package allow-list + signing digests).
    pub config: &'a Config,
    /// The enabled Widevine block (HMAC key + enforcement flag).
    pub widevine: &'a WidevineConfig,
    /// Revoked serials from the attestation CRL.
    pub revoked_serials: &'a HashSet<String>,
    /// The authenticated account's sr25519 public key (the JWT subject).
    pub subject_pubkey: &'a [u8; 32],
    /// Verification time (unix seconds).
    pub now_unix: i64,
}

/// Verify the evidence: recompute the cert-bound hash from the authenticated
/// subject and the request fields, then verify the attestation chain against
/// it. Does not consume the challenge or touch the dedup store — the route
/// owns those side effects, and the challenge is what makes evidence fresh.
pub fn verify(
    evidence: &RawEvidence,
    params: &VerifyParams<'_>,
) -> Result<VerifiedEvidence, EvidenceError> {
    // Every field is fixed-width, so the concatenation is unambiguous.
    let expected_challenge: [u8; 32] = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(DOMAIN.as_bytes());
        hasher.update(evidence.challenge);
        hasher.update(params.subject_pubkey);
        hasher.update(evidence.device_id);
        hasher.finalize().into()
    };

    let (Some(playstore_digest), Some(website_digest)) = (
        params.config.android_signing_digest_playstore.as_ref(),
        params.config.android_signing_digest_website.as_ref(),
    ) else {
        return Err(EvidenceError::Invalid(
            "android signing digests are not configured".to_string(),
        ));
    };
    let chain_params = key_attest::verify::VerifyParams {
        // The leaf's attestationChallenge must equal the recomputed evidence
        // hash — the TEE-signed certificate is what binds the challenge,
        // account, and deviceId to this claim.
        challenge: &expected_challenge,
        package_names: &params.config.android_package_names,
        playstore_digest,
        website_digest,
        trusted_roots_der: &key_attest::verify::google_roots_der(),
        trusted_verified_boot_keys: key_attest::verify::GRAPHENEOS_VERIFIED_BOOT_KEYS,
        revoked_serials: params.revoked_serials,
        now_unix: params.now_unix,
    };
    key_attest::verify::verify_chain(&evidence.chain_der, &chain_params)
        .map_err(|e| EvidenceError::Invalid(e.to_string()))?;

    Ok(VerifiedEvidence {
        challenge: evidence.challenge,
        hmac: device_hmac(
            params.widevine.hmac_key.expose_secret(),
            &evidence.device_id,
        ),
    })
}

/// `HMAC-SHA256(key, "poud:v1" ‖ deviceId)` — the stored pseudonym. The
/// preimage is fixed-width, so there is nothing to frame.
fn device_hmac(key: &[u8; 32], device_id: &[u8; 32]) -> [u8; 32] {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC takes any length");
    mac.update(HMAC_CONTEXT);
    mac.update(device_id);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn full_body() -> Value {
        json!({
            "attestationChain": ["AQID", "BAUG"],
            "deviceChallenge": base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]),
            "deviceId": base64::engine::general_purpose::STANDARD.encode([0x22u8; 32])
        })
    }

    #[test]
    fn extract_requires_all_three_fields_or_none() {
        assert!(extract(&json!({})).expect("no evidence").is_none());

        let raw = extract(&full_body()).expect("valid").expect("present");
        assert_eq!(raw.chain_der, vec![vec![1, 2, 3], vec![4, 5, 6]]);
        assert_eq!(raw.challenge, [0x11; 32]);
        assert_eq!(raw.device_id, [0x22; 32]);

        // Every partial combination is malformed.
        for missing in ["attestationChain", "deviceChallenge", "deviceId"] {
            let mut body = full_body();
            body.as_object_mut().unwrap().remove(missing);
            assert!(
                matches!(extract(&body), Err(EvidenceError::Malformed(_))),
                "missing {missing}"
            );
        }
    }

    #[test]
    fn extract_enforces_the_wire_bounds() {
        // Chain too short.
        let mut body = full_body();
        body["attestationChain"] = json!(["AQID"]);
        assert!(matches!(extract(&body), Err(EvidenceError::Malformed(_))));

        // Chain entry not a string.
        let mut body = full_body();
        body["attestationChain"] = json!(["AQID", 7]);
        assert!(matches!(extract(&body), Err(EvidenceError::Malformed(_))));

        // Challenge not 32 bytes.
        let mut body = full_body();
        body["deviceChallenge"] = json!("AQID");
        assert!(matches!(extract(&body), Err(EvidenceError::Malformed(_))));

        // Bad base64 device id.
        let mut body = full_body();
        body["deviceId"] = json!("!!!");
        assert!(matches!(extract(&body), Err(EvidenceError::Malformed(_))));
    }

    #[test]
    fn device_hmac_separates_keys_and_ids() {
        let hmac = device_hmac(&[1u8; 32], &[9u8; 32]);
        assert_ne!(hmac, device_hmac(&[2u8; 32], &[9u8; 32]));
        assert_ne!(hmac, device_hmac(&[1u8; 32], &[8u8; 32]));
        // Deterministic for the same inputs.
        assert_eq!(hmac, device_hmac(&[1u8; 32], &[9u8; 32]));
    }
}
