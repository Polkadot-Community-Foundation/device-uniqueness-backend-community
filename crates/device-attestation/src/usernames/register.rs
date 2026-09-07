// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::{collections::BTreeSet, str::FromStr as _};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
    Json,
};
use base64::Engine as _;
use http_common::AuthSubject;
use rand::{rngs::OsRng, seq::SliceRandom as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::{
    chain::outbox::{self, InsertError, NewReservation},
    device_check::{self, Decision},
    eligibility,
    http::state::AppState,
    payment, queue,
};

use super::error::{FieldError, UsernamesError, UsernamesResult};
use super::{available_digits, base_state, reservation_state, MAX_BASE_LEN};

/// The flat registration request (documentation mirror — the handler
/// validates raw JSON so it can report every failing field).
#[derive(Deserialize, ToSchema)]
#[allow(dead_code)]
pub struct RegisterRequest {
    /// SS58 beneficiary account that will own the username.
    #[serde(rename = "candidateAccountId")]
    #[schema(
        rename = "candidateAccountId",
        example = "5FbRAkhDvNVecNzHLFxBNXFXNwvBaV69S1W3nfBbnxYypkkT"
    )]
    candidate_account_id: String,
    /// Base username (lowercase ASCII letters, 6..=29 chars).
    #[schema(example = "tallesx")]
    username: String,
    /// Optional two-digit suffix, e.g. `"07"`; random-free if omitted.
    #[serde(rename = "preferredDigits")]
    #[schema(rename = "preferredDigits", example = "07")]
    preferred_digits: Option<String>,
    /// `0x`-hex 64-byte sr25519 signature proving control of the candidate.
    #[serde(rename = "candidateSignature")]
    #[schema(rename = "candidateSignature", example = "0x...64 bytes...")]
    candidate_signature: String,
    /// `0x`-hex ring VRF key.
    #[serde(rename = "ringVrfKey")]
    #[schema(rename = "ringVrfKey", example = "0x...")]
    ring_vrf_key: String,
    /// `0x`-hex 64-byte ownership proof.
    #[serde(rename = "proofOfOwnership")]
    #[schema(rename = "proofOfOwnership", example = "0x...64 bytes...")]
    proof_of_ownership: String,
    /// `0x`-hex 64-byte consumer registration signature.
    #[serde(rename = "consumerRegistrationSignature")]
    #[schema(rename = "consumerRegistrationSignature", example = "0x...64 bytes...")]
    consumer_registration_signature: String,
    /// `0x`-hex 65-byte identifier key.
    #[serde(rename = "identifierKey")]
    #[schema(rename = "identifierKey", example = "0x...65 bytes...")]
    identifier_key: String,
    /// Optional single-use registration voucher (the INSTANT lane): bypasses
    /// the PoUD gate and the registration queue. Ignored unless
    /// `REGISTRATION_VOUCHERS_ENABLED`.
    #[serde(rename = "lifetimePoUDVoucher")]
    #[schema(rename = "lifetimePoUDVoucher", example = "base64url-voucher-key")]
    lifetime_poud_voucher: Option<String>,
    /// Optional Android device-uniqueness evidence (Widevine PoUD): leaf-first
    /// base64 DER attestation chain, 2-10 entries, whose leaf key was created
    /// with `attestationChallenge = SHA-256(domain ‖ deviceChallenge ‖
    /// accountKey ‖ deviceId)`. All three evidence fields are present
    /// together or not at all; ignored unless `WIDEVINE_DEDUP_ENABLED`.
    /// Sent only when the app measured Widevine L1.
    #[serde(rename = "attestationChain")]
    #[schema(rename = "attestationChain", example = json!(["base64-der-leaf", "base64-der-root"]))]
    attestation_chain: Option<Vec<String>>,
    /// Base64 32-byte single-use challenge from `/auth/challenges`, bound
    /// into the leaf key's attestation challenge.
    #[serde(rename = "deviceChallenge")]
    #[schema(rename = "deviceChallenge", example = "base64-32-byte-challenge")]
    device_challenge: Option<String>,
    /// Base64 32-byte device pseudonym:
    /// `SHA-256("dub/poud/widevine-id/v1" ‖ rawWidevineId)`, computed on the
    /// device — the raw id never leaves it.
    #[serde(rename = "deviceId")]
    #[schema(rename = "deviceId", example = "base64-32-byte-device-id")]
    device_id: Option<String>,
    /// Optional DotNS reservation block.
    dotns: Option<Dotns>,
}

/// Optional DotNS reservation, parking a base label for later full-person use.
#[derive(Deserialize, ToSchema)]
#[allow(dead_code)]
pub(crate) struct Dotns {
    /// `0x`-hex 64-byte signature.
    #[schema(example = "0x...64 bytes...")]
    signature: String,
    /// Unix timestamp the reservation was signed at.
    #[serde(rename = "signedAt")]
    #[schema(rename = "signedAt", example = 1780000000i64)]
    signed_at: i64,
    /// The bare full-person name to reserve. Its own name on chain — it need
    /// not be `username`, and availability is checked against *this* name, not
    /// against the base of the lite username in the same claim.
    #[serde(rename = "reservedUsername")]
    #[schema(rename = "reservedUsername", example = "reservedname")]
    reserved_username: Option<String>,
}

/// `202` body: the reserved full username and its parts.
#[derive(Serialize, ToSchema)]
pub struct RegisterResponse {
    /// Reserved base username.
    #[schema(example = "tallesx")]
    pub base_username: String,
    /// Selected two-digit discriminator.
    #[schema(example = "07")]
    pub digits: String,
    /// Full `base.NN` username.
    #[schema(example = "tallesx.07")]
    pub username: String,
    /// Present only when the DeviceCheck free-slot gate ran and produced an
    /// advisory availability (`Register`/`Proceed`); omitted when DeviceCheck
    /// is disabled or the outcome short-circuited (payment/token/unavailable).
    #[serde(
        rename = "device_check_available",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(rename = "device_check_available")]
    pub device_check_available: Option<bool>,
    /// `"QUEUED"` when the registration queue is enabled and the claim is
    /// waiting in it; `"INSTANT"` when a voucher bypassed the gate and the
    /// queue; absent on the plain direct-to-writer path. (The
    /// `PAYMENT_REQUIRED` outcome is a separate `200` body, not this 202
    /// shape — see the route's 200 response.)
    #[serde(
        rename = "registrationOutcome",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(rename = "registrationOutcome", example = "QUEUED")]
    pub registration_outcome: Option<String>,
    /// Queue standing at claim time (present only with
    /// `registrationOutcome: "QUEUED"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue: Option<crate::queue::QueueStatusResponse>,
}

/// Field-check and refinement messages.
const MSG_HEX_64: &str = "Must be a hexadecimal string of exactly 64 bytes.";
const MSG_HEX_65: &str = "Must be a hexadecimal string of exactly 65 bytes.";
const MSG_DIGITS: &str = "Digits must be between 01-99";
const MSG_INVALID_SS58: &str = "Invalid ss58 address.";
const MSG_INVALID_SIGNATURE: &str = "Invalid signature.";
const MSG_DOTNS_DISABLED: &str = "dotNS gateway is not enabled in this environment.";
/// `BaseLabel` is `BoundedVec<u8, ConstU32<32>>` in the dotns-gateway pallet.
const MAX_DOTNS_LABEL_LEN: usize = 32;
const PATTERN_BASE: &str = "^([a-z]{6,})$";
const PATTERN_HEX_STRING: &str = "^(0x)?[a-fA-F0-9]+$";
const DEVICE_TOKEN_HEADER: &str = "Device-Token-iOS";

/// Reserve a lite username and enqueue it for on-chain registration.
#[utoipa::path(
    post,
    path = "/api/v1/usernames",
    tag = "Usernames",
    security(("bearer_jwt" = [])),
    request_body = RegisterRequest,
    responses(
        (status = 202, description = "Reservation accepted into the outbox for on-chain registration. \
          With the registration queue enabled (`QUEUE_ENABLED`) and the queue service live, the claim \
          waits in the balance-priority queue and the body additionally carries \
          `registrationOutcome: \"QUEUED\"` plus the claim's queue standing (poll \
          `GET /api/v1/registration/queue` for updates). A down queue service falls back to the \
          direct registration path (no queue fields). With `REGISTRATION_VOUCHERS_ENABLED`, a valid \
          `lifetimePoUDVoucher` bypasses the device gate and the queue: the reservation goes straight \
          to the writer and the body carries `registrationOutcome: \"INSTANT\"`.",
         body = RegisterResponse,
         example = json!({ "base_username": "tallesx", "digits": "07", "username": "tallesx.07" })),
        (status = 200, description = "The device must pay to register (hard-mode DeviceCheck: free \
            slot already used, or — with the payment lane on — a missing device token). Not an \
            error — a 200 outcome. With `PAYMENT_LANE_ENABLED` the body carries the deposit \
            instructions (`paymentAddress`, `amountRequired` in planck as a string) and the claim \
            is stored; registration proceeds automatically on the confirmed deposit (poll \
            `GET /api/v1/usernames/payment-status`). Lane off: the bare outcome, no payment path.",
         body = serde_json::Value,
         example = json!({ "registrationOutcome": "PAYMENT_REQUIRED",
                           "paymentAddress": "5F...", "amountRequired": "10000000000" })),
        (status = 400, description = "Validation failed (with per-field `fields`), malformed JSON, \
            a `lifetimePoUDVoucher` that is unknown, already used, or expired \
            (`{\"error\": \"Voucher already used\"}` — a voucher failure rejects the claim outright), \
            or — with `WIDEVINE_DEDUP_ENFORCE` — structurally malformed device evidence \
            (`{\"error\": \"DEVICE_EVIDENCE_MALFORMED\"}`: partial fields, bad base64, or wrong \
            field sizes — the specific reason is logged server-side, never returned).",
         body = serde_json::Value,
         example = json!({
             "error": "The request body contains invalid values.",
             "fields": [{ "field": "candidateSignature", "message": "Invalid signature." }]
         })),
        (status = 401, description = "Missing or invalid bearer token, \
            or hard-mode DeviceCheck required a usable Device-Token-iOS and none was present (payment \
            lane off — with `PAYMENT_LANE_ENABLED` a missing token resolves to the 200 \
            PAYMENT_REQUIRED outcome instead).",
         body = serde_json::Value),
        (status = 403, description = "Device evidence failed verification under \
            `WIDEVINE_DEDUP_ENFORCE`: chain policy, the cert-bound evidence hash (challenge / \
            account / deviceId), or a spent challenge. The specific reason is logged \
            server-side, never returned. Retryable once \
            with a fresh challenge; repeated failure surfaces as the paid lane.",
         body = serde_json::Value,
         example = json!({ "error": "DEVICE_EVIDENCE_INVALID", "message": "device evidence invalid" })),
        (status = 409, description = "Preferred digits taken, no digits available, username taken, or \
            the claim carries `dotns.reservedUsername` for a full-person name that is already owned \
            or whose reservation queue is full — checked against the reserved name itself, which \
            `attest` takes as its own argument and which need not be `username`. The runtime checks \
            that leg *before* it writes the lite username, and the consumer signature covers it, so \
            submitting would cost the whole registration and no server-side retry could rescue it. \
            Re-sign for another `dotns.reservedUsername`.",
         body = serde_json::Value,
         example = json!({ "error": "Preferred digits 07 already taken for username tallesx" })),
        (status = 429, description = "Subject rate limit exceeded (with `Retry-After`).",
         body = serde_json::Value),
        (status = 500, description = "Persistence failure or unexpected error.",
         body = serde_json::Value,
         example = json!({ "error": "Failed to persist username registration" })),
        (status = 502, description = "Hard-mode DeviceCheck could not reach Apple to resolve the device.",
         body = serde_json::Value,
         example = json!({ "error": "iOS DeviceCheck verification failed" })),
        (status = 503, description = "The DeviceCheck free slot could not be marked used at Apple after \
            a successful gate (upstream write failure; retryable), or the enforced Widevine dedup gate \
            could not fetch the attestation revocation list (`DEVICE_EVIDENCE_UNAVAILABLE`; retryable).",
         body = serde_json::Value,
         example = json!({ "error": "Failed to mark iOS device as registered with Apple DeviceCheck" }))
    )
)]
pub async fn register(
    State(state): State<AppState>,
    auth: AuthSubject,
    headers: HeaderMap,
    body: Bytes,
) -> UsernamesResult<Response> {
    super::check_rate_limit(&state, &auth.subject)?;
    validate_device_token_header(&headers)?;

    let value = super::parse_json_body(&body)?;
    let mut parsed = validate_register(&value, &state.config)?;

    let base = base_state(&state, &parsed.username).await?;
    if let Some(reserved) = reserved_name(&parsed) {
        let reservation = if reserved == parsed.username {
            base.reservation()
        } else {
            reservation_state(&state, reserved).await?
        };
        if reservation.rejects() {
            return Err(UsernamesError::FullNameUnavailable {
                reserved: reserved.to_string(),
            });
        }
    }
    let digit = select_digit(
        &base.taken,
        parsed.preferred_digits.as_deref(),
        &parsed.username,
    )?;
    let digits = format!("{digit:02}");
    let full_username = format!("{}.{digits}", parsed.username);
    let voucher = parsed.voucher.take();
    let preferred_digits = parsed.preferred_digits.clone();
    let new = build_reservation(&auth, parsed, &digits, &full_username);

    // Voucher precedence (spec order): a submitted
    // voucher resolves the claim before the DeviceCheck/PoUD gate ever runs —
    // a redeemable one registers instantly (no queue, no device bit spent), a
    // bad one rejects the claim outright and never falls through to another
    // lane. Only reachable with `REGISTRATION_VOUCHERS_ENABLED` (validation
    // ignores the field otherwise).
    if let Some(key) = voucher.as_deref() {
        let voucher_state = eligibility::voucher_state(&state.pool, key).await?;
        match eligibility::decide(Some(voucher_state)) {
            Err(reason) => return Err(UsernamesError::Voucher(reason)),
            Ok(eligibility::Lane::Instant) => {}
            // Impossible by the decision table; a 500 (not a panic, not a
            // silent redeem) if a future `decide` change breaks it.
            Ok(eligibility::Lane::Standard) => {
                debug_assert!(false, "a submitted voucher never selects the standard lane");
                return Err(UsernamesError::Internal(anyhow::anyhow!(
                    "eligibility returned the standard lane for a submitted voucher"
                )));
            }
        }
        let id = match eligibility::redeem_and_reserve(&state.pool, key, &new).await {
            Ok(id) => id,
            Err(eligibility::RedeemError::Conflict) => {
                return Err(UsernamesError::UsernameTaken {
                    base: new.base.clone(),
                    digits: digits.clone(),
                })
            }
            Err(eligibility::RedeemError::Voucher(reason)) => {
                return Err(UsernamesError::Voucher(reason))
            }
            Err(eligibility::RedeemError::Db(e)) => {
                tracing::error!(error = ?e, "voucher redeem + reservation insert failed");
                return Err(UsernamesError::PersistenceFailed);
            }
        };
        tracing::info!(id, username = %full_username, "username reserved via voucher (INSTANT)");
        return Ok((
            StatusCode::ACCEPTED,
            Json(RegisterResponse {
                base_username: new.base.clone(),
                digits,
                username: full_username,
                device_check_available: None,
                registration_outcome: Some("INSTANT".to_string()),
                queue: None,
            }),
        )
            .into_response());
    }

    // Spec FR-005: a non-store install routes straight to the payment
    // outcome, without any device-identity check. Only consulted when the
    // payment lane is on — the outcome must be payable, never a dead end —
    // and only a definite `false` verdict routes: `None` (old token, no-op
    // posture) passes while attestation soft mode lasts. Revisit that
    // default together with the `ENFORCE_AUTH` hard flip (attestation plan
    // Phase 5).
    if state.config.payment.is_some() && auth.app_from_official_store == Some(false) {
        return payment_required(&state, &auth, &new, preferred_digits.as_deref()).await;
    }

    // The Android twin of the iOS DeviceCheck gate below.
    let widevine_device = match widevine_gate(&state, &auth, &value).await? {
        WidevineGate::Proceed(device) => device,
        WidevineGate::PaymentRequired => {
            return payment_required(&state, &auth, &new, preferred_digits.as_deref()).await;
        }
    };

    // DeviceCheck is Apple iOS uniqueness, so it gates only iOS requests —
    // identified by the tamper-proof `plt` claim. A "seen device" resolves to a
    // 200 PAYMENT_REQUIRED, never an error. This query only shapes the fast path:
    // the free slot is claimed under a serialized, re-checked advisory lock in
    // `reserve`, so concurrent requests cannot double-spend it.
    let is_ios = auth.platform.as_deref() == Some("ios");
    let (mark_token, device_check_available): (Option<Vec<u8>>, Option<bool>) =
        match state.device_check.as_ref().filter(|_| is_ios) {
            Some(client) => {
                let device_token = device_token_bytes(&headers);
                let verdict = device_check::evaluate(client, device_token.as_deref()).await;
                match device_check::decide_gate(verdict, state.config.enforce_auth) {
                    // "Seen device" is the payment outcome, never an error.
                    Decision::Blocked => {
                        return payment_required(&state, &auth, &new, preferred_digits.as_deref())
                            .await;
                    }
                    // Payment lane on: the spec's "no error codes for
                    // unrecognized device tokens — these simply resolve to
                    // PAYMENT_REQUIRED". Lane off: a 401.
                    Decision::TokenRequired => {
                        return if state.config.payment.is_some() {
                            payment_required(&state, &auth, &new, preferred_digits.as_deref()).await
                        } else {
                            Err(UsernamesError::DeviceTokenRequired)
                        };
                    }
                    Decision::Unavailable(cause) => {
                        tracing::warn!(cause, "DeviceCheck unavailable (hard mode)");
                        return Err(UsernamesError::DeviceCheckUnavailable);
                    }
                    Decision::Register => (
                        Some(device_token.expect("Available verdict implies a device token")),
                        Some(true),
                    ),
                    Decision::Proceed { available } => (None, available),
                }
            }
            None => (None, None),
        };

    // Queue intake waits as `QUEUED` (the spec's PoUD-pass lane, the only
    // lane until the attestation slice). The flag alone selects the lane:
    // the queue is the throughput control for free registrations, so a dead
    // (or never-deployed) advancer parks claims durably behind the throttle
    // — drained in fair order when it returns — instead of silently
    // reopening the unthrottled direct path.
    let queue_lane = state.config.queue_enabled;
    let group = if queue_lane {
        Some(queue::intake_group(&state.chain, &auth.subject).await)
    } else {
        None
    };

    match reserve(
        &state,
        &new,
        mark_token.as_deref(),
        group,
        widevine_device.as_ref(),
    )
    .await?
    {
        ReserveOutcome::Reserved(id) => {
            tracing::info!(id, username = %full_username, queued = queue_lane, "username reserved");

            // The row is durably queued at this point, so a failed standing
            // read only degrades the response (no `queue` data), never the
            // claim itself.
            let queue = match group {
                Some(group) => match queue::queued_snapshot(&state.pool).await {
                    Ok(snapshot) => queue::drain_estimate(&snapshot, id).map(|estimate| {
                        queue::QueueStatusResponse {
                            queue_position: estimate.position,
                            group,
                            estimated_iterations_remaining: estimate.iterations,
                        }
                    }),
                    Err(e) => {
                        tracing::warn!(id, error = %e, "queue standing read failed after enqueue");
                        None
                    }
                },
                None => None,
            };

            Ok((
                StatusCode::ACCEPTED,
                Json(RegisterResponse {
                    base_username: new.base.clone(),
                    digits,
                    username: full_username,
                    device_check_available,
                    registration_outcome: queue_lane.then(|| "QUEUED".to_string()),
                    queue,
                }),
            )
                .into_response())
        }
        // Lost the claim race: a concurrent request took this device's free
        // slot. Same outcome as `Blocked` — a 200, never an error.
        ReserveOutcome::DeviceAlreadyClaimed => {
            payment_required(&state, &auth, &new, preferred_digits.as_deref()).await
        }
    }
}

/// The PAYMENT_REQUIRED outcome. Lane off (`PAYMENT_LANE_ENABLED=false`):
/// the bare body — a dead end, pinned by the parked
/// `register-200-devicecheck-payment-required` fixture. Lane on: mint (or
/// return) the subject's durable quote — the spec's deposit instructions;
/// the Phase-3 watcher registers the stored claim once the deposit lands.
async fn payment_required(
    state: &AppState,
    auth: &AuthSubject,
    new: &NewReservation,
    preferred_digits: Option<&str>,
) -> UsernamesResult<Response> {
    let Some(config) = state.config.payment.as_ref() else {
        return Ok((
            StatusCode::OK,
            Json(serde_json::json!({ "registrationOutcome": "PAYMENT_REQUIRED" })),
        )
            .into_response());
    };
    let payload = payment::ClaimPayload::from_reservation(new, preferred_digits);
    let quote = payment::quote(&state.pool, config, &auth.subject, &payload)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "payment quote failed");
            UsernamesError::PersistenceFailed
        })?;
    tracing::info!(
        subject = %auth.subject,
        base = %new.base,
        address = %quote.payment_address,
        "payment quote issued"
    );
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "registrationOutcome": "PAYMENT_REQUIRED",
            "paymentAddress": quote.payment_address,
            // Planck as a string, pending the client-team unit ruling
            // recorded in the plan.
            "amountRequired": quote.amount_planck.to_string(),
        })),
    )
        .into_response())
}
/// Advisory-lock key serializing hard-mode free-iOS DeviceCheck claims across
/// replicas (device-attestation database namespace).
const FREE_IOS_CLAIM_LOCK_KEY: i64 = 0x1DEA_DC01;

/// Outcome of the Widevine gate for this claim.
enum WidevineGate {
    /// Proceed on the standard lane; `Some` carries the device record to
    /// reserve atomically with the claim (enforced mode, unseen device).
    Proceed(Option<crate::widevine::store::PendingDevice>),
    /// Route to the payment outcome: seen device, or an enforced Android
    /// claim without acceptable evidence.
    PaymentRequired,
}

/// Evaluate the Widevine device evidence for this claim (wire spec v1).
///
/// Gate off: the evidence fields are ignored. Soft mode: verdicts are logged
/// and routing never changes. Enforced: malformed evidence is a 400, invalid
/// evidence a 403, a seen device or an evidence-less Android claim the payment
/// outcome, and an unseen device proceeds carrying its `PENDING` record.
///
/// The challenge is consumed only after evidence fully verifies, so malformed
/// evidence cannot burn one and a CRL outage stays retryable. The challenge is
/// the whole gate's freshness boundary — the evidence carries no lifetime.
async fn widevine_gate(
    state: &AppState,
    auth: &AuthSubject,
    body: &Value,
) -> UsernamesResult<WidevineGate> {
    use crate::widevine;

    let Some(cfg) = state.config.widevine.as_ref() else {
        return Ok(WidevineGate::Proceed(None));
    };
    let enforce = cfg.enforce;
    // Every reject logs its verdict in both modes. The response carries only
    // the error code, so this log is the one place the reason survives.
    let reject = |verdict: widevine::EvidenceError| -> UsernamesResult<WidevineGate> {
        tracing::warn!(verdict = %verdict, enforced = enforce, "widevine evidence rejected");
        if enforce {
            return Err(verdict.into());
        }
        Ok(WidevineGate::Proceed(None))
    };

    let raw = match widevine::extract(body) {
        Ok(raw) => raw,
        Err(verdict) => return reject(verdict),
    };
    let Some(raw) = raw else {
        // No evidence. Enforced mode routes Android claims to the paid lane;
        // other platforms have their own gates (iOS: DeviceCheck above).
        if enforce && auth.platform.as_deref() == Some("android") {
            return Ok(WidevineGate::PaymentRequired);
        }
        return Ok(WidevineGate::Proceed(None));
    };

    // CRL unavailability is infrastructure, not a device failure: enforced
    // mode surfaces a 503 "retry" rather than a spurious integrity reject.
    let revoked_serials = match state.crl.revoked_serials().await {
        Ok(serials) => serials,
        Err(e) if enforce => {
            tracing::warn!(error = %e, "attestation CRL unavailable (widevine enforced mode)");
            return Err(UsernamesError::DeviceEvidenceUnavailable);
        }
        Err(e) => {
            tracing::warn!(error = %e, "attestation CRL unavailable (widevine soft mode, request allowed)");
            return Ok(WidevineGate::Proceed(None));
        }
    };

    // The JWT subject is this issuer's `0x`-hex sr25519 account key — it is
    // folded into the cert-bound evidence hash as the candidate, so evidence
    // can never be relayed under another account's token.
    let subject_pubkey: Option<[u8; 32]> = auth
        .subject
        .strip_prefix("0x")
        .and_then(|raw| hex::decode(raw).ok())
        .and_then(|bytes| bytes.try_into().ok());
    let Some(subject_pubkey) = subject_pubkey else {
        return reject(widevine::EvidenceError::Invalid(
            "JWT subject is not a 32-byte account key".to_string(),
        ));
    };

    let params = widevine::VerifyParams {
        config: &state.config,
        widevine: cfg,
        revoked_serials: &revoked_serials,
        subject_pubkey: &subject_pubkey,
        now_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
    };
    let verified = match widevine::verify(&raw, &params) {
        Ok(verified) => verified,
        Err(verdict) => return reject(verdict),
    };

    // Single-use: the evidence challenge is consumed in soft mode too, so a
    // replayed claim already logs (and later enforces) as spent. Infrastructure
    // failures stay observational in soft mode instead of blocking the claim.
    let challenge_consumed = match crate::auth::challenge::consume(&state.pool, &verified.challenge)
        .await
    {
        Ok(consumed) => consumed,
        Err(e) if enforce => return Err(e.into()),
        Err(e) => {
            tracing::warn!(error = %e, "widevine challenge consume failed (soft mode, request allowed)");
            return Ok(WidevineGate::Proceed(None));
        }
    };
    if !challenge_consumed {
        return reject(widevine::EvidenceError::Invalid(
            "evidence challenge is unknown, spent, or expired".to_string(),
        ));
    }

    let seen = match widevine::store::seen(&state.pool, &verified.hmac).await {
        Ok(seen) => seen,
        Err(e) if enforce => return Err(e.into()),
        Err(e) => {
            tracing::warn!(error = %e, "widevine device lookup failed (soft mode, request allowed)");
            return Ok(WidevineGate::Proceed(None));
        }
    };

    if !enforce {
        tracing::info!(
            seen,
            "widevine dedup verdict (soft mode, routing unchanged)"
        );
        return Ok(WidevineGate::Proceed(None));
    }
    if seen {
        return Ok(WidevineGate::PaymentRequired);
    }
    Ok(WidevineGate::Proceed(Some(
        crate::widevine::store::PendingDevice {
            hmac: verified.hmac,
        },
    )))
}

/// Outcome of [`reserve`]. `DeviceAlreadyClaimed` arises when a concurrent
/// request won a device race first: the serialized free-iOS claim (DeviceCheck
/// lock), or the Widevine device-record unique key.
enum ReserveOutcome {
    Reserved(i64),
    DeviceAlreadyClaimed,
}

/// Persist the reservation.
///
/// Without a `mark_token` or `widevine_device` it is a plain insert.
///
/// With a `widevine_device` (an enforced-mode fresh Android device) the device
/// record is reserved `PENDING` in the same transaction as the claim: the
/// unique `device_hmac` key is the race arbiter, so a concurrent claim
/// for the same physical device yields `DeviceAlreadyClaimed` (mapped to a 200
/// PAYMENT_REQUIRED) instead of a second free registration.
///
/// With a `mark_token` (a hard-mode fresh iOS device) the whole claim is
/// serialized under a transaction-scoped advisory lock, and Apple is re-queried
/// *under* that lock — the gate's earlier query is already stale, so this
/// re-check is what closes the TOCTOU. The row is inserted before the slot is
/// marked, so an insert failure never reaches Apple and an Apple rejection
/// rolls back.
///
/// Not fully atomic: a DB commit failure after a successful mark consumes the
/// slot without a reservation. That fails safe — the device never gains an
/// extra free registration.
///
/// The two device gates are platform-disjoint (`mark_token` is iOS-only,
/// `widevine_device` Android-only), so at most one branch runs.
async fn reserve(
    state: &AppState,
    new: &NewReservation,
    mark_token: Option<&[u8]>,
    queue_group: Option<u8>,
    widevine_device: Option<&crate::widevine::store::PendingDevice>,
) -> UsernamesResult<ReserveOutcome> {
    let conflict = || UsernamesError::UsernameTaken {
        base: new.base.clone(),
        digits: new.digits.clone(),
    };

    if let Some(device) = widevine_device {
        let mut tx = state.pool.begin().await.map_err(|e| {
            tracing::error!(error = ?e, "begin reservation transaction failed");
            UsernamesError::PersistenceFailed
        })?;
        let id = match insert_reservation(&mut *tx, new, queue_group).await {
            Ok(id) => id,
            Err(InsertError::Conflict) => return Err(conflict()),
            Err(InsertError::Db(e)) => {
                tracing::error!(error = ?e, "reservation outbox insert failed");
                return Err(UsernamesError::PersistenceFailed);
            }
        };
        // The atomic reserve: the device record commits or rolls back with
        // the claim itself, so a crash between the two is impossible.
        match crate::widevine::store::insert_pending(&mut *tx, device, id).await {
            Ok(()) => {}
            Err(crate::widevine::store::InsertDeviceError::Seen) => {
                return Ok(ReserveOutcome::DeviceAlreadyClaimed);
            }
            Err(crate::widevine::store::InsertDeviceError::Db(e)) => {
                tracing::error!(error = ?e, "widevine device record insert failed");
                return Err(UsernamesError::PersistenceFailed);
            }
        }
        tx.commit().await.map_err(|e| {
            tracing::error!(error = ?e, "commit reservation transaction failed");
            UsernamesError::PersistenceFailed
        })?;
        return Ok(ReserveOutcome::Reserved(id));
    }

    let Some(token) = mark_token else {
        return match insert_reservation(&state.pool, new, queue_group).await {
            Ok(id) => Ok(ReserveOutcome::Reserved(id)),
            Err(InsertError::Conflict) => Err(conflict()),
            Err(InsertError::Db(e)) => {
                tracing::error!(error = ?e, "reservation outbox insert failed");
                Err(UsernamesError::PersistenceFailed)
            }
        };
    };

    let client = state
        .device_check
        .as_ref()
        .expect("a mark token implies DeviceCheck is enabled");
    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!(error = ?e, "begin reservation transaction failed");
        UsernamesError::PersistenceFailed
    })?;

    // Serialize all hard-mode free-iOS claims: an xact-scoped advisory lock held
    // until commit/rollback, so at most one claim runs this critical section at
    // a time (safe across replicas).
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(FREE_IOS_CLAIM_LOCK_KEY)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "acquiring DeviceCheck claim lock failed");
            UsernamesError::PersistenceFailed
        })?;

    // Authoritative re-check under the lock. The gate's pre-transaction query is
    // stale here; this re-read is what prevents a concurrent double-spend.
    match client.already_used(token).await {
        Ok(true) => {
            if let Err(rb) = tx.rollback().await {
                tracing::error!(error = ?rb, "rollback after lost claim race failed");
            }
            return Ok(ReserveOutcome::DeviceAlreadyClaimed);
        }
        Ok(false) => {}
        Err(err) => {
            tracing::warn!(error = %err, "DeviceCheck re-query under lock failed (hard mode)");
            if let Err(rb) = tx.rollback().await {
                tracing::error!(error = ?rb, "rollback after DeviceCheck re-query failure failed");
            }
            return Err(UsernamesError::DeviceCheckUnavailable);
        }
    }

    // Insert first: an insert failure leaves the transaction untouched and
    // never marks the device, so the slot is preserved.
    let id = match insert_reservation(&mut *tx, new, queue_group).await {
        Ok(id) => id,
        Err(InsertError::Conflict) => return Err(conflict()),
        Err(InsertError::Db(e)) => {
            tracing::error!(error = ?e, "reservation outbox insert failed");
            return Err(UsernamesError::PersistenceFailed);
        }
    };

    // Mark the free slot used only after the row exists; roll back if Apple
    // rejects so the slot is never consumed without a durable reservation.
    if let Err(err) = client.register_device(token).await {
        tracing::error!(error = %err, "DeviceCheck register_device failed; rolling back reservation");
        if let Err(rb) = tx.rollback().await {
            tracing::error!(error = ?rb, "reservation rollback failed after DeviceCheck failure");
        }
        return Err(UsernamesError::DeviceRegistrationFailed);
    }

    tx.commit().await.map_err(|e| {
        tracing::error!(error = ?e, "commit reservation transaction failed");
        UsernamesError::PersistenceFailed
    })?;
    Ok(ReserveOutcome::Reserved(id))
}

/// Insert the outbox row on either intake lane: `QUEUED` with its priority
/// group when the queue lane is on, plain `RESERVED` otherwise. Generic over
/// the executor so it runs on the pool or inside the DeviceCheck transaction.
async fn insert_reservation<'e, E>(
    executor: E,
    new: &NewReservation,
    queue_group: Option<u8>,
) -> Result<i64, InsertError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    match queue_group {
        Some(group) => outbox::insert_queued(executor, new, i32::from(group)).await,
        None => outbox::insert(executor, new).await,
    }
}

/// The fully-validated registration request, with hex fields decoded.
struct ParsedRegister {
    candidate_account_id: String,
    username: String,
    preferred_digits: Option<String>,
    candidate_signature: Vec<u8>,
    ring_vrf_key: Vec<u8>,
    proof_of_ownership: Vec<u8>,
    consumer_registration_signature: Vec<u8>,
    identifier_key: Vec<u8>,
    /// `lifetimePoUDVoucher`, populated only when
    /// `REGISTRATION_VOUCHERS_ENABLED` (the wire ignores the field).
    voucher: Option<String>,
    dotns: Option<ParsedDotns>,
}

/// Assemble the outbox row from the validated request (shared by the voucher
/// INSTANT path and the standard gate/queue path).
fn build_reservation(
    auth: &AuthSubject,
    parsed: ParsedRegister,
    digits: &str,
    full_username: &str,
) -> NewReservation {
    NewReservation {
        account_id: auth.subject.clone(),
        candidate_account_id: parsed.candidate_account_id,
        base: parsed.username,
        digits: digits.to_string(),
        full_username: full_username.to_string(),
        candidate_signature: parsed.candidate_signature,
        ring_vrf_key: parsed.ring_vrf_key,
        proof_of_ownership: parsed.proof_of_ownership,
        consumer_registration_signature: parsed.consumer_registration_signature,
        identifier_key: parsed.identifier_key,
        dotns_signature: parsed.dotns.as_ref().map(|d| d.signature.clone()),
        dotns_signed_at: parsed.dotns.as_ref().map(|d| d.signed_at),
        reserved_username: parsed.dotns.and_then(|d| d.reserved_username),
    }
}

struct ParsedDotns {
    signature: Vec<u8>,
    signed_at: i64,
    reserved_username: Option<String>,
}

/// The full-person name this claim asks to reserve, if it asks for one.
fn reserved_name(parsed: &ParsedRegister) -> Option<&str> {
    parsed.dotns.as_ref()?.reserved_username.as_deref()
}

/// Validate `Device-Token-iOS`: base64, when present.
fn validate_device_token_header(headers: &HeaderMap) -> UsernamesResult<()> {
    let Some(raw) = headers.get(DEVICE_TOKEN_HEADER) else {
        return Ok(());
    };
    let valid = raw.to_str().is_ok_and(is_base64);
    if valid {
        return Ok(());
    }
    Err(UsernamesError::InvalidHeader(vec![FieldError {
        message: "Invalid base64-encoded string".to_string(),
        field: DEVICE_TOKEN_HEADER.to_string(),
    }]))
}

/// Decode the (already shape-validated) `Device-Token-iOS` header to raw
/// bytes for the DeviceCheck query. Absent or empty → `None` (an empty header
/// value counts as no token / `DeviceCheckInactive`).
fn device_token_bytes(headers: &HeaderMap) -> Option<Vec<u8>> {
    let raw = headers.get(DEVICE_TOKEN_HEADER)?.to_str().ok()?;
    if raw.is_empty() {
        return None;
    }
    base64::engine::general_purpose::STANDARD.decode(raw).ok()
}

/// The base64 rule: empty, or padded groups of four.
fn is_base64(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if !value.len().is_multiple_of(4) {
        return false;
    }
    let core = value.trim_end_matches('=');
    value.len() - core.len() <= 2
        && core
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Validate the raw body (see module docs for the three-phase semantics).
fn validate_register(
    value: &Value,
    config: &crate::config::Config,
) -> Result<ParsedRegister, UsernamesError> {
    let mut errors: Vec<FieldError> = Vec::new();
    let object = value.as_object();

    let get = |field: &str| object.and_then(|o| o.get(field));

    // A required string field: missing / non-string is a type error.
    let required_string = |errors: &mut Vec<FieldError>, field: &str| -> Option<String> {
        match get(field) {
            Some(Value::String(s)) => Some(s.clone()),
            other => {
                errors.push(FieldError {
                    message: http_common::error::expected(
                        "string",
                        http_common::error::received_name(other),
                    ),
                    field: field.to_string(),
                });
                None
            }
        }
    };

    let mut refine_skipped = false;

    // --- field phase, in field order ------------------------------------
    let candidate_account_id = required_string(&mut errors, "candidateAccountId");
    if candidate_account_id.is_none() {
        refine_skipped = true;
    }

    let username = required_string(&mut errors, "username");
    match &username {
        None => refine_skipped = true,
        Some(name) => {
            if !(name.len() >= 6 && name.bytes().all(|b| b.is_ascii_lowercase())) {
                errors.push(FieldError {
                    message: http_common::error::must_match(PATTERN_BASE),
                    field: "username".to_string(),
                });
                refine_skipped = true;
            }
        }
    }

    let preferred_digits = match get("preferredDigits") {
        None => None,
        Some(Value::String(s)) => {
            if !is_preferred_digits(s) {
                errors.push(FieldError {
                    message: MSG_DIGITS.to_string(),
                    field: "preferredDigits".to_string(),
                });
            }
            Some(s.clone())
        }
        Some(other) => {
            errors.push(FieldError {
                message: http_common::error::expected(
                    "string",
                    http_common::error::type_name(other),
                ),
                field: "preferredDigits".to_string(),
            });
            refine_skipped = true;
            None
        }
    };

    // `0x`-prefixed exact-length hex fields (no abort): a failed check still
    // lets the refinement run, which then skips the verifier.
    let fixed_hex = |errors: &mut Vec<FieldError>,
                     refine_skipped: &mut bool,
                     field: &str,
                     hex_digits: usize,
                     message: &str|
     -> (Option<String>, bool) {
        match get(field) {
            Some(Value::String(s)) => {
                let ok = is_prefixed_hex(s, hex_digits);
                if !ok {
                    errors.push(FieldError {
                        message: message.to_string(),
                        field: field.to_string(),
                    });
                }
                (Some(s.clone()), ok)
            }
            other => {
                errors.push(FieldError {
                    message: http_common::error::expected(
                        "string",
                        http_common::error::received_name(other),
                    ),
                    field: field.to_string(),
                });
                *refine_skipped = true;
                (None, false)
            }
        }
    };

    let (candidate_signature_raw, candidate_signature_ok) = fixed_hex(
        &mut errors,
        &mut refine_skipped,
        "candidateSignature",
        128,
        MSG_HEX_64,
    );

    let ring_vrf_key = match get("ringVrfKey") {
        Some(Value::String(s)) => {
            let stripped = s.strip_prefix("0x").unwrap_or(s);
            if stripped.is_empty() || !stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
                errors.push(FieldError {
                    message: http_common::error::must_match(PATTERN_HEX_STRING),
                    field: "ringVrfKey".to_string(),
                });
                refine_skipped = true;
                None
            } else {
                Some(s.clone())
            }
        }
        other => {
            errors.push(FieldError {
                message: http_common::error::expected(
                    "string",
                    http_common::error::received_name(other),
                ),
                field: "ringVrfKey".to_string(),
            });
            refine_skipped = true;
            None
        }
    };

    let (proof_of_ownership_raw, _) = fixed_hex(
        &mut errors,
        &mut refine_skipped,
        "proofOfOwnership",
        128,
        MSG_HEX_64,
    );
    let (consumer_registration_signature_raw, _) = fixed_hex(
        &mut errors,
        &mut refine_skipped,
        "consumerRegistrationSignature",
        128,
        MSG_HEX_64,
    );
    let (identifier_key_raw, _) = fixed_hex(
        &mut errors,
        &mut refine_skipped,
        "identifierKey",
        130,
        MSG_HEX_65,
    );

    let dotns = match get("dotns") {
        None => None,
        Some(Value::Object(block)) => {
            let mut signature = None;
            match block.get("signature") {
                Some(Value::String(s)) => {
                    if is_prefixed_hex(s, 128) {
                        signature = Some(s.clone());
                    } else {
                        errors.push(FieldError {
                            message: MSG_HEX_64.to_string(),
                            field: "dotns.signature".to_string(),
                        });
                    }
                }
                other => {
                    errors.push(FieldError {
                        message: http_common::error::expected(
                            "string",
                            http_common::error::received_name(other),
                        ),
                        field: "dotns.signature".to_string(),
                    });
                    refine_skipped = true;
                }
            }
            let signed_at = match block.get("signedAt") {
                Some(Value::Number(n)) => match n.as_f64() {
                    Some(f) if f.fract() == 0.0 && f >= 0.0 => Some(f as i64),
                    Some(f) if f.fract() != 0.0 => {
                        errors.push(FieldError {
                            message: http_common::error::expected("integer", "number"),
                            field: "dotns.signedAt".to_string(),
                        });
                        refine_skipped = true;
                        None
                    }
                    _ => {
                        errors.push(FieldError {
                            message: "must be greater than or equal to 0".to_string(),
                            field: "dotns.signedAt".to_string(),
                        });
                        refine_skipped = true;
                        None
                    }
                },
                other => {
                    errors.push(FieldError {
                        message: http_common::error::expected(
                            "number",
                            http_common::error::received_name(other),
                        ),
                        field: "dotns.signedAt".to_string(),
                    });
                    refine_skipped = true;
                    None
                }
            };
            let reserved_username = match block.get("reservedUsername") {
                None => None,
                Some(Value::String(s)) => {
                    if s.len() >= 6 && s.bytes().all(|b| b.is_ascii_lowercase()) {
                        Some(s.clone())
                    } else {
                        errors.push(FieldError {
                            message: http_common::error::must_match(PATTERN_BASE),
                            field: "dotns.reservedUsername".to_string(),
                        });
                        refine_skipped = true;
                        None
                    }
                }
                Some(other) => {
                    errors.push(FieldError {
                        message: http_common::error::expected(
                            "string",
                            http_common::error::type_name(other),
                        ),
                        field: "dotns.reservedUsername".to_string(),
                    });
                    refine_skipped = true;
                    None
                }
            };
            Some((signature, signed_at, reserved_username))
        }
        Some(other) => {
            errors.push(FieldError {
                message: http_common::error::expected(
                    "object",
                    http_common::error::type_name(other),
                ),
                field: "dotns".to_string(),
            });
            refine_skipped = true;
            None
        }
    };

    // `lifetimePoUDVoucher` (the INSTANT lane): only recognised when the
    // voucher feature is on — the wire ignores unknown body fields, so
    // flag-off requests carrying it validate exactly as before. An empty
    // string is treated as absent (the Device-Token-iOS precedent).
    let voucher = if config.registration_vouchers_enabled {
        match get("lifetimePoUDVoucher") {
            None => None,
            Some(Value::String(s)) if s.is_empty() => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(other) => {
                errors.push(FieldError {
                    message: http_common::error::expected(
                        "string",
                        http_common::error::type_name(other),
                    ),
                    field: "lifetimePoUDVoucher".to_string(),
                });
                refine_skipped = true;
                None
            }
        }
    } else {
        None
    };

    // --- refinement phase ----------------------------------------------
    if !refine_skipped {
        let account_id = candidate_account_id.as_deref().unwrap_or_default();
        match subxt::utils::AccountId32::from_str(account_id) {
            Err(_) => errors.push(FieldError {
                message: MSG_INVALID_SS58.to_string(),
                field: "candidateAccountId".to_string(),
            }),
            Ok(candidate) => {
                // A pattern-failed candidateSignature already carries its
                // 400 field error from the check phase; the verifier is
                // skipped rather than fed a malformed string.
                if candidate_signature_ok {
                    let signature = decode_prefixed_hex(candidate_signature_raw.as_deref());
                    let ring = decode_prefixed_hex(ring_vrf_key.as_deref());
                    if !verify_candidate_signature(&candidate.0, &signature, &ring) {
                        errors.push(FieldError {
                            message: MSG_INVALID_SIGNATURE.to_string(),
                            field: "candidateSignature".to_string(),
                        });
                    }
                }
            }
        }

        if let Some(name) = &username {
            if name.len() > MAX_BASE_LEN {
                errors.push(FieldError {
                    message: format!("Username sum exceeds the maximum length: ({MAX_BASE_LEN})."),
                    field: "username".to_string(),
                });
            }
        }

        if let Some((_signature, signed_at, reserved_username)) = &dotns {
            if !config.dotns_gateway_enabled {
                errors.push(FieldError {
                    message: MSG_DOTNS_DISABLED.to_string(),
                    field: "dotns".to_string(),
                });
            } else {
                if let Some(signed_at) = signed_at {
                    let now = time::OffsetDateTime::now_utc().unix_timestamp();
                    let skew = config.dotns_max_future_skew_secs as i64;
                    let max_age = config.dotns_intake_freshness_max_age_secs as i64;
                    if *signed_at > now + skew {
                        errors.push(FieldError {
                            message: format!("signedAt is in the future (tolerance {skew}s)."),
                            field: "dotns.signedAt".to_string(),
                        });
                    }
                    if now - signed_at > max_age {
                        errors.push(FieldError {
                            message: format!(
                                "signedAt is older than the intake freshness bound ({max_age}s). \
                                 Re-sign with a fresh timestamp and resubmit."
                            ),
                            field: "dotns.signedAt".to_string(),
                        });
                    }
                }

                // `reservedUsername` is relayed verbatim into `reserve_name`'s
                // `Option<BaseLabel>`, a `BoundedVec<u8, 32>`. A longer value
                // makes the extrinsic unbuildable. Rejecting it here rather
                // than letting the writer discover it.
                if let Some(reserved) = reserved_username {
                    if reserved.len() > MAX_DOTNS_LABEL_LEN {
                        errors.push(FieldError {
                            message: format!(
                                "reservedUsername exceeds the maximum label length: \
                                 ({MAX_DOTNS_LABEL_LEN})."
                            ),
                            field: "dotns.reservedUsername".to_string(),
                        });
                    }
                }

                // The reservation signature is deliberately **not** verified here, and an
                // unverifiable one is deliberately not a 400.
                //
                // The dotNS half is optional and independent — `ASSIGNED` +
                // `DOTNS_FAILED_TERMINAL` is a legitimate resting state — so rejecting would
                // cost the caller its People username over the optional half. The writer runs
                // `check_dotns_submittable` before spending an extrinsic either way.
                //
                // The gates above stay 400s: they reject *malformed* blocks, not unverifiable
                // signatures.
            }
        }
    }

    if !errors.is_empty() {
        return Err(UsernamesError::InvalidBody(errors));
    }

    Ok(ParsedRegister {
        candidate_account_id: candidate_account_id.unwrap_or_default(),
        username: username.unwrap_or_default(),
        preferred_digits,
        candidate_signature: decode_prefixed_hex(candidate_signature_raw.as_deref()),
        ring_vrf_key: decode_prefixed_hex(ring_vrf_key.as_deref()),
        proof_of_ownership: decode_prefixed_hex(proof_of_ownership_raw.as_deref()),
        consumer_registration_signature: decode_prefixed_hex(
            consumer_registration_signature_raw.as_deref(),
        ),
        identifier_key: decode_prefixed_hex(identifier_key_raw.as_deref()),
        voucher,
        dotns: dotns.map(|(signature, signed_at, reserved_username)| ParsedDotns {
            signature: decode_prefixed_hex(signature.as_deref()),
            signed_at: signed_at.unwrap_or_default(),
            reserved_username,
        }),
    })
}

/// `^0x[a-fA-F0-9]{n}$`.
fn is_prefixed_hex(value: &str, hex_digits: usize) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|rest| rest.len() == hex_digits && rest.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `^(0[1-9]|[1-9][0-9])$`.
fn is_preferred_digits(value: &str) -> bool {
    matches!(
        value.as_bytes(),
        [b'0', b'1'..=b'9'] | [b'1'..=b'9', b'0'..=b'9']
    )
}

/// Decode a validated `0x`-optional hex string (empty on `None`).
fn decode_prefixed_hex(value: Option<&str>) -> Vec<u8> {
    let value = value.unwrap_or_default();
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).unwrap_or_default()
}

/// The message prefix the People Chain reconstructs for `PeopleLite.attest`;
/// `candidateSignature` (and `proofOfOwnership`) cover
/// `POP_REGISTER_PREFIX || candidatePubkey || ringVrfKey`.
const POP_REGISTER_PREFIX: &[u8] = b"pop:people-lite:register using";

/// Verifies the caller controls `candidate_pubkey`.
///
/// The candidate's sr25519 key must have signed
/// `POP_REGISTER_PREFIX || candidatePubkey || ringVrfKey`. Uses `subxt_signer`
/// (schnorrkel with the Substrate signing context). Symmetric with the shipping
/// Polkadot wallets and the on-chain verifier.
fn verify_candidate_signature(
    candidate_pubkey: &[u8; 32],
    candidate_signature: &[u8],
    ring_vrf_key: &[u8],
) -> bool {
    let Ok(signature) = <[u8; 64]>::try_from(candidate_signature) else {
        return false;
    };
    let mut message = Vec::with_capacity(POP_REGISTER_PREFIX.len() + 32 + ring_vrf_key.len());
    message.extend_from_slice(POP_REGISTER_PREFIX);
    message.extend_from_slice(candidate_pubkey);
    message.extend_from_slice(ring_vrf_key);
    subxt_signer::sr25519::verify(
        &subxt_signer::sr25519::Signature(signature),
        message,
        &subxt_signer::sr25519::PublicKey(*candidate_pubkey),
    )
}

/// Choose the discriminator: the preferred one if free, else a random free
/// one. The pool is `01..=99` (`00` is never offered). The preferred string
/// is regex-validated before this point.
fn select_digit(taken: &BTreeSet<u8>, preferred: Option<&str>, base: &str) -> UsernamesResult<u8> {
    match preferred {
        Some(p) => {
            let d: u8 = p.parse().map_err(|_| {
                UsernamesError::Internal(anyhow::anyhow!("preferredDigits validated upstream"))
            })?;
            if taken.contains(&d) {
                return Err(UsernamesError::PreferredDigitsTaken {
                    digits: p.to_string(),
                    base: base.to_string(),
                });
            }
            Ok(d)
        }
        None => {
            let available = available_digits(taken);
            available
                .choose(&mut OsRng)
                .copied()
                .ok_or_else(|| UsernamesError::NoDigitsAvailable {
                    base: base.to_string(),
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> crate::config::Config {
        crate::config::Config::test_default()
    }

    fn valid_body() -> serde_json::Value {
        use std::str::FromStr as _;
        use subxt_signer::sr25519::Keypair;
        use subxt_signer::SecretUri;

        let keypair = Keypair::from_uri(&SecretUri::from_str("//Alice").unwrap()).unwrap();
        let candidate = keypair.public_key();
        let ring = [7u8; 32];
        let mut message = Vec::new();
        message.extend_from_slice(POP_REGISTER_PREFIX);
        message.extend_from_slice(&candidate.0);
        message.extend_from_slice(&ring);
        let signature = keypair.sign(&message).0;

        json!({
            "candidateAccountId": candidate.to_account_id().to_string(),
            "username": "aliceuser",
            "candidateSignature": format!("0x{}", hex::encode(signature)),
            "ringVrfKey": format!("0x{}", hex::encode(ring)),
            "proofOfOwnership": format!("0x{}", "03".repeat(64)),
            "consumerRegistrationSignature": format!("0x{}", "04".repeat(64)),
            "identifierKey": format!("0x{}", "05".repeat(65))
        })
    }

    fn errors_of(value: serde_json::Value) -> Vec<(String, String)> {
        match validate_register(&value, &config()) {
            Err(UsernamesError::InvalidBody(errors)) => {
                errors.into_iter().map(|e| (e.field, e.message)).collect()
            }
            other => panic!("expected InvalidBody, got {other:?}", other = other.err()),
        }
    }

    #[test]
    fn accepts_a_genuinely_signed_request() {
        let parsed = validate_register(&valid_body(), &config()).expect("valid");
        assert_eq!(parsed.username, "aliceuser");
        assert_eq!(parsed.candidate_signature.len(), 64);
    }

    #[test]
    fn empty_object_reports_every_required_field_in_order() {
        let pointers: Vec<String> = errors_of(json!({}))
            .into_iter()
            .map(|(pointer, _)| pointer)
            .collect();
        assert_eq!(
            pointers,
            [
                "candidateAccountId",
                "username",
                "candidateSignature",
                "ringVrfKey",
                "proofOfOwnership",
                "consumerRegistrationSignature",
                "identifierKey",
            ]
        );
    }

    #[test]
    fn wrong_signature_is_a_400_with_the_captured_message() {
        let mut body = valid_body();
        body["candidateSignature"] = json!(format!("0x{}", "ab".repeat(64)));
        assert_eq!(
            errors_of(body),
            [(
                "candidateSignature".to_string(),
                "Invalid signature.".to_string()
            )]
        );
    }

    #[test]
    fn pattern_failed_signature_is_a_400() {
        for bad in ["nothex", &format!("0x{}", "ab".repeat(63))] {
            let mut body = valid_body();
            body["candidateSignature"] = json!(bad);
            assert_eq!(
                errors_of(body),
                [("candidateSignature".to_string(), MSG_HEX_64.to_string())],
                "{bad}"
            );
        }
    }

    #[test]
    fn abort_fields_suppress_the_refinement() {
        let mut body = valid_body();
        body["ringVrfKey"] = json!("nothex!");
        assert_eq!(
            errors_of(body),
            [(
                "ringVrfKey".to_string(),
                http_common::error::must_match(PATTERN_HEX_STRING)
            )]
        );

        let mut body = valid_body();
        body["username"] = json!("Abcdef");
        assert_eq!(
            errors_of(body),
            [(
                "username".to_string(),
                http_common::error::must_match(PATTERN_BASE)
            )]
        );
    }

    #[test]
    fn type_errors_suppress_the_refinement() {
        let body = json!({
            "candidateAccountId": 5, "username": 6, "candidateSignature": 7,
            "ringVrfKey": 8, "proofOfOwnership": 9,
            "consumerRegistrationSignature": 10, "identifierKey": 11
        });
        let errors = errors_of(body);
        assert_eq!(errors.len(), 7);
        assert!(errors
            .iter()
            .all(|(_, detail)| detail == "expected string, received number"));
    }

    #[test]
    fn refinement_issues_use_the_captured_messages() {
        let mut body = valid_body();
        body["candidateAccountId"] = json!("not-an-address");
        assert_eq!(
            errors_of(body),
            [(
                "candidateAccountId".to_string(),
                "Invalid ss58 address.".to_string()
            )]
        );

        let mut body = valid_body();
        body["username"] = json!("a".repeat(30));
        assert_eq!(
            errors_of(body),
            [(
                "username".to_string(),
                "Username sum exceeds the maximum length: (29).".to_string()
            )]
        );
    }

    #[test]
    fn preferred_digits_and_identifier_checks_collect_in_field_order() {
        let mut body = valid_body();
        body["preferredDigits"] = json!("00");
        body["identifierKey"] = json!(format!("0x{}", "ab".repeat(64)));
        assert_eq!(
            errors_of(body),
            [
                (
                    "preferredDigits".to_string(),
                    "Digits must be between 01-99".to_string()
                ),
                (
                    "identifierKey".to_string(),
                    "Must be a hexadecimal string of exactly 65 bytes.".to_string()
                ),
            ]
        );
    }

    #[test]
    fn dotns_gating_and_freshness_use_the_captured_messages() {
        let mut disabled = config();
        disabled.dotns_gateway_enabled = false;
        let mut body = valid_body();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        body["dotns"] = json!({ "signature": format!("0x{}", "ab".repeat(64)), "signedAt": now });
        match validate_register(&body, &disabled) {
            Err(UsernamesError::InvalidBody(errors)) => {
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].field, "dotns");
                assert_eq!(errors[0].message, MSG_DOTNS_DISABLED);
            }
            other => panic!("expected InvalidBody, got {other:?}", other = other.err()),
        }

        let enabled = config();
        let mut future = valid_body();
        future["dotns"] =
            json!({ "signature": format!("0x{}", "ab".repeat(64)), "signedAt": now + 700 });
        assert_eq!(
            match validate_register(&future, &enabled) {
                Err(UsernamesError::InvalidBody(errors)) => errors[0].message.clone(),
                other => panic!("{other:?}", other = other.err()),
            },
            "signedAt is in the future (tolerance 600s)."
        );

        let mut stale = valid_body();
        stale["dotns"] =
            json!({ "signature": format!("0x{}", "ab".repeat(64)), "signedAt": now - 700 });
        assert_eq!(
            match validate_register(&stale, &enabled) {
                Err(UsernamesError::InvalidBody(errors)) => errors[0].message.clone(),
                other => panic!("{other:?}", other = other.err()),
            },
            "signedAt is older than the intake freshness bound (600s). \
             Re-sign with a fresh timestamp and resubmit."
        );

        let mut valid = valid_body();
        valid["dotns"] = dotns_block(now, Some("reservedname"), &enabled);
        let parsed = validate_register(&valid, &enabled).expect("valid dotns");
        let dotns = parsed.dotns.expect("dotns parsed");
        assert_eq!(dotns.reserved_username.as_deref(), Some("reservedname"));
    }

    #[test]
    fn only_a_claim_that_asks_for_the_full_name_is_preflighted() {
        let config = config();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let plain = validate_register(&valid_body(), &config).expect("valid");
        assert_eq!(
            reserved_name(&plain),
            None,
            "no dotns block means no reservation leg"
        );

        let mut without = valid_body();
        without["dotns"] = dotns_block(now, None, &config);
        assert_eq!(
            reserved_name(&validate_register(&without, &config).expect("valid")),
            None
        );

        let mut with = valid_body();
        with["dotns"] = dotns_block(now, Some("aliceuser"), &config);
        assert_eq!(
            reserved_name(&validate_register(&with, &config).expect("valid")),
            Some("aliceuser")
        );
    }

    /// The name the preflight gates on is the one the runtime reserves, not
    /// the base of the lite username — `attest` takes them as separate
    /// arguments and nothing requires them to agree.
    #[test]
    fn the_reserved_name_is_read_from_the_dotns_block_not_the_username() {
        let config = config();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let mut body = valid_body();
        assert_eq!(body["username"], json!("aliceuser"));
        body["dotns"] = dotns_block(now, Some("reservedname"), &config);

        let parsed = validate_register(&body, &config).expect("valid");
        assert_eq!(reserved_name(&parsed), Some("reservedname"));
    }

    /// The 409 names the name that was actually checked — the reserved one,
    /// not the base of the lite username, which the runtime never consults for
    /// this leg and which the old message printed in its place.
    #[tokio::test]
    async fn the_full_name_conflict_names_the_reserved_name() {
        use axum::response::IntoResponse as _;
        use http_body_util::BodyExt as _;

        let response = UsernamesError::FullNameUnavailable {
            reserved: "reservedname".to_string(),
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("read body")
            .to_bytes();
        let body: Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(
            body["error"],
            json!("The full name reservedname is not available to reserve. Choose another name.")
        );
    }

    fn dotns_block(
        signed_at: i64,
        reserved: Option<&str>,
        config: &crate::config::Config,
    ) -> serde_json::Value {
        use subxt_signer::sr25519::Keypair;
        use subxt_signer::SecretUri;

        let keypair = Keypair::from_uri(&SecretUri::from_str("//Alice").unwrap()).unwrap();
        let message = crate::dotns::reservation_message(
            &keypair.public_key().0,
            &config.attester_account,
            b"aliceuser",
            &[5u8; 65],
            reserved.map(str::as_bytes),
            signed_at as u64,
        );
        let mut block = json!({
            "signature": format!("0x{}", hex::encode(keypair.sign(&message).0)),
            "signedAt": signed_at,
        });
        if let Some(reserved) = reserved {
            block["reservedUsername"] = json!(reserved);
        }
        block
    }

    #[test]
    fn an_unverifiable_dotns_signature_still_yields_a_username() {
        let config = config();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let mut junk = valid_body();
        junk["dotns"] = json!({ "signature": format!("0x{}", "ab".repeat(64)), "signedAt": now });
        let parsed = validate_register(&junk, &config).expect("junk dotns signature is accepted");
        assert_eq!(parsed.username, "aliceuser");
        assert!(
            parsed.dotns.is_some(),
            "the block is stored, so the writer decides its fate"
        );

        let mut other_attester = self::config();
        other_attester.attester_account = [0xbb; 32];
        let mut wrong = valid_body();
        wrong["dotns"] = dotns_block(now, None, &other_attester);
        assert!(validate_register(&wrong, &config).is_ok());

        let mut reserved_mismatch = valid_body();
        let mut block = dotns_block(now, Some("reservedname"), &config);
        block.as_object_mut().unwrap().remove("reservedUsername");
        reserved_mismatch["dotns"] = block;
        assert!(validate_register(&reserved_mismatch, &config).is_ok());
    }

    #[test]
    fn a_malformed_dotns_block_is_still_rejected() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let mut too_long = valid_body();
        too_long["dotns"] = json!({
            "signature": format!("0x{}", "ab".repeat(64)),
            "signedAt": now,
            "reservedUsername": "x".repeat(MAX_DOTNS_LABEL_LEN + 1),
        });
        assert_eq!(
            errors_of(too_long)
                .into_iter()
                .map(|(pointer, _)| pointer)
                .collect::<Vec<_>>(),
            ["dotns.reservedUsername".to_string()]
        );

        let mut stale = valid_body();
        stale["dotns"] = json!({
            "signature": format!("0x{}", "ab".repeat(64)),
            "signedAt": now - 86_400,
        });
        assert_eq!(
            errors_of(stale)
                .into_iter()
                .map(|(pointer, _)| pointer)
                .collect::<Vec<_>>(),
            ["dotns.signedAt".to_string()]
        );
    }

    #[test]
    fn an_oversized_reserved_username_is_rejected_before_the_signature_check() {
        let config = config();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let oversized = "a".repeat(MAX_DOTNS_LABEL_LEN + 1);

        let mut body = valid_body();
        body["dotns"] = dotns_block(now, Some(&oversized), &config);
        assert_eq!(
            errors_of(body),
            [(
                "dotns.reservedUsername".to_string(),
                format!(
                    "reservedUsername exceeds the maximum label length: ({MAX_DOTNS_LABEL_LEN})."
                )
            )]
        );

        let mut at_bound = valid_body();
        let exact = "a".repeat(MAX_DOTNS_LABEL_LEN);
        at_bound["dotns"] = dotns_block(now, Some(&exact), &config);
        assert!(validate_register(&at_bound, &config).is_ok());
    }

    #[test]
    fn preferred_digit_selection_maps_to_the_frozen_409s() {
        let taken: BTreeSet<u8> = [7u8].into_iter().collect();
        assert_eq!(select_digit(&taken, Some("08"), "base").unwrap(), 8);
        assert!(matches!(
            select_digit(&taken, Some("07"), "base"),
            Err(UsernamesError::PreferredDigitsTaken { .. })
        ));
        let all: BTreeSet<u8> = (1..=99u8).collect();
        assert!(matches!(
            select_digit(&all, None, "base"),
            Err(UsernamesError::NoDigitsAvailable { .. })
        ));
    }

    #[test]
    fn voucher_field_is_ignored_when_the_feature_is_off() {
        let mut body = valid_body();
        body["lifetimePoUDVoucher"] = json!("some-voucher-key");
        let parsed = validate_register(&body, &config()).expect("valid");
        assert_eq!(parsed.voucher, None);

        let mut body = valid_body();
        body["lifetimePoUDVoucher"] = json!(42);
        assert!(validate_register(&body, &config()).is_ok());
    }

    #[test]
    fn voucher_field_is_recognised_when_the_feature_is_on() {
        let mut on = config();
        on.registration_vouchers_enabled = true;

        let mut body = valid_body();
        body["lifetimePoUDVoucher"] = json!("some-voucher-key");
        let parsed = validate_register(&body, &on).expect("valid");
        assert_eq!(parsed.voucher.as_deref(), Some("some-voucher-key"));

        assert_eq!(validate_register(&valid_body(), &on).unwrap().voucher, None);
        let mut empty = valid_body();
        empty["lifetimePoUDVoucher"] = json!("");
        assert_eq!(validate_register(&empty, &on).unwrap().voucher, None);

        let mut bad = valid_body();
        bad["lifetimePoUDVoucher"] = json!(42);
        match validate_register(&bad, &on) {
            Err(UsernamesError::InvalidBody(errors)) => {
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].field, "lifetimePoUDVoucher");
                assert_eq!(errors[0].message, "expected string, received number");
            }
            other => panic!("expected InvalidBody, got {other:?}", other = other.err()),
        }
    }

    #[test]
    fn device_token_header_base64_rule() {
        assert!(is_base64(""));
        assert!(is_base64("AgAAABEuCTMX76f2R1TNNVkWUcwEUNk0"));
        assert!(is_base64("YWJj"));
        assert!(is_base64("YQ=="));
        assert!(!is_base64("not base64!!!"));
        assert!(!is_base64("abc"));
        assert!(!is_base64("a==="));
    }

    #[test]
    fn device_token_bytes_decodes_present_and_ignores_absent_or_empty() {
        use axum::http::HeaderValue;

        assert_eq!(device_token_bytes(&HeaderMap::new()), None);

        let mut empty = HeaderMap::new();
        empty.insert(DEVICE_TOKEN_HEADER, HeaderValue::from_static(""));
        assert_eq!(device_token_bytes(&empty), None);

        let token = b"device-token-bytes";
        let encoded = base64::engine::general_purpose::STANDARD.encode(token);
        let mut present = HeaderMap::new();
        present.insert(
            DEVICE_TOKEN_HEADER,
            HeaderValue::from_str(&encoded).unwrap(),
        );
        assert_eq!(device_token_bytes(&present).as_deref(), Some(&token[..]));
    }

    #[test]
    fn candidate_signature_verifies_control_of_beneficiary() {
        use std::str::FromStr as _;
        use subxt_signer::sr25519::Keypair;
        use subxt_signer::SecretUri;

        let keypair = Keypair::from_uri(&SecretUri::from_str("//Alice").unwrap()).unwrap();
        let candidate = keypair.public_key().0;
        let ring_vrf_key = [7u8; 32];

        let mut message = Vec::new();
        message.extend_from_slice(POP_REGISTER_PREFIX);
        message.extend_from_slice(&candidate);
        message.extend_from_slice(&ring_vrf_key);
        let signature = keypair.sign(&message).0;

        assert!(verify_candidate_signature(
            &candidate,
            &signature,
            &ring_vrf_key
        ));
        assert!(!verify_candidate_signature(
            &candidate, &signature, &[9u8; 32]
        ));
        let other = Keypair::from_uri(&SecretUri::from_str("//Bob").unwrap())
            .unwrap()
            .public_key()
            .0;
        assert!(!verify_candidate_signature(
            &other,
            &signature,
            &ring_vrf_key
        ));
        assert!(!verify_candidate_signature(
            &candidate,
            &[0u8; 10],
            &ring_vrf_key
        ));
    }
}
