// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeSet;

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
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

use crate::{
    chain::outbox::{self, InsertError, NewReservation},
    device_check::{self, Decision},
    eligibility,
    http::state::AppState,
    queue,
    signature::PEOPLE_PALLET,
};

use super::error::{FieldError, UsernamesError, UsernamesResult};
use super::{available_digits, base_state_at, reservation_state};

mod request;

pub(crate) use request::Dotns;
pub use request::RegisterRequest;
use request::{reserved_name, validate_register, ParsedRegister};

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
    /// is disabled or the outcome short-circuited (ineligible/token/unavailable).
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
        (status = 200, description = "The device is not eligible for a free registration: \
            hard-mode DeviceCheck found its free slot already used, enforced Widevine dedup found \
            the device already recorded or the Android claim carried no evidence, or a concurrent \
            claim won the device's slot. Not an error — a 200 outcome, and a terminal one: no \
            claim is stored and there is no paid alternative. The value `PAYMENT_REQUIRED` is \
            historical (the retired paid lane) and kept for client compatibility.",
         body = serde_json::Value,
         example = json!({ "registrationOutcome": "PAYMENT_REQUIRED" })),
        (status = 400, description = "Validation failed (with per-field `fields`; an unsupported \
            `payloadVersion` is reported on that field rather than as an invalid signature), malformed JSON, \
            a `lifetimePoUDVoucher` that is unknown, already used, or expired \
            (`{\"error\": \"Voucher already used\"}` — a voucher failure rejects the claim outright), \
            a device-evidence field of the wrong JSON type (in every Widevine mode, like any \
            other field), or — with `WIDEVINE_DEDUP_ENFORCE` — structurally malformed device \
            evidence (`{\"error\": \"DEVICE_EVIDENCE_MALFORMED\"}`: partial fields, bad base64, \
            or wrong field sizes — the specific reason is logged server-side, never returned).",
         body = serde_json::Value,
         example = json!({
             "error": "The request body contains invalid values.",
             "fields": [{ "field": "candidateSignature", "message": "Invalid signature." }]
         })),
        (status = 401, description = "Missing or invalid bearer token, \
            or hard-mode DeviceCheck required a usable Device-Token-iOS and none was present.",
         body = serde_json::Value),
        (status = 403, description = "Device evidence failed verification under \
            `WIDEVINE_DEDUP_ENFORCE`: chain policy, the cert-bound evidence hash (challenge / \
            account / deviceId), or a spent challenge. The specific reason is logged \
            server-side, never returned. Retryable once \
            with a fresh challenge; a claim retried without evidence gets the 200 ineligible \
            outcome.",
         body = serde_json::Value,
         example = json!({ "error": "DEVICE_EVIDENCE_INVALID", "message": "device evidence invalid" })),
        (status = 409, description = "Preferred digits taken, no digits available, username taken, or \
            the claim carries `dotns.reservedUsername` for a personhood name that is already owned \
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
    let () = super::check_rate_limit(&state, &auth.subject).await?;
    validate_device_token_header(&headers)?;

    let value = super::parse_json_body(&body)?;
    // One block handle serves the signature form and the base-state read.
    let at = state
        .chain
        .online()
        .at_current_block()
        .await
        .map_err(|e| UsernamesError::from(anyhow::Error::from(e)))?;
    let signature_form = crate::signature::account_signature_form(at.metadata_ref(), PEOPLE_PALLET);
    let mut parsed = validate_register(&value, &state.config, &signature_form)?;

    let base = base_state_at(&state, &parsed.username, &at).await?;
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
    let digit = select_digit(&base.taken, parsed.preferred_digits, &parsed.username)?;
    let digits = format!("{digit:02}");
    let full_username = format!("{}.{digits}", parsed.username);
    let voucher = parsed.voucher.take();
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

    // The Android twin of the iOS DeviceCheck gate below.
    let widevine_device = match widevine_gate(&state, &auth, &value).await? {
        WidevineGate::Proceed(device) => device,
        WidevineGate::Ineligible => return Ok(device_ineligible()),
    };

    // DeviceCheck is Apple iOS uniqueness, so it gates only iOS requests —
    // identified by the tamper-proof `plt` claim. A "seen device" resolves to
    // the 200 ineligible outcome, never an error. This query only shapes the fast path:
    // the free slot is claimed under a serialized, re-checked advisory lock in
    // `reserve`, so concurrent requests cannot double-spend it.
    let is_ios = auth.platform.as_deref() == Some("ios");
    let (mark_token, device_check_available): (Option<Vec<u8>>, Option<bool>) =
        match state.device_check.as_ref().filter(|_| is_ios) {
            Some(client) => {
                let device_token = device_token_bytes(&headers);
                let verdict = device_check::evaluate(client, device_token.as_deref()).await;
                match device_check::decide_gate(verdict, state.config.enforce_auth) {
                    // "Seen device" is the ineligible outcome, never an error.
                    Decision::Blocked => return Ok(device_ineligible()),
                    Decision::TokenRequired => return Err(UsernamesError::DeviceTokenRequired),
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
        ReserveOutcome::DeviceAlreadyClaimed => Ok(device_ineligible()),
    }
}

/// The outcome for a device that already spent (or cannot prove) its free
/// registration. The paid lane that once followed it is retired, so this is a
/// dead end; the `PAYMENT_REQUIRED` wire value is kept because shipped clients
/// match on it to show their "claim unavailable" screen.
fn device_ineligible() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({ "registrationOutcome": "PAYMENT_REQUIRED" })),
    )
        .into_response()
}

/// Advisory-lock key serializing hard-mode free-iOS DeviceCheck claims across
/// replicas (device-attestation database namespace).
const FREE_IOS_CLAIM_LOCK_KEY: i64 = 0x1DEA_DC01;

/// Outcome of the Widevine gate for this claim.
enum WidevineGate {
    /// Proceed on the standard lane; `Some` carries the device record to
    /// reserve atomically with the claim (enforced mode, unseen device).
    Proceed(Option<crate::widevine::store::PendingDevice>),
    /// Route to the ineligible outcome: seen device, or an enforced Android
    /// claim without evidence.
    Ineligible,
}

/// Evaluate the Widevine device evidence for this claim (wire spec v1).
///
/// Gate off: the evidence fields are ignored. Soft mode: verdicts are logged
/// and routing never changes. Enforced: malformed evidence is a 400, invalid
/// evidence a 403, a seen device or an evidence-less Android claim the
/// ineligible outcome, and an unseen device proceeds carrying its `PENDING` record.
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
        // No evidence. Enforced mode rules Android claims ineligible; other
        // platforms have their own gates (iOS: DeviceCheck below).
        if enforce && auth.platform.as_deref() == Some("android") {
            return Ok(WidevineGate::Ineligible);
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
        return Ok(WidevineGate::Ineligible);
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
/// for the same physical device yields `DeviceAlreadyClaimed` (mapped to the 200
/// ineligible outcome) instead of a second free registration.
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
        payload_version: parsed.payload_version.into(),
    }
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

/// Choose the discriminator: the preferred one if free, else a random free
/// one. The pool is `01..=99` (`00` is never offered, nor parsed as a
/// preference).
fn select_digit(taken: &BTreeSet<u8>, preferred: Option<u8>, base: &str) -> UsernamesResult<u8> {
    match preferred {
        Some(d) => {
            if taken.contains(&d) {
                return Err(UsernamesError::PreferredDigitsTaken {
                    digits: format!("{d:02}"),
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

    /// Shipped clients match on this exact body to show their "claim
    /// unavailable" screen, so it must stay a bare 200 with nothing else.
    #[tokio::test]
    async fn an_ineligible_device_gets_the_bare_payment_required_outcome() {
        use http_body_util::BodyExt as _;

        let response = device_ineligible();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("read body")
            .to_bytes();
        let body: Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(body, json!({ "registrationOutcome": "PAYMENT_REQUIRED" }));
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

    #[test]
    fn preferred_digit_selection_maps_to_the_frozen_409s() {
        let taken: BTreeSet<u8> = [7u8].into_iter().collect();
        assert_eq!(select_digit(&taken, Some(8), "base").unwrap(), 8);
        assert!(matches!(
            select_digit(&taken, Some(7), "base"),
            Err(UsernamesError::PreferredDigitsTaken { .. })
        ));
        let all: BTreeSet<u8> = (1..=99u8).collect();
        assert!(matches!(
            select_digit(&all, None, "base"),
            Err(UsernamesError::NoDigitsAvailable { .. })
        ));
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
}
