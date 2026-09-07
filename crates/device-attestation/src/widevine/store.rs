// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Postgres store for Widevine device dedup records.
//!
//! One row per pseudonymized physical device, `UNIQUE (device_hmac)`; the raw
//! `deviceId` never reaches this table. `PENDING` is reserved in the same
//! transaction as the username reservation, becomes `CONSUMED` on on-chain
//! success (clearing `reservation_id`, so no permanent device→username link),
//! and is deleted on terminal failure so the device can claim again.

use sqlx::PgPool;

/// A device record to reserve alongside a claim.
#[derive(Debug, Clone)]
pub struct PendingDevice {
    /// `HMAC-SHA256(k, "poud:v1" ‖ deviceId)` — the device identity.
    pub hmac: [u8; 32],
}

/// Why the `PENDING` insert failed.
#[derive(Debug, thiserror::Error)]
pub enum InsertDeviceError {
    /// The device is already recorded (`PENDING` or `CONSUMED`) — a lost
    /// race, resolved as the payment outcome like any seen device.
    #[error("device already recorded")]
    Seen,
    /// Any other database failure.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Whether the device HMAC is already recorded (`PENDING` or `CONSUMED`
/// both count — a pending claim holds the slot).
pub async fn seen(pool: &PgPool, hmac: &[u8; 32]) -> Result<bool, sqlx::Error> {
    let row = sqlx::query("SELECT 1 FROM widevine_devices WHERE device_hmac = $1")
        .bind(&hmac[..])
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

/// Insert the `PENDING` device record tied to `reservation_id`. A unique
/// violation on `device_hmac` maps to [`InsertDeviceError::Seen`] when a
/// concurrent claim records the device first.
pub async fn insert_pending<'e, E>(
    executor: E,
    device: &PendingDevice,
    reservation_id: i64,
) -> Result<(), InsertDeviceError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO widevine_devices (device_hmac, status, reservation_id) \
         VALUES ($1, 'PENDING', $2)",
    )
    .bind(&device.hmac[..])
    .bind(reservation_id)
    .execute(executor)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => InsertDeviceError::Seen,
        _ => InsertDeviceError::Db(e),
    })?;
    Ok(())
}

/// Mark the reservation's `PENDING` device record `CONSUMED` (on-chain
/// success) and clear `reservation_id` — once the claim has landed, the
/// table remembers only that the device used its free slot, never which
/// username it registered. Reservations without a pending Widevine record are
/// successful no-ops.
pub async fn consume_for_reservation<'e, E>(
    executor: E,
    reservation_id: i64,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "UPDATE widevine_devices \
         SET status = 'CONSUMED', reservation_id = NULL, updated_at = now() \
         WHERE reservation_id = $1 AND status = 'PENDING'",
    )
    .bind(reservation_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Release the reservation's `PENDING` device record (terminal claim
/// failure): the row is deleted so the device can claim again. `CONSUMED`
/// rows are never released. Returns whether a row was released.
pub async fn release_for_reservation<'e, E>(
    executor: E,
    reservation_id: i64,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let done = sqlx::query(
        "DELETE FROM widevine_devices WHERE reservation_id = $1 AND status = 'PENDING'",
    )
    .bind(reservation_id)
    .execute(executor)
    .await?;
    Ok(done.rows_affected() > 0)
}
