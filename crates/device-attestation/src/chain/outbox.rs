// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeSet;

use sqlx::{PgPool, Row as _};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Waiting in the registration queue (`QUEUE_ENABLED` intake). Entry state;
    /// while the queue is enabled only the advancer moves it to `RESERVED`
    /// (queue disabled: the chain-writer's janitor drains leftovers).
    Queued,
    /// Validated + persisted, not yet submitted. Entry state when the queue is
    /// disabled; otherwise reached via the advancer.
    Reserved,
    /// Extrinsic built + signed + broadcast; recorded before awaiting inclusion.
    Submitting,
    /// Confirmed on-chain (or reconciled as already-owned). Terminal success.
    Assigned,
    /// Transient failure; re-enqueued with backoff via `not_before`.
    RetryAfter,
    /// Permanent failure (bad input, unrecoverable dispatch). Terminal.
    FailedTerminal,
}

impl Status {
    pub const ALL: [Status; 6] = [
        Status::Queued,
        Status::Reserved,
        Status::Submitting,
        Status::Assigned,
        Status::RetryAfter,
        Status::FailedTerminal,
    ];

    /// The stored `status` string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Status::Queued => "QUEUED",
            Status::Reserved => "RESERVED",
            Status::Submitting => "SUBMITTING",
            Status::Assigned => "ASSIGNED",
            Status::RetryAfter => "RETRY_AFTER",
            Status::FailedTerminal => "FAILED_TERMINAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotnsStatus {
    /// Carries a dotns block. Not yet submitted to Asset Hub.
    Pending,
    /// Extrinsic built, signed and broadcast. Recorded before awaiting
    /// inclusion.
    Submitting,
    /// Confirmed on Asset Hub, or reconciled as already-owned. Terminal
    /// success.
    Reserved,
    /// Transient failure. Re-enqueued with backoff via `dotns_not_before`.
    RetryAfter,
    /// Permanent failure: bad signature, or label owned elsewhere. Terminal.
    FailedTerminal,
    /// The reservation signature aged out before submission. Terminal. Not
    /// recoverable by the backend. Only the client can re-sign.
    Expired,
    /// The People half failed terminally, so the dotNS half was never
    /// attempted. Terminal.
    Abandoned,
}

impl DotnsStatus {
    pub const ALL: [DotnsStatus; 7] = [
        DotnsStatus::Pending,
        DotnsStatus::Submitting,
        DotnsStatus::Reserved,
        DotnsStatus::RetryAfter,
        DotnsStatus::FailedTerminal,
        DotnsStatus::Expired,
        DotnsStatus::Abandoned,
    ];

    /// The stored `dotns_status` string.
    pub const fn as_str(self) -> &'static str {
        match self {
            DotnsStatus::Pending => "PENDING",
            DotnsStatus::Submitting => "SUBMITTING",
            DotnsStatus::Reserved => "RESERVED",
            DotnsStatus::RetryAfter => "RETRY_AFTER",
            DotnsStatus::FailedTerminal => "FAILED_TERMINAL",
            DotnsStatus::Expired => "EXPIRED",
            DotnsStatus::Abandoned => "ABANDONED",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StatusDepth {
    pub depth: i64,
    pub oldest_age_secs: Option<f64>,
}

pub async fn depth_by_status(pool: &PgPool) -> Result<Vec<(Status, StatusDepth)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT status, count(*) AS depth, \
                extract(epoch from now() - min(updated_at))::float8 AS oldest_age_secs \
         FROM username_reservations GROUP BY status",
    )
    .fetch_all(pool)
    .await?;

    let mut observed = std::collections::BTreeMap::new();
    for row in &rows {
        let status: String = row.try_get("status")?;
        observed.insert(
            status,
            StatusDepth {
                depth: row.try_get("depth")?,
                oldest_age_secs: row.try_get("oldest_age_secs")?,
            },
        );
    }
    Ok(Status::ALL
        .into_iter()
        .map(|status| {
            let depth = observed.remove(status.as_str()).unwrap_or(StatusDepth {
                depth: 0,
                oldest_age_secs: None,
            });
            (status, depth)
        })
        .collect())
}

pub struct NewReservation {
    pub account_id: String,
    pub candidate_account_id: String,
    pub base: String,
    pub digits: String,
    pub full_username: String,
    pub candidate_signature: Vec<u8>,
    pub ring_vrf_key: Vec<u8>,
    pub proof_of_ownership: Vec<u8>,
    pub consumer_registration_signature: Vec<u8>,
    pub identifier_key: Vec<u8>,
    pub dotns_signature: Option<Vec<u8>>,
    pub dotns_signed_at: Option<i64>,
    pub reserved_username: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum InsertError {
    #[error("username already taken")]
    Conflict,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

pub async fn insert<'e, E>(executor: E, r: &NewReservation) -> Result<i64, InsertError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    insert_with(executor, r, Status::Reserved, 1).await
}

pub async fn insert_queued<'e, E>(
    executor: E,
    r: &NewReservation,
    queue_group: i32,
) -> Result<i64, InsertError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    insert_with(executor, r, Status::Queued, queue_group).await
}

async fn insert_with<'e, E>(
    executor: E,
    r: &NewReservation,
    status: Status,
    queue_group: i32,
) -> Result<i64, InsertError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let dotns_status = r
        .dotns_signature
        .is_some()
        .then_some(DotnsStatus::Pending.as_str());
    let row = sqlx::query(
        "INSERT INTO username_reservations \
           (account_id, candidate_account_id, base, digits, full_username, \
            candidate_signature, ring_vrf_key, proof_of_ownership, \
            consumer_registration_signature, identifier_key, \
            dotns_signature, dotns_signed_at, reserved_username, \
            status, queue_group, dotns_status) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) \
         RETURNING id",
    )
    .bind(&r.account_id)
    .bind(&r.candidate_account_id)
    .bind(&r.base)
    .bind(&r.digits)
    .bind(&r.full_username)
    .bind(&r.candidate_signature)
    .bind(&r.ring_vrf_key)
    .bind(&r.proof_of_ownership)
    .bind(&r.consumer_registration_signature)
    .bind(&r.identifier_key)
    .bind(&r.dotns_signature)
    .bind(r.dotns_signed_at)
    .bind(&r.reserved_username)
    .bind(status.as_str())
    .bind(queue_group)
    .bind(dotns_status)
    .fetch_one(executor)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => InsertError::Conflict,
        _ => InsertError::Db(e),
    })?;
    Ok(row.try_get::<i64, _>("id")?)
}

pub async fn allocated_discriminators(
    pool: &PgPool,
    base: &str,
) -> Result<BTreeSet<u8>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT digits FROM username_reservations \
         WHERE base = $1",
    )
    .bind(base)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            let raw = row.try_get::<String, _>("digits")?;
            raw.parse::<u8>()
                .map_err(|error| sqlx::Error::ColumnDecode {
                    index: "digits".to_string(),
                    source: Box::new(error),
                })
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct Reservation {
    pub id: i64,
    pub full_username: String,
    pub candidate_account_id: String,
    pub candidate_signature: Vec<u8>,
    pub ring_vrf_key: Vec<u8>,
    pub proof_of_ownership: Vec<u8>,
    pub consumer_registration_signature: Vec<u8>,
    pub identifier_key: Vec<u8>,
    pub reserved_username: Option<String>,
    pub attempt: i32,
    pub dotns_signature: Option<Vec<u8>>,
    pub dotns_signed_at: Option<i64>,
    pub dotns_attempt: i32,
    pub created_at: OffsetDateTime,
}

const SELECT_COLS: &str = "id, full_username, candidate_account_id, candidate_signature, \
     ring_vrf_key, proof_of_ownership, consumer_registration_signature, identifier_key, \
     reserved_username, attempt, dotns_signature, dotns_signed_at, dotns_attempt, created_at";

fn row_to_reservation(row: &sqlx::postgres::PgRow) -> Result<Reservation, sqlx::Error> {
    Ok(Reservation {
        id: row.try_get("id")?,
        full_username: row.try_get("full_username")?,
        candidate_account_id: row.try_get("candidate_account_id")?,
        candidate_signature: row.try_get("candidate_signature")?,
        ring_vrf_key: row.try_get("ring_vrf_key")?,
        proof_of_ownership: row.try_get("proof_of_ownership")?,
        consumer_registration_signature: row.try_get("consumer_registration_signature")?,
        identifier_key: row.try_get("identifier_key")?,
        reserved_username: row.try_get("reserved_username")?,
        attempt: row.try_get("attempt")?,
        dotns_signature: row.try_get("dotns_signature")?,
        dotns_signed_at: row.try_get("dotns_signed_at")?,
        dotns_attempt: row.try_get("dotns_attempt")?,
        created_at: row.try_get("created_at")?,
    })
}

pub async fn claim_due(pool: &PgPool, limit: i64) -> Result<Vec<Reservation>, sqlx::Error> {
    let rows = sqlx::query(&format!(
        "SELECT {SELECT_COLS} FROM username_reservations \
         WHERE status = 'RESERVED' \
            OR (status = 'RETRY_AFTER' AND (not_before IS NULL OR not_before <= now())) \
         ORDER BY created_at ASC LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.iter().map(row_to_reservation).collect()
}

pub async fn claim_dotns_due(pool: &PgPool, limit: i64) -> Result<Vec<Reservation>, sqlx::Error> {
    let rows = sqlx::query(&format!(
        "SELECT {SELECT_COLS} FROM username_reservations \
         WHERE status = 'ASSIGNED' \
           AND (dotns_status = 'PENDING' \
                OR (dotns_status = 'RETRY_AFTER' \
                    AND (dotns_not_before IS NULL OR dotns_not_before <= now()))) \
         ORDER BY created_at ASC LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.iter().map(row_to_reservation).collect()
}

pub async fn dotns_submitting(pool: &PgPool) -> Result<Vec<Reservation>, sqlx::Error> {
    let rows = sqlx::query(&format!(
        "SELECT {SELECT_COLS} FROM username_reservations \
         WHERE dotns_status = 'SUBMITTING' ORDER BY created_at ASC"
    ))
    .fetch_all(pool)
    .await?;
    rows.iter().map(row_to_reservation).collect()
}

pub async fn dotns_depth_by_status(
    pool: &PgPool,
) -> Result<Vec<(DotnsStatus, StatusDepth)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT dotns_status, count(*) AS depth, \
                extract(epoch from now() - min(updated_at))::float8 AS oldest_age_secs \
         FROM username_reservations WHERE dotns_status IS NOT NULL GROUP BY dotns_status",
    )
    .fetch_all(pool)
    .await?;

    let mut observed = std::collections::BTreeMap::new();
    for row in &rows {
        let status: String = row.try_get("dotns_status")?;
        observed.insert(
            status,
            StatusDepth {
                depth: row.try_get("depth")?,
                oldest_age_secs: row.try_get("oldest_age_secs")?,
            },
        );
    }
    Ok(DotnsStatus::ALL
        .into_iter()
        .map(|status| {
            let depth = observed.remove(status.as_str()).unwrap_or(StatusDepth {
                depth: 0,
                oldest_age_secs: None,
            });
            (status, depth)
        })
        .collect())
}

pub async fn submitting(pool: &PgPool) -> Result<Vec<Reservation>, sqlx::Error> {
    let rows = sqlx::query(&format!(
        "SELECT {SELECT_COLS} FROM username_reservations WHERE status = 'SUBMITTING' \
         ORDER BY created_at ASC"
    ))
    .fetch_all(pool)
    .await?;
    rows.iter().map(row_to_reservation).collect()
}

#[derive(Debug, Clone)]
pub struct Guard {
    pub lease_name: String,
    pub holder_id: String,
    pub epoch: i64,
}

const LEASE_HELD: &str = " AND EXISTS (SELECT 1 FROM writer_lease \
     WHERE name = $5 AND holder_id = $6 AND lease_epoch = $7 AND expires_at > now())";

pub async fn mark_submitting(
    pool: &PgPool,
    guard: &Guard,
    id: i64,
    tx_hash: &str,
    nonce: i64,
    attempt: i32,
) -> Result<bool, sqlx::Error> {
    let sql = format!(
        "UPDATE username_reservations \
         SET status='SUBMITTING', tx_hash=$2, nonce=$3, attempt=$4, submitted_at=now(), updated_at=now() \
         WHERE id=$1{LEASE_HELD}"
    );
    let done = sqlx::query(&sql)
        .bind(id)
        .bind(tx_hash)
        .bind(nonce)
        .bind(attempt)
        .bind(&guard.lease_name)
        .bind(&guard.holder_id)
        .bind(guard.epoch)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() == 1)
}

pub async fn mark_assigned<'e, E>(executor: E, guard: &Guard, id: i64) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    guarded_status(executor, guard, id, Status::Assigned, None, None).await
}

pub async fn mark_retry(
    pool: &PgPool,
    guard: &Guard,
    id: i64,
    not_before: OffsetDateTime,
    attempt: i32,
    err: &str,
) -> Result<bool, sqlx::Error> {
    guarded_status(
        pool,
        guard,
        id,
        Status::RetryAfter,
        Some((not_before, attempt)),
        Some(err),
    )
    .await
}

pub async fn mark_failed<'e, E>(
    executor: E,
    guard: &Guard,
    id: i64,
    err: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    guarded_status(executor, guard, id, Status::FailedTerminal, None, Some(err)).await
}

pub async fn mark_dotns_submitting(
    pool: &PgPool,
    guard: &Guard,
    id: i64,
    tx_hash: &str,
    attempt: i32,
) -> Result<bool, sqlx::Error> {
    let sql = format!(
        "UPDATE username_reservations \
         SET dotns_status='SUBMITTING', dotns_tx_hash=$2, dotns_attempt=$3, \
             dotns_not_before=$4, updated_at=now() \
         WHERE id=$1{LEASE_HELD}"
    );
    let done = sqlx::query(&sql)
        .bind(id)
        .bind(tx_hash)
        .bind(attempt)
        .bind(None::<OffsetDateTime>)
        .bind(&guard.lease_name)
        .bind(&guard.holder_id)
        .bind(guard.epoch)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() == 1)
}

pub async fn mark_dotns_reserved(
    pool: &PgPool,
    guard: &Guard,
    id: i64,
) -> Result<bool, sqlx::Error> {
    guarded_dotns_status(pool, guard, id, DotnsStatus::Reserved, None, None).await
}

pub async fn mark_dotns_retry(
    pool: &PgPool,
    guard: &Guard,
    id: i64,
    not_before: OffsetDateTime,
    attempt: i32,
    err: &str,
) -> Result<bool, sqlx::Error> {
    guarded_dotns_status(
        pool,
        guard,
        id,
        DotnsStatus::RetryAfter,
        Some((not_before, attempt)),
        Some(err),
    )
    .await
}

pub async fn mark_dotns_failed(
    pool: &PgPool,
    guard: &Guard,
    id: i64,
    err: &str,
) -> Result<bool, sqlx::Error> {
    guarded_dotns_status(
        pool,
        guard,
        id,
        DotnsStatus::FailedTerminal,
        None,
        Some(err),
    )
    .await
}

pub async fn mark_dotns_expired(
    pool: &PgPool,
    guard: &Guard,
    id: i64,
    err: &str,
) -> Result<bool, sqlx::Error> {
    guarded_dotns_status(pool, guard, id, DotnsStatus::Expired, None, Some(err)).await
}

async fn guarded_dotns_status(
    pool: &PgPool,
    guard: &Guard,
    id: i64,
    status: DotnsStatus,
    retry: Option<(OffsetDateTime, i32)>,
    err: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let (not_before, attempt) = match retry {
        Some((nb, a)) => (Some(nb), Some(a)),
        None => (None, None),
    };
    let sql = format!(
        "UPDATE username_reservations \
         SET dotns_status=$2, \
             dotns_not_before = CASE WHEN $2 = 'RETRY_AFTER' THEN $3 ELSE dotns_not_before END, \
             dotns_attempt = COALESCE($4, dotns_attempt), \
             dotns_last_error = COALESCE($8, dotns_last_error), \
             updated_at = now() \
         WHERE id=$1{LEASE_HELD}"
    );
    let done = sqlx::query(&sql)
        .bind(id)
        .bind(status.as_str())
        .bind(not_before)
        .bind(attempt)
        .bind(&guard.lease_name)
        .bind(&guard.holder_id)
        .bind(guard.epoch)
        .bind(err)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() == 1)
}

const DOTNS_ABANDONED_REASON: &str =
    "People registration failed terminally; dotNS reservation never attempted";

const DOTNS_OPEN_STATES: &str = "('PENDING', 'RETRY_AFTER')";

async fn guarded_status<'e, E>(
    executor: E,
    guard: &Guard,
    id: i64,
    status: Status,
    retry: Option<(OffsetDateTime, i32)>,
    err: Option<&str>,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let (not_before, attempt) = match retry {
        Some((nb, a)) => (Some(nb), Some(a)),
        None => (None, None),
    };
    let closes_dotns = format!("$2 = 'FAILED_TERMINAL' AND dotns_status IN {DOTNS_OPEN_STATES}");
    let sql = format!(
        "UPDATE username_reservations \
         SET status=$2, \
             not_before = CASE WHEN $2 = 'RETRY_AFTER' THEN $3 ELSE not_before END, \
             attempt = COALESCE($4, attempt), \
             last_error = COALESCE($8, last_error), \
             dotns_status = CASE WHEN {closes_dotns} \
                 THEN '{abandoned}' ELSE dotns_status END, \
             dotns_last_error = CASE WHEN {closes_dotns} \
                 THEN '{reason}' ELSE dotns_last_error END, \
             dotns_not_before = CASE WHEN {closes_dotns} \
                 THEN NULL ELSE dotns_not_before END, \
             updated_at = now() \
         WHERE id=$1{LEASE_HELD}",
        abandoned = DotnsStatus::Abandoned.as_str(),
        reason = DOTNS_ABANDONED_REASON,
    );
    let done = sqlx::query(&sql)
        .bind(id)
        .bind(status.as_str())
        .bind(not_before)
        .bind(attempt)
        .bind(&guard.lease_name)
        .bind(&guard.holder_id)
        .bind(guard.epoch)
        .bind(err)
        .execute(executor)
        .await?;
    Ok(done.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_covers_every_status() {
        for status in Status::ALL {
            match status {
                Status::Queued
                | Status::Reserved
                | Status::Submitting
                | Status::Assigned
                | Status::RetryAfter
                | Status::FailedTerminal => {}
            }
        }
        let distinct: std::collections::BTreeSet<_> =
            Status::ALL.iter().map(|status| status.as_str()).collect();
        assert_eq!(distinct.len(), Status::ALL.len(), "ALL repeats a status");
    }

    #[test]
    fn dotns_all_covers_every_status() {
        for status in DotnsStatus::ALL {
            match status {
                DotnsStatus::Pending
                | DotnsStatus::Submitting
                | DotnsStatus::Reserved
                | DotnsStatus::RetryAfter
                | DotnsStatus::FailedTerminal
                | DotnsStatus::Expired
                | DotnsStatus::Abandoned => {}
            }
        }
        let distinct: std::collections::BTreeSet<_> = DotnsStatus::ALL
            .iter()
            .map(|status| status.as_str())
            .collect();
        assert_eq!(
            distinct.len(),
            DotnsStatus::ALL.len(),
            "ALL repeats a status"
        );
    }
}
