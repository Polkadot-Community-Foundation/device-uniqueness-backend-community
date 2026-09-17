// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};

use chain_types::people;
use chain_types::people::runtime_types::indiv_pallet_resources::types::ConsumerInfo;
use sqlx::{PgPool, Postgres, Row as _, Transaction};
use subxt::utils::AccountId32;

use crate::chain::{BoxError, ChainError, PeopleChain};
use crate::projection;
use crate::ss58::Ss58Error;

/// Outcome of one [`index_finalized_range`] pass across finalized blocks.
#[derive(Debug, Clone, Copy)]
pub struct IndexReport {
    /// First finalized block number considered (checkpoint + 1).
    pub from_block: u64,
    /// Finalized head block number reached.
    pub to_block: u64,
    /// Number of finalized blocks processed in this pass.
    pub blocks_processed: u64,
    /// Number of accounts upserted from re-read consumer storage.
    pub accounts_upserted: u64,
    /// Number of accounts deleted because their consumer entry was absent.
    pub accounts_deleted: u64,
    /// Number of consumer values that failed username decoding and were skipped.
    pub decode_failures: u64,
}

impl IndexReport {
    /// A pass that indexed nothing and left the projection resting at `block`.
    fn idle(block: u64) -> Self {
        Self {
            from_block: block,
            to_block: block,
            blocks_processed: 0,
            accounts_upserted: 0,
            accounts_deleted: 0,
            decode_failures: 0,
        }
    }
}

/// Fatal incremental indexing failure.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    /// A finalized block or event query failed.
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// Subxt rejected a storage or constant operation.
    #[error("reading finalized People Chain storage: {0}")]
    Storage(#[source] BoxError),
    /// The chain's SS58 prefix could not encode account identifiers.
    #[error(transparent)]
    Ss58(#[from] Ss58Error),
    #[error("writing username projection: {0}")]
    Database(#[from] sqlx::Error),
    #[error("finalized block number {0} exceeds the database range")]
    SnapshotNumber(u64),
}

/// Index every finalized block from the stored checkpoint up to the head,
/// reading the finalized head itself.
///
/// The order matters: the lock, then the checkpoint, and only then the chain.
/// Both early exits — another instance holds the lock, or the projection has no
/// checkpoint to index from — are answerable from the database alone, and
/// asking the chain for a head neither would use turns a local no-op into a
/// round trip that can fail.
pub async fn index_finalized_range(
    pool: &PgPool,
    chain: &PeopleChain,
) -> Result<Option<IndexReport>, IndexError> {
    let Some(_lock) = try_projection_lock(pool).await? else {
        return Ok(None);
    };
    let Some(checkpoint) = read_checkpoint(pool).await? else {
        return Ok(Some(IndexReport::idle(0)));
    };
    let head_number = chain.finalized_head_number().await?;
    index_from_checkpoint(pool, chain, checkpoint, head_number).await
}

/// Index every finalized block from the stored checkpoint up to `head_number`.
///
/// Takes the projection lock with `pg_try_advisory_lock`, returning `Ok(None)`
/// when another instance holds it. Commits per block, so an interrupted pass
/// never advances past the last fully-written one. A zero report means the
/// checkpoint row is missing (bootstrap seeds it at startup).
pub async fn index_finalized_range_to(
    pool: &PgPool,
    chain: &PeopleChain,
    head_number: u64,
) -> Result<Option<IndexReport>, IndexError> {
    let Some(_lock) = try_projection_lock(pool).await? else {
        return Ok(None);
    };
    index_finalized_range_locked(pool, chain, head_number).await
}

pub struct ProjectionLock {
    _connection: sqlx::pool::PoolConnection<Postgres>,
}

pub async fn try_projection_lock(pool: &PgPool) -> Result<Option<ProjectionLock>, sqlx::Error> {
    let mut lock_connection = pool.acquire().await?;
    lock_connection.close_on_drop();
    let acquired: bool = sqlx::query("SELECT pg_try_advisory_lock($1)")
        .bind(crate::projection::PROJECTION_LOCK_ID)
        .fetch_one(&mut *lock_connection)
        .await?
        .try_get(0)?;
    if !acquired {
        return Ok(None);
    }
    Ok(Some(ProjectionLock {
        _connection: lock_connection,
    }))
}

pub async fn index_finalized_range_locked(
    pool: &PgPool,
    chain: &PeopleChain,
    head_number: u64,
) -> Result<Option<IndexReport>, IndexError> {
    let Some(checkpoint) = read_checkpoint(pool).await? else {
        return Ok(Some(IndexReport::idle(0)));
    };
    index_from_checkpoint(pool, chain, checkpoint, head_number).await
}

async fn read_checkpoint(pool: &PgPool) -> Result<Option<u64>, IndexError> {
    let Some(row) = sqlx::query("SELECT last_finalized_number FROM sync_state WHERE id = 1")
        .fetch_optional(pool)
        .await?
    else {
        return Ok(None);
    };
    let checkpoint = row.try_get::<i64, _>("last_finalized_number")?;
    Ok(Some(u64::try_from(checkpoint).unwrap_or(0)))
}

async fn index_from_checkpoint(
    pool: &PgPool,
    chain: &PeopleChain,
    checkpoint: u64,
    head_number: u64,
) -> Result<Option<IndexReport>, IndexError> {
    if head_number <= checkpoint {
        return Ok(Some(IndexReport::idle(checkpoint)));
    }

    let mut report = IndexReport {
        from_block: checkpoint + 1,
        to_block: head_number,
        blocks_processed: 0,
        accounts_upserted: 0,
        accounts_deleted: 0,
        decode_failures: 0,
    };

    for number in (checkpoint + 1)..=head_number {
        index_block(pool, chain, number, &mut report).await?;
        report.blocks_processed += 1;
    }

    Ok(Some(report))
}

pub const MAX_SPECULATIVE_WINDOW: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpeculativeWindow {
    /// Finality has caught up to the best head; nothing is unfinalized.
    Nothing,
    /// The gap is too wide to be a normal finality trail — stand down.
    StandDown,
    /// Scan this inclusive range for events.
    Scan { from: u64, to: u64 },
}

fn plan_speculative_window(finalized: u64, best: u64) -> SpeculativeWindow {
    if best <= finalized {
        return SpeculativeWindow::Nothing;
    }
    if best - finalized > MAX_SPECULATIVE_WINDOW {
        return SpeculativeWindow::StandDown;
    }
    SpeculativeWindow::Scan {
        from: finalized + 1,
        to: best,
    }
}

/// Outcome of one speculative pass over the unfinalized window.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpeculativeReport {
    /// First unfinalized block scanned (finalized head + 1).
    pub from_block: u64,
    /// Best block the window was reconciled against.
    pub to_block: u64,
    /// Unfinalized blocks scanned for events this pass.
    pub blocks_scanned: u64,
    /// Accounts re-read at the best head: those named by window events plus
    /// the rows already held speculatively, less any already held *finalized* —
    /// speculation can neither overwrite nor delete those, so reading them
    /// could only confirm what it may not act on.
    pub accounts_checked: u64,
    /// Rows added, or refreshed because their content actually changed. A row
    /// that is merely still pending is left untouched, so this counts
    /// admissions rather than passes.
    pub accounts_admitted: u64,
    /// Speculative rows retracted — the fork that carried them lost, or the
    /// consumer entry is simply gone at the new best head.
    pub accounts_retracted: u64,
    /// Consumer values that failed decoding. Also counted in
    /// `accounts_retracted`, since a value that will not decode is retracted.
    pub decode_failures: u64,
    /// Set when the window was too wide to scan, so nothing new was admitted.
    /// Rows already held were still re-checked.
    pub skipped_wide_window: bool,
}

#[derive(Debug, Default)]
pub struct SpeculativeCache {
    entries: BTreeMap<u64, CachedBlock>,
}

/// The accounts one block's events named, and the hash they were read from.
#[derive(Debug)]
struct CachedBlock {
    hash: [u8; 32],
    accounts: Vec<[u8; 32]>,
}

impl SpeculativeCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, number: u64, hash: &[u8; 32]) -> Option<&[[u8; 32]]> {
        self.entries
            .get(&number)
            .filter(|cached| &cached.hash == hash)
            .map(|cached| cached.accounts.as_slice())
    }

    fn insert(&mut self, number: u64, hash: [u8; 32], accounts: Vec<[u8; 32]>) {
        self.entries.insert(number, CachedBlock { hash, accounts });
    }

    /// Drop everything at or below `finalized`: those heights can no longer be
    /// replaced, and the finalized pass owns them from here on.
    fn prune_finalized(&mut self, finalized: u64) {
        self.entries = self.entries.split_off(&finalized.saturating_add(1));
    }
}

pub async fn index_speculative_window(
    pool: &PgPool,
    chain: &PeopleChain,
    finalized: u64,
    best: u64,
    cache: &mut SpeculativeCache,
) -> Result<SpeculativeReport, IndexError> {
    let mut report = SpeculativeReport {
        from_block: finalized.saturating_add(1),
        to_block: best,
        ..Default::default()
    };
    let scan = match plan_speculative_window(finalized, best) {
        SpeculativeWindow::Nothing => {
            report.to_block = finalized;
            None
        }
        SpeculativeWindow::StandDown => {
            report.skipped_wide_window = true;
            None
        }
        SpeculativeWindow::Scan { from, to } => Some((from, to)),
    };
    cache.prune_finalized(finalized);

    let mut affected: Vec<[u8; 32]> = Vec::new();
    if let Some((from, to)) = scan {
        for number in from..=to {
            let at = chain
                .online()
                .at_block(number)
                .await
                .map_err(|source| ChainError::Query(Box::new(source)))?;
            let hash = at.block_hash().0;
            match cache.get(number, &hash) {
                Some(accounts) => affected.extend_from_slice(accounts),
                None => {
                    let events = at
                        .events()
                        .fetch()
                        .await
                        .map_err(|source| ChainError::Query(Box::new(source)))?;
                    let accounts = accounts_from_events(&events)?;
                    affected.extend_from_slice(&accounts);
                    cache.insert(number, hash, accounts);
                }
            }
            report.blocks_scanned += 1;
        }
    }
    affected.extend(projection::speculative_accounts(pool).await?);
    let affected = dedupe_accounts(affected);
    let already_finalized = projection::finalized_accounts(pool, &affected).await?;
    let affected: Vec<[u8; 32]> = affected
        .into_iter()
        .filter(|account| !already_finalized.contains(account))
        .collect();
    report.accounts_checked = affected.len() as u64;
    if affected.is_empty() {
        return Ok(report);
    }

    let head = best.max(finalized);
    let at = chain
        .online()
        .at_block(head)
        .await
        .map_err(|source| ChainError::Query(Box::new(source)))?;
    let block_hash = at.block_hash().0;
    let block_number = at.block_number();
    let block_number_db =
        i64::try_from(block_number).map_err(|_| IndexError::SnapshotNumber(block_number))?;
    let ss58_prefix = crate::ss58::validate_prefix(
        at.constants()
            .entry(people::constants().system().ss58_prefix())
            .map_err(|source| IndexError::Storage(Box::new(source)))?,
    )?;

    let mut tx = pool.begin().await?;
    for account in &affected {
        let consumer = at
            .storage()
            .try_fetch(
                people::storage().resources().consumers(),
                (AccountId32(*account),),
            )
            .await
            .map_err(|source| IndexError::Storage(Box::new(source)))?;
        let mut decode_failed = false;
        let decoded = match consumer {
            Some(value) => {
                let consumer: ConsumerInfo = value
                    .decode()
                    .map_err(|source| IndexError::Storage(Box::new(source)))?;
                match projection::decode_consumer(
                    *account,
                    consumer.identifier_key,
                    consumer.lite_username.0,
                    consumer.full_username.map(|username| username.0),
                    ss58_prefix,
                    block_hash,
                    block_number,
                ) {
                    Ok(record) => Some(record),
                    Err(error) => {
                        decode_failed = true;
                        tracing::warn!(stage = "speculative", account = ?account, error = ?error, "retracting undecodable consumer");
                        None
                    }
                }
            }
            None => None,
        };
        match decoded {
            Some(record) => {
                if projection::upsert_speculative(&mut tx, &record, block_number_db).await? {
                    report.accounts_admitted += 1;
                }
            }
            None => {
                if decode_failed {
                    report.decode_failures += 1;
                }
                if projection::delete_if_speculative(&mut tx, account).await? {
                    report.accounts_retracted += 1;
                }
            }
        }
    }
    tx.commit().await?;
    Ok(report)
}

/// Index one finalized block, committing its writes and checkpoint atomically.
async fn index_block(
    pool: &PgPool,
    chain: &PeopleChain,
    number: u64,
    report: &mut IndexReport,
) -> Result<(), IndexError> {
    let at = chain
        .online()
        .at_block(number)
        .await
        .map_err(|source| ChainError::Query(Box::new(source)))?;
    let block_hash = at.block_hash().0;
    let block_number = at.block_number();
    let block_number_db =
        i64::try_from(block_number).map_err(|_| IndexError::SnapshotNumber(block_number))?;

    let events = at
        .events()
        .fetch()
        .await
        .map_err(|source| ChainError::Query(Box::new(source)))?;

    let affected = dedupe_accounts(accounts_from_events(&events)?);

    if affected.is_empty() {
        let mut tx = pool.begin().await?;
        advance_checkpoint(&mut tx, block_number_db, &block_hash, 0, 0).await?;
        tx.commit().await?;
        return Ok(());
    }

    let ss58_prefix = crate::ss58::validate_prefix(
        at.constants()
            .entry(people::constants().system().ss58_prefix())
            .map_err(|source| IndexError::Storage(Box::new(source)))?,
    )?;

    let mut tx = pool.begin().await?;
    let mut block_upserts = 0_u64;
    let mut block_deletes = 0_u64;
    let mut block_failures = 0_u64;

    for account in &affected {
        let consumer = at
            .storage()
            .try_fetch(
                people::storage().resources().consumers(),
                (AccountId32(*account),),
            )
            .await
            .map_err(|source| IndexError::Storage(Box::new(source)))?;
        match consumer {
            Some(value) => {
                let consumer: ConsumerInfo = value
                    .decode()
                    .map_err(|source| IndexError::Storage(Box::new(source)))?;
                match projection::decode_consumer(
                    *account,
                    consumer.identifier_key,
                    consumer.lite_username.0,
                    consumer.full_username.map(|username| username.0),
                    ss58_prefix,
                    block_hash,
                    block_number,
                ) {
                    Ok(record) => {
                        projection::upsert(&mut tx, &record, block_number_db).await?;
                        block_upserts += 1;
                    }
                    Err(error) => {
                        projection::delete_account(&mut tx, account).await?;
                        block_failures += 1;
                        tracing::warn!(stage = "username", account = ?account, error = ?error, "deleting now-malformed consumer");
                    }
                }
            }
            None => {
                projection::delete_account(&mut tx, account).await?;
                block_deletes += 1;
            }
        }
    }

    advance_checkpoint(
        &mut tx,
        block_number_db,
        &block_hash,
        block_upserts,
        block_failures,
    )
    .await?;
    tx.commit().await?;

    report.accounts_upserted += block_upserts;
    report.accounts_deleted += block_deletes;
    report.decode_failures += block_failures;
    Ok(())
}

/// Advance the single-row checkpoint to `block_number` within an open tx.
async fn advance_checkpoint(
    tx: &mut Transaction<'_, Postgres>,
    block_number: i64,
    block_hash: &[u8; 32],
    records_indexed: u64,
    decode_failures: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE sync_state SET
            last_finalized_number = $1,
            last_finalized_hash = $2,
            last_synced_at = now(),
            records_indexed = $3,
            decode_failures = $4,
            updated_at = now()
         WHERE id = 1",
    )
    .bind(block_number)
    .bind(block_hash.as_slice())
    .bind(records_indexed as i64)
    .bind(decode_failures as i64)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn accounts_from_events(
    events: &subxt::events::Events<chain_types::PeopleConfig>,
) -> Result<Vec<[u8; 32]>, IndexError> {
    let mut affected: Vec<[u8; 32]> = Vec::new();
    for event in events.find::<people::resources::events::LitePersonRegistered>() {
        let event = event.map_err(|source| IndexError::Storage(Box::new(source)))?;
        affected.push(event.account.0);
    }
    for event in events.find::<people::resources::events::PersonRegistered>() {
        let event = event.map_err(|source| IndexError::Storage(Box::new(source)))?;
        affected.push(event.account.0);
    }
    for event in events.find::<people::resources::events::IdentifierKeyUpdated>() {
        let event = event.map_err(|source| IndexError::Storage(Box::new(source)))?;
        affected.push(event.account.0);
    }
    for event in events.find::<people::people_lite::events::ConsumerRegistered>() {
        let event = event.map_err(|source| IndexError::Storage(Box::new(source)))?;
        affected.push(event.account.0);
    }
    Ok(affected)
}

/// Deduplicate affected accounts deterministically for stable per-block reads.
fn dedupe_accounts(accounts: impl IntoIterator<Item = [u8; 32]>) -> Vec<[u8; 32]> {
    accounts
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        dedupe_accounts, plan_speculative_window, SpeculativeCache, SpeculativeWindow,
        MAX_SPECULATIVE_WINDOW,
    };

    #[test]
    fn nothing_to_speculate_when_finality_has_caught_up() {
        assert_eq!(plan_speculative_window(10, 10), SpeculativeWindow::Nothing);
        assert_eq!(plan_speculative_window(10, 9), SpeculativeWindow::Nothing);
    }

    #[test]
    fn scans_the_gap_starting_one_past_the_checkpoint() {
        assert_eq!(
            plan_speculative_window(10, 13),
            SpeculativeWindow::Scan { from: 11, to: 13 }
        );
        // Comfortably past the measured People trail of 2-5 blocks.
        assert_eq!(
            plan_speculative_window(100, 114),
            SpeculativeWindow::Scan { from: 101, to: 114 }
        );
    }

    #[test]
    fn stands_down_once_the_window_stops_looking_like_a_finality_trail() {
        let edge = MAX_SPECULATIVE_WINDOW;
        assert_eq!(
            plan_speculative_window(0, edge),
            SpeculativeWindow::Scan { from: 1, to: edge }
        );
        assert_eq!(
            plan_speculative_window(0, edge + 1),
            SpeculativeWindow::StandDown
        );
    }

    #[test]
    fn dedupe_removes_duplicates_and_sorts() {
        let deduped = dedupe_accounts([[3; 32], [1; 32], [3; 32], [2; 32], [1; 32]]);
        assert_eq!(deduped, vec![[1; 32], [2; 32], [3; 32]]);
    }

    #[test]
    fn dedupe_is_deterministic_regardless_of_input_order() {
        let forward = dedupe_accounts([[1; 32], [2; 32], [3; 32]]);
        let reversed = dedupe_accounts([[3; 32], [2; 32], [1; 32]]);
        assert_eq!(forward, reversed);
    }

    #[test]
    fn cache_answers_a_height_only_for_the_hash_it_was_read_from() {
        let mut cache = SpeculativeCache::new();
        cache.insert(10, [0xaa; 32], vec![[1; 32]]);

        assert_eq!(cache.get(10, &[0xaa; 32]), Some([[1; 32]].as_slice()));
        assert_eq!(cache.get(10, &[0xbb; 32]), None);
        assert_eq!(cache.get(11, &[0xaa; 32]), None);
    }

    #[test]
    fn cache_forgets_heights_finality_has_reached() {
        let mut cache = SpeculativeCache::new();
        for number in 8..=12 {
            cache.insert(number, [number as u8; 32], vec![[number as u8; 32]]);
        }

        cache.prune_finalized(10);

        for number in 8..=10 {
            assert_eq!(cache.get(number, &[number as u8; 32]), None);
        }
        for number in 11..=12 {
            assert!(cache.get(number, &[number as u8; 32]).is_some());
        }
    }

    #[test]
    fn a_wide_window_still_reconciles_rows_it_already_holds() {
        let plan = plan_speculative_window(0, MAX_SPECULATIVE_WINDOW + 1);
        assert_eq!(plan, SpeculativeWindow::StandDown);
        assert!(!matches!(plan, SpeculativeWindow::Scan { .. }));
    }
}
