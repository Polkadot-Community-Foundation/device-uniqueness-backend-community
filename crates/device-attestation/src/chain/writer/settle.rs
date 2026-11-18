// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Settling dotNS pending claims from the writer's Asset Hub signer.
//!
//! The gateway mints from a Root origin, which pallet-revive does not let
//! deploy a contract, so a name whose owner has no `LabelStore` yet is kept by
//! `DotnsPopController` as a pending claim. It stays pending until a signed
//! origin calls `settlePendingClaims(user, limit)`, which deploys the store and
//! writes the label. That call is permissionless and its signer pays the fee
//! and the store's deposit. Device-name holders have no Asset Hub funds, so
//! nobody else makes it.
//! makes it.
//!
//! Settlement runs in the dotNS lane, between its passes and on its nonce, so
//! it never races a reservation submission. Each step walks one page of the
//! controller's own set of accounts with pending claims, dry-runs each
//! settlement, and submits the ones that would go through as one
//! `Utility.force_batch` of `Revive.call`s, never proxied.
//!
//! The signer's free balance also pays `reserve_name`'s fee up front, so a
//! step only spends what it holds above the signer balance floor: settlement
//! never starves the reservations the lane exists for.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::Result;
use chain_types::{AssetHubConfig, AssetHubExtrinsicParamsBuilder};
use subxt::dynamic::Value;
use subxt::extrinsics::ExtrinsicEvents;
use subxt::metadata::ArcMetadata;
use subxt::tx::DynamicPayload;
use subxt::utils::{AccountId32, H160};

use super::dotns::Dotns;
use super::engine::{finalize, Cx, Drain};
use super::events::item_results;
use super::passes::Ticker;
use super::tx::{build_contract_batch_tx, build_map_account_tx, ContractCall};
use crate::chain::asset_hub::AssetHub;
use crate::chain::dotns::Settlement;

/// Every value `dub_dotns_settle_total`'s `outcome` label takes.
const SETTLE_OUTCOMES: [&str; 3] = ["ok", "failed", "revert"];

/// When and how much the writer settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SettleConfig {
    /// Whether the writer settles at all (`DOTNS_SETTLE_ENABLED`).
    pub enabled: bool,
    /// The least time between two settlement steps
    /// (`DOTNS_SETTLE_INTERVAL_SECS`).
    pub interval: Duration,
    /// Pending claims settled per account per call
    /// (`DOTNS_SETTLE_CLAIM_LIMIT`).
    pub claim_limit: u64,
    /// Accounts settled per step, all in one extrinsic
    /// (`DOTNS_SETTLE_MAX_ACCOUNTS`).
    pub max_accounts: u64,
}

/// The settlement step's state between passes.
pub(super) struct Settler {
    config: SettleConfig,
    /// The signer free balance, in planck, settlement never spends below
    /// (`ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK`): it is what `reserve_name`
    /// pays its fees from.
    balance_floor: u128,
    ticker: Ticker,
    /// Where the next page of pending accounts starts. It stays put while a
    /// page still holds an account to settle, and moves past a page once every
    /// account on it is in `passed`. It returns to the start once a page comes
    /// back empty.
    cursor: u64,
    /// The accounts this walk passes over: their settlement would revert, or
    /// failed in its block, or never fits an extrinsic. They are kept by
    /// address, not by count, because the controller's set is an
    /// `EnumerableSet` whose `remove` moves its last account into the freed
    /// slot, so positions shift under the cursor. Cleared when the walk
    /// wraps, so every account is tried again once per walk.
    passed: HashSet<H160>,
}

impl Settler {
    /// A settler whose first step is due at once, which never spends the
    /// signer below `balance_floor` planck.
    pub(super) fn new(config: SettleConfig, balance_floor: u128) -> Self {
        for outcome in SETTLE_OUTCOMES {
            metrics::counter!("dub_dotns_settle_total", "outcome" => outcome).absolute(0);
        }
        Self {
            config,
            balance_floor,
            ticker: Ticker::new(config.interval),
            cursor: 0,
            passed: HashSet::new(),
        }
    }

    /// Settle one page of pending accounts, if settlement is on and due.
    pub(super) async fn step(&mut self, drain: &mut Drain<Dotns>, cx: &Cx<'_>) {
        if !self.config.enabled || !self.ticker.due() {
            return;
        }
        drain
            .aside(cx, "dotns settlement", async |chain, nonce| {
                self.settle(cx, chain, nonce).await
            })
            .await;
    }

    /// One settlement step with `nonce`. `Ok(true)` when it submitted.
    async fn settle(&mut self, cx: &Cx<'_>, chain: &AssetHub, nonce: u64) -> Result<bool> {
        let signer = cx.signer_account.0;
        let Some(funds) = spendable(chain.free_balance(signer).await?, self.balance_floor) else {
            tracing::warn!(
                floor_planck = self.balance_floor,
                "dotns settlement paused: the signer is at its balance floor, \
                 which reservations need for their fees"
            );
            return Ok(false);
        };
        if !chain.is_revive_mapped(&signer).await? {
            tracing::info!("mapping the writer's signer in pallet-revive before it settles");
            submit(cx, chain, nonce, &build_map_account_tx()).await?;
            return Ok(true);
        }

        let at = chain.online().at_current_block().await?;
        let contracts = chain.dotns_contracts(&at).await?;
        let pending = contracts.pending_claim_users(&at).await?;
        metrics::gauge!("dub_dotns_pending_claim_accounts").set(pending as f64);
        let page = contracts
            .pending_claim_page(&at, self.cursor, self.config.max_accounts)
            .await?;
        if page.is_empty() {
            self.cursor = 0;
            self.passed.clear();
            return Ok(false);
        }

        let candidates: Vec<H160> = page
            .iter()
            .copied()
            .filter(|user| !self.passed.contains(user))
            .collect();
        let dry_runs = candidates.iter().map(|user| {
            contracts.dry_run_settlement(&at, AccountId32(signer), *user, self.config.claim_limit)
        });
        let dry_runs = futures::future::try_join_all(dry_runs).await?;
        let mut settlements: Vec<Settlement> = Vec::with_capacity(dry_runs.len());
        for (user, dry_run) in candidates.iter().zip(dry_runs) {
            match dry_run {
                Some(settlement) => settlements.push(settlement),
                None => {
                    self.passed.insert(*user);
                }
            }
        }
        let skipped = candidates.len() - settlements.len();
        metrics::counter!("dub_dotns_settle_total", "outcome" => "revert")
            .increment(skipped as u64);

        let budget = budget_of(chain.max_extrinsic_weight().await?);
        let calls = pack(contracts.controller(), &settlements, budget, funds);
        if calls.is_empty() {
            if let Some(first) = settlements.first() {
                if fits(first, budget) {
                    tracing::warn!(
                        funds_planck = funds,
                        deposit_planck = deposit_limit(first.deposit),
                        floor_planck = self.balance_floor,
                        "dotns settlement paused: the next deposit would take \
                         the signer below its balance floor"
                    );
                } else {
                    // It would hold the cursor here for good, so pass it.
                    self.passed.insert(first.user);
                    tracing::warn!(
                        user = ?first.user,
                        budget = ?budget,
                        "a single dotns settlement does not fit the extrinsic budget"
                    );
                }
            }
            self.cursor = next_cursor(self.cursor, &page, &self.passed);
            return Ok(false);
        }
        // `pack` takes a leading run, so these are the settlements submitted.
        let submitted = &settlements[..calls.len()];
        let (events, metadata) = submit(cx, chain, nonce, &build_contract_batch_tx(&calls)).await?;
        let items = item_results(&events, &metadata)?;
        if items.len() != submitted.len() {
            // The nonce was spent, so the step counts as submitted; the
            // controller's own count shows what settled on the next step.
            tracing::warn!(
                items = items.len(),
                calls = submitted.len(),
                "dotns settlement batch results do not line up with its calls"
            );
            self.cursor = next_cursor(self.cursor, &page, &self.passed);
            return Ok(true);
        }
        let failed = items.iter().filter(|item| item.is_err()).count();
        let settled = items.len() - failed;
        metrics::counter!("dub_dotns_settle_total", "outcome" => "ok").increment(settled as u64);
        metrics::counter!("dub_dotns_settle_total", "outcome" => "failed").increment(failed as u64);
        for (settlement, item) in submitted.iter().zip(&items) {
            if let Err(error) = item {
                // Still pending; retrying it every step would hold the cursor.
                self.passed.insert(settlement.user);
                tracing::warn!(user = ?settlement.user, %error, "dotns settlement failed");
            }
        }
        self.cursor = next_cursor(self.cursor, &page, &self.passed);
        tracing::info!(
            settled,
            failed,
            skipped,
            pending,
            "dotns pending claims settled"
        );
        Ok(true)
    }
}

/// Sign `payload` with the writer's signer at `nonce`, submit it, and await
/// finalization.
async fn submit(
    cx: &Cx<'_>,
    chain: &AssetHub,
    nonce: u64,
    payload: &DynamicPayload<Vec<Value>>,
) -> Result<(ExtrinsicEvents<AssetHubConfig>, ArcMetadata)> {
    let params = AssetHubExtrinsicParamsBuilder::new().nonce(nonce).build();
    let at = chain.online().at_current_block().await?;
    let signed = chain_client::create_signed_v4(&at, payload, cx.signer, params).await?;
    finalize(cx, signed.submit_and_watch().await?).await
}

/// The weight limit for a call whose dry run required `weight`: a quarter more,
/// since the state may move between the dry run and the block.
#[must_use]
fn weight_limit((ref_time, proof_size): (u64, u64)) -> (u64, u64) {
    let grow = |part: u64| part.saturating_add(part / 4);
    (grow(ref_time), grow(proof_size))
}

/// The storage-deposit limit for a call whose dry run charged `deposit`: a
/// tenth more, for the same reason.
#[must_use]
fn deposit_limit(deposit: u128) -> u128 {
    deposit.saturating_add(deposit / 10)
}

/// The weight one settlement extrinsic may use: half of what a normal
/// extrinsic may, so one never fills a block the dotNS lane also needs.
#[must_use]
fn budget_of((ref_time, proof_size): (u64, u64)) -> (u64, u64) {
    (ref_time / 2, proof_size / 2)
}

/// What the signer may spend on settlement: its `free` balance above `floor`,
/// or `None` when it holds nothing above it.
#[must_use]
fn spendable(free: u128, floor: u128) -> Option<u128> {
    free.checked_sub(floor).filter(|funds| *funds > 0)
}

/// Whether `settlement`'s weight limit fits `budget` on its own.
#[must_use]
fn fits(settlement: &Settlement, budget: (u64, u64)) -> bool {
    let limit = weight_limit(settlement.weight);
    limit.0 <= budget.0 && limit.1 <= budget.1
}

/// The leading `settlements` whose weight limits fit `budget`, and whose
/// deposit limits fit `funds`, together, as calls on `controller`. The rest
/// stay pending for a later step.
#[must_use]
fn pack(
    controller: H160,
    settlements: &[Settlement],
    budget: (u64, u64),
    funds: u128,
) -> Vec<ContractCall<'_>> {
    let mut used = (0u64, 0u64);
    let mut spent = 0u128;
    let mut calls = Vec::new();
    for settlement in settlements {
        let limit = weight_limit(settlement.weight);
        let deposit = deposit_limit(settlement.deposit);
        let next = (
            used.0.saturating_add(limit.0),
            used.1.saturating_add(limit.1),
        );
        let next_spent = spent.saturating_add(deposit);
        if next.0 > budget.0 || next.1 > budget.1 || next_spent > funds {
            break;
        }
        used = next;
        spent = next_spent;
        calls.push(ContractCall {
            dest: controller,
            weight_limit: limit,
            storage_deposit_limit: deposit,
            data: &settlement.data,
        });
    }
    calls
}

/// Where the next page starts after a step over `page` at `cursor`. The
/// cursor moves past the page only once every account on it is `passed`:
/// a settled account's slot is refilled with the set's last account, so a
/// page that settled anything is read again, and an account left for want of
/// budget or funds is tried again.
#[must_use]
fn next_cursor(cursor: u64, page: &[H160], passed: &HashSet<H160>) -> u64 {
    if page.iter().all(|user| passed.contains(user)) {
        cursor.saturating_add(u64::try_from(page.len()).unwrap_or(u64::MAX))
    } else {
        cursor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_leave_headroom_over_the_dry_run() {
        assert_eq!(weight_limit((400, 80)), (500, 100), "a quarter more weight");
        assert_eq!(deposit_limit(1_000), 1_100, "a tenth more deposit");
        assert_eq!(deposit_limit(0), 0, "a refund needs no deposit");
        assert_eq!(
            weight_limit((u64::MAX, 0)),
            (u64::MAX, 0),
            "saturates instead of overflowing"
        );
    }

    fn settlement(proof_size: u64) -> Settlement {
        Settlement {
            user: H160::repeat_byte(1),
            data: vec![1],
            weight: (100, proof_size),
            deposit: 10,
        }
    }

    #[test]
    fn a_settlement_extrinsic_takes_half_the_extrinsic_limit() {
        assert_eq!(
            budget_of((1_600, 8_388_608)),
            (800, 4_194_304),
            "half of each part"
        );
    }

    #[test]
    fn settlements_are_packed_until_the_budget_is_spent() {
        // The paseo-next dry run: about 1.17 MB of proof each, 1.46 MB with
        // headroom, so two fit half of the 8 MiB extrinsic limit.
        let settlements = vec![settlement(1_166_006); 5];
        let calls = pack(
            H160::zero(),
            &settlements,
            budget_of((u64::MAX, 8_388_608)),
            u128::MAX,
        );
        assert_eq!(calls.len(), 2, "two settlements fit the proof budget");
        assert_eq!(
            calls[0].weight_limit,
            weight_limit((100, 1_166_006)),
            "each call carries its own headroom"
        );
        assert_eq!(
            calls[0].storage_deposit_limit, 11,
            "and its deposit headroom"
        );

        assert!(
            pack(H160::zero(), &settlements, (u64::MAX, 1_000), u128::MAX).is_empty(),
            "one that never fits is not sent"
        );
        assert!(!fits(&settlements[0], (u64::MAX, 1_000)));
        assert!(fits(&settlements[0], budget_of((u64::MAX, 8_388_608))));
    }

    #[test]
    fn settlement_spends_only_what_the_signer_holds_above_its_floor() {
        assert_eq!(spendable(1_000, 400), Some(600));
        assert_eq!(spendable(400, 400), None, "at the floor, nothing");
        assert_eq!(spendable(100, 400), None, "below it, nothing");

        // Each deposit limit is 11 (10 plus a tenth).
        let settlements = vec![settlement(1); 5];
        let budget = (u64::MAX, u64::MAX);
        assert_eq!(pack(H160::zero(), &settlements, budget, 33).len(), 3);
        assert_eq!(
            pack(H160::zero(), &settlements, budget, 32).len(),
            2,
            "a deposit that would cross the floor is left for a later step"
        );
        assert!(pack(H160::zero(), &settlements, budget, 10).is_empty());
    }

    #[test]
    fn the_cursor_moves_past_a_page_only_once_every_account_on_it_is_passed() {
        let (a, b) = (H160::repeat_byte(1), H160::repeat_byte(2));
        let page = [a, b];
        let mut passed = HashSet::new();
        assert_eq!(
            next_cursor(4, &page, &passed),
            4,
            "settled slots are refilled from the end of the set, so read the page again"
        );
        passed.insert(b);
        assert_eq!(
            next_cursor(4, &page, &passed),
            4,
            "a passed account is skipped by address, not by holding the cursor on it"
        );
        passed.insert(a);
        assert_eq!(
            next_cursor(4, &page, &passed),
            6,
            "an all-passed page is left"
        );
        assert_eq!(next_cursor(u64::MAX, &page, &passed), u64::MAX, "saturates");
    }
}
