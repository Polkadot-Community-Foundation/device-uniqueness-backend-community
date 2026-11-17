// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::time::{Duration, Instant};

use subxt::utils::AccountId32;
use tokio::sync::watch;

use super::{
    error::WriterError,
    hex_account,
    observe::{record_outbox_gauges, record_spec_version},
    WriterConfig,
};
use crate::chain::{asset_hub::AssetHub, people::PeopleChain};

/// How long one attester-resource read may take.
const RESOURCE_READ_TIMEOUT: Duration = Duration::from_secs(30);

// A job that fires on its own interval.
struct Ticker {
    every: Duration,
    last: Option<Instant>,
}

impl Ticker {
    fn new(every: Duration) -> Self {
        Self { every, last: None }
    }

    // Whether the job is due, marking it run if so.
    fn due(&mut self) -> bool {
        if self.last.is_none_or(|t| t.elapsed() >= self.every) {
            self.last = Some(Instant::now());
            return true;
        }
        false
    }
}

// The writer's periodic passes and when each is next due.
pub(super) struct Passes {
    resources: Ticker,
    /// The Asset Hub half of the resource read, on its own ticker so it is
    /// not consumed while the dotNS lane has yet to connect: the first read
    /// then happens as soon as the link is up, not a whole interval later.
    asset_hub_resources: Ticker,
    stranded: Ticker,
    asset_hub: watch::Receiver<Option<AssetHub>>,
}

impl Passes {
    pub(super) fn new(config: &WriterConfig, asset_hub: watch::Receiver<Option<AssetHub>>) -> Self {
        Self {
            resources: Ticker::new(config.resource_poll_interval),
            asset_hub_resources: Ticker::new(config.resource_poll_interval),
            stranded: Ticker::new(config.queue_fallback_after),
            asset_hub,
        }
    }

    // Run whatever is due.
    pub(super) async fn tick(
        &mut self,
        pool: &sqlx::PgPool,
        chain: &PeopleChain,
        signer_account: &AccountId32,
        proxy_for: Option<[u8; 32]>,
        config: &WriterConfig,
    ) {
        if self.resources.due() {
            bounded(
                people_resources(chain, signer_account, proxy_for, config),
                "attester resources",
            )
            .await;
            if let Err(e) = record_outbox_gauges(pool).await {
                tracing::warn!(error = %e, "outbox gauge pass failed");
            }
        }
        let asset_hub = self.asset_hub.borrow().clone();
        if let Some(asset_hub) = asset_hub.filter(|_| self.asset_hub_resources.due()) {
            bounded(
                asset_hub_resources(&asset_hub, signer_account, config),
                "dotns attester resources",
            )
            .await;
        }

        self.queue(pool, config).await;
    }

    // The queue's two mutually exclusive halves.
    async fn queue(&mut self, pool: &sqlx::PgPool, config: &WriterConfig) {
        if config.queue_enabled {
            if !self.stranded.due() {
                return;
            }
            match crate::queue::stranded_queued(pool).await {
                Ok(0) => {}
                Ok(stranded) => tracing::warn!(
                    stranded,
                    "queue advancer is down with claims queued; holding the throttle \
                     (queue enabled — not draining). Restart registration-queue, or \
                     retire the queue by setting QUEUE_ENABLED=false everywhere."
                ),
                Err(e) => tracing::warn!(error = %e, "stranded-queue check failed"),
            }
        } else {
            match crate::queue::fallback_drain(pool, config.queue_fallback_after).await {
                Ok(0) => {}
                Ok(drained) => tracing::warn!(
                    drained,
                    "queue disabled with advancer gone; promoted leftover queued claims"
                ),
                Err(e) => tracing::warn!(error = %e, "queue janitor drain failed"),
            }
        }
    }
}

/// Run one resource read under [`RESOURCE_READ_TIMEOUT`], logging a failure.
async fn bounded(
    read: impl std::future::Future<Output = Result<(), WriterError>>,
    what: &'static str,
) {
    match tokio::time::timeout(RESOURCE_READ_TIMEOUT, read).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "{what} read failed"),
        Err(_) => tracing::warn!(
            timeout_secs = RESOURCE_READ_TIMEOUT.as_secs(),
            "{what} read timed out"
        ),
    }
}

async fn people_resources(
    chain: &PeopleChain,
    signer_account: &AccountId32,
    proxy_for: Option<[u8; 32]>,
    config: &WriterConfig,
) -> Result<(), WriterError> {
    let allowance_account = config.attester;
    let allowance = chain.attestation_allowance(allowance_account).await?;
    let signer_balance = chain.free_balance(signer_account.0).await?;
    let primary_balance = match proxy_for {
        Some(primary) => Some(chain.free_balance(primary).await?),
        None => None,
    };

    tracing::info!(
        allowance,
        allowance_account = %hex_account(&allowance_account),
        signer = %hex_account(&signer_account.0),
        signer_balance_planck = signer_balance,
        primary_balance_planck = primary_balance,
        "attester_resources"
    );
    metrics::gauge!("dub_attester_allowance").set(allowance as f64);
    record_spec_version("people", chain.online()).await;
    metrics::gauge!(
        "dub_account_free_balance_planck",
        "role" => "signer",
        "chain" => "people"
    )
    .set(signer_balance as f64);
    if let Some(primary) = primary_balance {
        metrics::gauge!(
            "dub_account_free_balance_planck",
            "role" => "primary",
            "chain" => "people"
        )
        .set(primary as f64);
    }

    if allowance < config.allowance_floor {
        tracing::warn!(
            allowance,
            floor = config.allowance_floor,
            allowance_account = %hex_account(&allowance_account),
            "attestation allowance below floor; registration stops at zero"
        );
    }
    if signer_balance < config.signer_balance_floor_planck {
        tracing::warn!(
            signer_balance_planck = signer_balance,
            floor_planck = config.signer_balance_floor_planck,
            signer = %hex_account(&signer_account.0),
            "chain-writer signer balance below floor; registrations will fail to pay fees"
        );
    }
    Ok(())
}

async fn asset_hub_resources(
    asset_hub: &AssetHub,
    signer_account: &AccountId32,
    config: &WriterConfig,
) -> Result<(), WriterError> {
    let allowance_account = config.attester;
    let allowance = asset_hub.attestation_allowance(allowance_account).await?;
    let ah_signer_balance = asset_hub.free_balance(signer_account.0).await?;
    tracing::info!(
        allowance,
        allowance_account = %hex_account(&allowance_account),
        signer_balance_planck = ah_signer_balance,
        "dotns_attester_resources"
    );
    metrics::gauge!("dub_dotns_attester_allowance").set(allowance as f64);
    record_spec_version("asset-hub", asset_hub.online()).await;
    metrics::gauge!(
        "dub_account_free_balance_planck",
        "role" => "signer",
        "chain" => "asset-hub"
    )
    .set(ah_signer_balance as f64);

    if allowance < config.allowance_floor {
        tracing::warn!(
            allowance,
            floor = config.allowance_floor,
            allowance_account = %hex_account(&allowance_account),
            "dotns gateway allowance below floor; reservations stop at zero"
        );
    }
    if ah_signer_balance < config.signer_balance_floor_planck {
        tracing::warn!(
            signer_balance_planck = ah_signer_balance,
            floor_planck = config.signer_balance_floor_planck,
            signer = %hex_account(&signer_account.0),
            "chain-writer signer balance on Asset Hub below floor; \
             failed reservations will not pay their fees"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticker_is_due_at_startup_and_then_waits_out_its_interval() {
        let mut ticker = Ticker::new(Duration::from_secs(3600));
        assert!(ticker.due(), "the first turn runs the pass");
        assert!(!ticker.due(), "the interval has not elapsed");
        assert!(!ticker.due());
    }
}
