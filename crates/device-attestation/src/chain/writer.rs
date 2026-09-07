// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::HashMap,
    str::FromStr as _,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use chain_types::{AssetHubExtrinsicParamsBuilder, PeopleExtrinsicParamsBuilder};
use secrecy::{ExposeSecret as _, SecretString};
use sqlx::PgPool;
use subxt::{
    client::OnlineClientAtBlockT,
    dynamic::Value,
    extrinsics::ExtrinsicEvents,
    metadata::ArcMetadata,
    tx::{DynamicPayload, TransactionProgress},
    utils::AccountId32,
};
use time::OffsetDateTime;

use chain_client::{settle_batch_size, WriterSigner};

use super::asset_hub::{AssetHub, ValidityWindow};
use super::lease;
use super::outbox::{self, Guard, Reservation};
use super::people::PeopleChain;
use super::registry::NameRegistry as _;
use crate::dotns;

mod events;
#[cfg(test)]
mod fixtures;
mod lane;
mod observe;
mod tx;

use events::{check_proxied_call, item_results};
use lane::{Defer, Dotns, Lane as _, Outcome, People};
use observe::{
    record_outbox_gauges, record_spec_version, record_writer_info, zero_init_submit_outcomes,
};
use tx::{
    build_registration_batch_tx, build_registration_tx, build_reserve_name_batch_tx,
    build_reserve_name_tx,
};

/// The claim size a writer uses when `CHAIN_WRITER_BATCH_SIZE` is unset or
/// unusable. Also the AIMD ceiling every lane climbs back to.
const DEFAULT_BATCH_SIZE: u16 = 25;

/// Consecutive successful submissions a lane must post before it relaxes a
/// known-bad size back by one and probes it again.
///
/// Without it the AIMD alternates forever against a chain that rejects every
/// batch of two or more — halve to 1, succeed, grow to 2, fail, halve to 1 —
/// paying a fee and a nonce on every other pass and never converging. See
/// [`BatchLane::ceiling`].
const CEILING_PROBE_RUN: u16 = 20;

/// The shared backoff for rows re-queued by a *reconcile*, as opposed to a
/// whole-batch failure. The batch did submit, so there is no failure run to
/// escalate against; the rows only need long enough for the chain state that
/// decided them to settle.
const BATCH_RECONCILE_BACKOFF: time::Duration = time::Duration::seconds(10);

/// How many `SUBMITTING` rows one startup-reconcile owner read covers. A writer
/// that died mid-drain can leave far more than a batch's worth, and a single
/// unbounded read over all of them is one point of failure for the whole
/// reconcile.
const RECONCILE_READ_CHUNK: usize = 50;

/// Chain-writer configuration, loaded from the environment.
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// password, so it is a secret.
    pub database_url: SecretString,
    pub people_rpc_url: String,
    /// SURI of the hot signing key (the proxy key, or the primary in dev).
    pub signer_suri: SecretString,
    /// Attester authority (`ATTESTER_ACCOUNT`), the account device-attestation-api also
    /// publishes. Proxying is derived from it — see
    /// [`WriterSigner::proxy_for`].
    pub attester: [u8; 32],
    pub holder_id: String,
    /// Lease row name (all writers of one account share it).
    pub lease_name: String,
    /// Lease TTL / heartbeat expiry.
    pub lease_ttl: Duration,
    /// Idle poll interval between outbox scans.
    pub poll_interval: Duration,
    /// **Maximum** rows claimed per scan, and the ceiling the adaptive batch
    /// size climbs back to. Not a fixed claim size: a whole-batch failure
    /// halves the size in use, a success grows it by one, floor 1.
    pub batch_size: u16,
    /// Per-submit finalization timeout.
    pub finalize_timeout: Duration,
    /// Max submit attempts before a row is failed terminally.
    pub max_attempts: i32,
    /// Whether the registration queue is enabled (`QUEUE_ENABLED` — must
    /// match device-attestation-api's value). On: `QUEUED` rows are never drained here;
    /// a dead advancer only raises the stranded-queue warning, keeping the
    /// free lane's throttle intact. Off: this writer is the janitor that
    /// drains leftover `QUEUED` rows so retiring the queue strands nothing.
    pub queue_enabled: bool,
    /// Janitor grace (queue disabled only): how long the advancer's lease may
    /// be expired before leftover `QUEUED` rows are drained — the window that
    /// lets a live advancer finish a fair drain during the retire sequence.
    /// Doubles as the warning cadence while the queue is enabled.
    pub queue_fallback_after: Duration,
    /// Cadence of the payment watch pass (deposit detection + expiry over
    /// `payment_requests`). Read-only on chain; a no-op while the payment
    /// lane has never quoted anything.
    pub payment_poll_interval: Duration,
    /// Cadence of the attester-resources pass: read the attestation allowance
    /// and the account balances that registration silently dies without.
    pub resource_poll_interval: Duration,
    /// WARN below this many remaining attestations.
    pub allowance_floor: u32,
    /// WARN below this signer free balance, in planck (transaction fees come
    /// from the signer, not the proxied primary).
    pub signer_balance_floor_planck: u128,
    /// Whether the dotNS gateway lane is live (`DOTNS_GATEWAY_ENABLED`). Must
    /// match device-attestation-api's value, which gates intake. When off, no Asset Hub
    /// connection is opened at all and `dotns_status` rows are left alone.
    pub dotns_gateway_enabled: bool,
    /// Asset Hub RPC endpoint. Required when the dotNS lane is enabled.
    pub asset_hub_rpc_url: Option<String>,
}

impl WriterConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = http_common::config::required_var("DEVICE_ATTESTATION_DATABASE_URL")?;
        let people_rpc_url = std::env::var("PEOPLE_RPC_URL")
            .unwrap_or_else(|_| "wss://previewnet.substrate.dev/people".to_string());
        let signer_suri = std::env::var("CHAIN_WRITER_SIGNER_SURI")
            .context("CHAIN_WRITER_SIGNER_SURI is required")?;
        let attester = crate::config::attester_account_from_env()?;
        let holder_id = match std::env::var("CHAIN_WRITER_HOLDER_ID") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => format!(
                "writer-{}-{:08x}",
                std::process::id(),
                rand::random::<u32>()
            ),
        };

        Ok(Self {
            database_url: SecretString::from(database_url),
            people_rpc_url,
            signer_suri: SecretString::from(signer_suri),
            attester,
            holder_id,
            lease_name: std::env::var("CHAIN_WRITER_LEASE_NAME")
                .unwrap_or_else(|_| "people-chain-writer".to_string()),
            lease_ttl: Duration::from_secs(env_u64("CHAIN_WRITER_LEASE_TTL_SECS", 30)),
            poll_interval: Duration::from_secs(env_u64("CHAIN_WRITER_POLL_SECS", 2)),
            batch_size: env_u16("CHAIN_WRITER_BATCH_SIZE", DEFAULT_BATCH_SIZE),
            finalize_timeout: Duration::from_secs(env_u64("CHAIN_WRITER_FINALIZE_SECS", 120)),
            max_attempts: env_u64("CHAIN_WRITER_MAX_ATTEMPTS", 8) as i32,
            queue_enabled: crate::config::env_bool("QUEUE_ENABLED", false)?,
            queue_fallback_after: Duration::from_secs(crate::queue::env_u64_strict(
                "QUEUE_FALLBACK_AFTER_SECS",
                60,
            )?),
            payment_poll_interval: Duration::from_secs(crate::queue::env_u64_strict(
                "PAYMENT_POLL_INTERVAL_SECS",
                30,
            )?),
            resource_poll_interval: Duration::from_secs(crate::queue::env_u64_strict(
                "ATTESTER_RESOURCE_POLL_SECS",
                60,
            )?),
            allowance_floor: u32::try_from(crate::queue::env_u64_strict(
                "ATTESTER_ALLOWANCE_FLOOR",
                100,
            )?)
            .context("ATTESTER_ALLOWANCE_FLOOR must fit a u32")?,
            signer_balance_floor_planck: u128::from(crate::queue::env_u64_strict(
                "ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK",
                10_000_000_000,
            )?),
            dotns_gateway_enabled: crate::config::env_bool("DOTNS_GATEWAY_ENABLED", false)?,
            asset_hub_rpc_url: match std::env::var("ASSET_HUB_RPC_URL") {
                Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
                _ => None,
            },
        })
    }
}

pub async fn run(config: WriterConfig) -> anyhow::Result<()> {
    tracing::info!(
        people_rpc = %config.people_rpc_url,
        attester = %hex_account(&config.attester),
        holder = %config.holder_id,
        "starting device-attestation-chain-writer"
    );
    let pool = crate::db::connect(config.database_url.expose_secret()).await?;
    let chain = PeopleChain::connect(&config.people_rpc_url).await?;
    let signer = WriterSigner::from_secret(config.signer_suri.expose_secret())?;
    let signer_account = AccountId32(signer.public_bytes());
    let proxy_for = signer
        .proxy_for(AccountId32(config.attester))
        .map(|primary| primary.0);

    let dotns_lane = match (config.dotns_gateway_enabled, &config.asset_hub_rpc_url) {
        (true, Some(url)) => {
            tracing::info!(
                asset_hub_rpc = %url,
                "dotns lane enabled; Asset Hub connects on the first pass"
            );
            DotnsLane::Enabled {
                rpc_url: url.clone(),
                connected: None,
                last_error: None,
                retry_at: None,
            }
        }
        (true, None) => anyhow::bail!(
            "DOTNS_GATEWAY_ENABLED is on but ASSET_HUB_RPC_URL is unset. device-attestation-api would \
             accept dotns blocks that nothing ever submits — set the RPC URL, or turn the \
             gateway off for this environment."
        ),
        (false, _) => {
            tracing::info!("dotns lane disabled");
            DotnsLane::Disabled
        }
    };
    tracing::info!(
        signer = %hex_account(&signer_account.0),
        attester = %hex_account(&config.attester),
        mode = if proxy_for.is_some() { "proxy" } else { "direct" },
        "device-attestation-chain-writer connected"
    );
    record_writer_info(&config, &signer_account);
    zero_init_submit_outcomes();
    http_common::metrics::spawn_readiness_probe(
        "device-attestation-chain-writer",
        (pool.clone(), chain.clone()),
        |(p, c)| crate::http::health::probe(p, c),
    );

    let batch_max = config.batch_size;
    let mut writer = Writer {
        pool,
        chain,
        dotns_lane,
        signer,
        signer_account,
        proxy_for,
        config,
        next_nonce: None,
        next_nonce_ah: None,
        batch_max,
        people_batch: BatchLane::new("people", batch_max),
        dotns_batch: BatchLane::new("dotns", batch_max),
    };
    writer.run_forever().await
}

struct Writer {
    pool: PgPool,
    chain: PeopleChain,
    dotns_lane: DotnsLane,
    signer: WriterSigner,
    signer_account: AccountId32,
    proxy_for: Option<[u8; 32]>,
    config: WriterConfig,
    next_nonce: Option<u64>,
    next_nonce_ah: Option<u64>,
    /// The ceiling both lanes' adaptive sizes climb back to
    /// (`CHAIN_WRITER_BATCH_SIZE`).
    batch_max: u16,
    /// People's current batch size, and its run of consecutive whole-batch
    /// failures (the shared backoff's exponent).
    people_batch: BatchLane,
    /// Asset Hub's own size and failure run. Deliberately separate: Asset Hub's
    /// weight budget and `reserve_name`'s cost — it dispatches into a contract
    /// — are unrelated to People's, so one shared number would be wrong for
    /// both.
    dotns_batch: BatchLane,
}

/// One lane's adaptive batch state.
#[derive(Debug, Clone, Copy)]
struct BatchLane {
    /// The `lane` label this state is published under.
    lane: &'static str,
    /// Rows claimed per pass right now. Starts at the configured maximum.
    size: u16,
    /// Consecutive whole-batch failures, reset by any successful submission.
    /// Drives the *shared* retry backoff: a per-row `2^attempt` would stampede
    /// the entire set back into the next pass at once.
    failures: u16,
    /// The smallest size known to have failed as a whole, if any. Growth stops
    /// one below it.
    ///
    /// Plain AIMD has no memory of what failed, so a chain that rejects every
    /// batch of two or more — a proxy whose `ProxyType` permits the inner call
    /// but not `Utility.force_batch` is the plausible one — makes it alternate
    /// forever: halve to 1, succeed, grow to 2, fail. Every other pass then
    /// pays a fee and burns a nonce on an included extrinsic whose
    /// `ProxyExecuted` is `Err`, leaving throughput below the pre-batching
    /// writer with nothing converging. Remembering the size that failed ends
    /// the alternation; [`CEILING_PROBE_RUN`] is what keeps it from being
    /// permanent after a merely transient failure.
    ceiling: Option<u16>,
    /// Consecutive successful submissions since `ceiling` last moved.
    clean: u16,
}

impl BatchLane {
    fn new(lane: &'static str, size: u16) -> Self {
        let lane = Self {
            lane,
            size,
            failures: 0,
            ceiling: None,
            clean: 0,
        };
        lane.record_size();
        lane
    }

    /// Records a successful submission: grow back toward the limit, clear the
    /// failure run, and after a long enough clean run relax the ceiling by one
    /// so a transient failure does not pin the lane forever.
    fn succeeded(&mut self, max: u16) {
        self.failures = 0;
        self.clean = self.clean.saturating_add(1);
        if self.clean >= CEILING_PROBE_RUN {
            self.clean = 0;
            self.ceiling = match self.ceiling {
                Some(c) if c < max => Some(c + 1),
                Some(_) => None,
                None => None,
            };
        }
        self.size = settle_batch_size(self.size, self.grow_limit(max), true);
        self.record_size();
    }

    /// Records a whole-batch failure: halve (floor 1), remember the size that
    /// failed, and return the shared backoff for re-queueing the set.
    fn failed(&mut self, max: u16) -> time::Duration {
        let attempted = self.size;
        self.size = settle_batch_size(self.size, max, false);
        if self.size < attempted {
            // Only when the halving actually moved: a batch of one failing is
            // not a size problem, and a ceiling of 1 would mean "never submit".
            self.ceiling = Some(self.ceiling.map_or(attempted, |c| c.min(attempted)));
        }
        self.clean = 0;
        self.failures = self.failures.saturating_add(1);
        metrics::counter!("dub_chain_batch_failed_total", "lane" => self.lane).increment(1);
        self.record_size();
        time::Duration::seconds(2i64.saturating_pow(u32::from(self.failures).clamp(1, 6)))
    }

    /// The largest size `succeeded` may grow to: the configured maximum, or one
    /// below the smallest size known to fail.
    fn grow_limit(&self, max: u16) -> u16 {
        match self.ceiling {
            Some(c) => max.min(c.saturating_sub(1)).max(1),
            None => max,
        }
    }

    /// The size an operator needs during an incident: a lane pinned at 1 is a
    /// chain rejecting whole batches, not a quiet queue.
    fn record_size(&self) {
        metrics::gauge!("dub_chain_batch_size", "lane" => self.lane).set(f64::from(self.size));
    }
}

const DOTNS_RECONNECT_INTERVAL: Duration = Duration::from_secs(30);

enum DotnsLane {
    Disabled,
    Enabled {
        rpc_url: String,
        connected: Option<(AssetHub, ValidityWindow)>,
        last_error: Option<String>,
        retry_at: Option<Instant>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DotnsDial {
    Ready,
    Dial,
    Skip,
}

impl DotnsLane {
    fn dial_state(&self, now: Instant) -> DotnsDial {
        match self {
            DotnsLane::Disabled => DotnsDial::Skip,
            DotnsLane::Enabled { connected, .. } if connected.is_some() => DotnsDial::Ready,
            DotnsLane::Enabled { retry_at, .. } => match retry_at {
                Some(at) if now < *at => DotnsDial::Skip,
                _ => DotnsDial::Dial,
            },
        }
    }

    fn record_dial_failure(&mut self, reason: String, now: Instant) -> bool {
        let DotnsLane::Enabled {
            last_error,
            retry_at,
            ..
        } = self
        else {
            return false;
        };
        *retry_at = Some(now + DOTNS_RECONNECT_INTERVAL);
        let is_new = last_error.as_deref() != Some(reason.as_str());
        if is_new {
            *last_error = Some(reason);
        }
        is_new
    }

    fn record_dial_success(&mut self, up: (AssetHub, ValidityWindow)) {
        if let DotnsLane::Enabled {
            connected,
            last_error,
            retry_at,
            ..
        } = self
        {
            *connected = Some(up);
            *last_error = None;
            *retry_at = None;
        }
    }
}

async fn connect_asset_hub(url: &str) -> anyhow::Result<(AssetHub, ValidityWindow)> {
    let client = AssetHub::connect(url).await?;
    let window = client.validity_window().await?;
    Ok((client, window))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubmitFailureAction {
    Assign,
    Park,
    Retry,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DotnsReject {
    NotInLane,
    UnbuildableLabel(String),
    UnbuildableReserved(String),
    BadSignature,
    Expired { signed_at: i64, deadline_secs: u64 },
    FutureDated { signed_at: i64, submittable_at: i64 },
}

const MAX_LABEL_BYTES: usize = 32;

fn check_dotns_submittable(
    r: &Reservation,
    candidate: &[u8; 32],
    attester: &[u8; 32],
    window: ValidityWindow,
    now: i64,
) -> Result<(), DotnsReject> {
    let (Some(signature), Some(signed_at)) = (&r.dotns_signature, r.dotns_signed_at) else {
        return Err(DotnsReject::NotInLane);
    };

    let label = &r.full_username;
    if label.len() > MAX_LABEL_BYTES {
        return Err(DotnsReject::UnbuildableLabel(format!(
            "lite label is {} bytes, over BaseLabel's {MAX_LABEL_BYTES}",
            label.len()
        )));
    }
    let base = dotns::lite_base(label);
    if base.len() == label.len() {
        return Err(DotnsReject::UnbuildableLabel(
            "lite label has no digit suffix".to_string(),
        ));
    }
    if let Some(reserved) = &r.reserved_username {
        if reserved.len() > MAX_LABEL_BYTES {
            return Err(DotnsReject::UnbuildableReserved(format!(
                "reservedUsername is {} bytes, over BaseLabel's {MAX_LABEL_BYTES}",
                reserved.len()
            )));
        }
    }

    let max_future_skew = i64::try_from(window.max_future_skew_secs).unwrap_or(i64::MAX);
    if signed_at > now.saturating_add(max_future_skew) {
        return Err(DotnsReject::FutureDated {
            signed_at,
            submittable_at: signed_at.saturating_sub(max_future_skew),
        });
    }

    if dotns::reservation_expired(signed_at, window.max_validity_secs, now) {
        return Err(DotnsReject::Expired {
            signed_at,
            deadline_secs: window.max_validity_secs,
        });
    }

    let signed_at = u64::try_from(signed_at).map_err(|_| DotnsReject::BadSignature)?;
    if !dotns::verify_reservation_signature(
        signature,
        candidate,
        attester,
        base.as_bytes(),
        &r.identifier_key,
        r.reserved_username.as_ref().map(|s| s.as_bytes()),
        signed_at,
    ) {
        return Err(DotnsReject::BadSignature);
    }
    Ok(())
}

/// The one runtime error that *is* success: the username is already registered
/// to the candidate, so the row is on chain and belongs in `ASSIGNED`.
const ALREADY_REGISTERED: &str = "PeopleLite::AlreadyRegistered";

const UNFUNDED_SIGNER: &str = "Inability to pay some fees";

const UNFUNDED_PARK_BACKOFF_SECS: i64 = 300;

/// Rejections that another submission cannot talk the runtime out of, so the
/// row fails on the first pass rather than paying `max_attempts` fees for the
/// same answer.
///
/// All three come from `attest`'s optional `reserved_username` leg, which the
/// runtime checks *before* it writes the lite username — so they cost the whole
/// registration. The intake preflight refuses these claims before a row exists;
/// what reaches here raced that check (a queue that filled in between). The
/// writer cannot resubmit without the reservation, because the consumer
/// signature covers it — only the client can re-sign.
///
/// `QueueFull` is not immutable in principle: entries expire and
/// `remove_expired_username_reservation` is permissionless. But nothing drains
/// within the seconds our backoff spans, so retrying only buys more fees.
const DETERMINISTIC_REJECTIONS: &[&str] = &[
    "Resources::UsernameReservationTaken",
    "Resources::QueueFull",
    "Resources::AlreadyHasReservation",
];

fn is_deterministic_rejection(reason: &str) -> bool {
    DETERMINISTIC_REJECTIONS
        .iter()
        .any(|rejection| reason.contains(rejection))
}

fn terminal_reason(reason: &str) -> String {
    if is_deterministic_rejection(reason) {
        format!("rejected deterministically, not retried: {reason}")
    } else {
        format!("max attempts reached: {reason}")
    }
}

fn classify_submit_failure(
    reason: &str,
    observed_owner: Option<[u8; 32]>,
    candidate: [u8; 32],
    completed_attempts: i32,
    max_attempts: i32,
) -> SubmitFailureAction {
    if observed_owner == Some(candidate) || reason.contains(ALREADY_REGISTERED) {
        SubmitFailureAction::Assign
    } else if reason.contains(UNFUNDED_SIGNER) {
        SubmitFailureAction::Park
    } else if is_deterministic_rejection(reason) || completed_attempts >= max_attempts {
        SubmitFailureAction::Fail
    } else {
        SubmitFailureAction::Retry
    }
}

impl Writer {
    async fn run_forever(&mut self) -> anyhow::Result<()> {
        loop {
            let guard = self.acquire_lease().await?;
            tracing::info!(epoch = guard.epoch, "acquired writer lease");
            self.next_nonce = None;
            self.next_nonce_ah = None;
            if let Err(e) = self.reconcile_submitting(&guard).await {
                tracing::warn!(error = %e, "startup reconcile failed");
            }
            if let Err(e) = self.reconcile_dotns_submitting(&guard).await {
                tracing::warn!(error = %e, "startup dotns reconcile failed");
            }
            if let Err(e) = self.active_loop(&guard).await {
                tracing::warn!(error = %e, "writer loop exited; re-acquiring lease");
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    async fn acquire_lease(&self) -> anyhow::Result<Guard> {
        loop {
            let epoch = lease::try_acquire(
                &self.pool,
                &self.config.lease_name,
                &self.config.holder_id,
                self.config.lease_ttl,
            )
            .await?;
            if let Some(epoch) = epoch {
                return Ok(Guard {
                    lease_name: self.config.lease_name.clone(),
                    holder_id: self.config.holder_id.clone(),
                    epoch,
                });
            }
            tracing::info!("writer lease held by another instance; waiting");
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    async fn heartbeat(&self, guard: &Guard) -> anyhow::Result<bool> {
        Ok(lease::renew(
            &self.pool,
            &guard.lease_name,
            &guard.holder_id,
            guard.epoch,
            self.config.lease_ttl,
        )
        .await?)
    }

    async fn active_loop(&mut self, guard: &Guard) -> anyhow::Result<()> {
        let mut last_payment_pass: Option<std::time::Instant> = None;
        let mut last_stranded_check: Option<std::time::Instant> = None;
        let mut last_resource_pass: Option<std::time::Instant> = None;
        loop {
            if !self.heartbeat(guard).await? {
                anyhow::bail!("lost writer lease");
            }
            if last_resource_pass.is_none_or(|t| t.elapsed() >= self.config.resource_poll_interval)
            {
                last_resource_pass = Some(std::time::Instant::now());
                if let Err(e) = self.log_attester_resources().await {
                    tracing::warn!(error = %e, "attester resources read failed");
                }
                if let Err(e) = record_outbox_gauges(&self.pool).await {
                    tracing::warn!(error = %e, "outbox gauge pass failed");
                }
            }
            if self.config.queue_enabled {
                if last_stranded_check
                    .is_none_or(|t| t.elapsed() >= self.config.queue_fallback_after)
                {
                    last_stranded_check = Some(std::time::Instant::now());
                    match crate::queue::stranded_queued(&self.pool).await {
                        Ok(0) => {}
                        Ok(stranded) => tracing::warn!(
                            stranded,
                            "queue advancer is down with claims queued; holding the throttle \
                             (queue enabled — not draining). Restart registration-queue, or \
                             retire the queue by setting QUEUE_ENABLED=false everywhere."
                        ),
                        Err(e) => tracing::warn!(error = %e, "stranded-queue check failed"),
                    }
                }
            } else {
                match crate::queue::fallback_drain(&self.pool, self.config.queue_fallback_after)
                    .await
                {
                    Ok(0) => {}
                    Ok(drained) => tracing::warn!(
                        drained,
                        "queue disabled with advancer gone; promoted leftover queued claims"
                    ),
                    Err(e) => tracing::warn!(error = %e, "queue janitor drain failed"),
                }
            }
            if last_payment_pass.is_none_or(|t| t.elapsed() >= self.config.payment_poll_interval) {
                last_payment_pass = Some(std::time::Instant::now());
                match crate::payment::watch_pass(&self.pool, &self.chain).await {
                    Ok(stats) if stats.acted() => tracing::info!(
                        expired = stats.expired,
                        confirmed = stats.confirmed,
                        conflicted = stats.conflicted,
                        still_pending = stats.still_pending,
                        "payment watch pass"
                    ),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "payment watch pass failed"),
                }
            }
            let due = outbox::claim_due(&self.pool, i64::from(self.people_batch.size)).await?;
            if !due.is_empty() {
                self.people_pass(guard, &due).await?;
            }
            self.dotns_pass(guard).await?;
            if due.is_empty() {
                tokio::time::sleep(self.config.poll_interval).await;
            }
        }
    }

    /// Drain one claimed set onto People Chain.
    ///
    /// Triage decides each row's fate offline and against one batched owner
    /// read; whatever is left is submitted as **one** extrinsic. A single-row
    /// set keeps the pre-batching path exactly — a bare `attest` whose
    /// `ProxyExecuted` is a genuine per-row verdict — because one registration
    /// should not pay for a `force_batch` wrapper.
    async fn people_pass(&mut self, guard: &Guard, due: &[Reservation]) -> anyhow::Result<()> {
        if !self.heartbeat(guard).await? {
            anyhow::bail!("lost writer lease");
        }
        let submittable = self.triage_people(guard, due).await?;
        match submittable.len() {
            0 => Ok(()),
            1 => {
                let (r, candidate) = submittable[0];
                self.process_one(guard, r, candidate).await
            }
            _ => self.process_people_batch(guard, &submittable).await,
        }
    }

    /// Resolve every row that can be decided without submitting anything, and
    /// return the rest paired with their parsed candidate accounts.
    ///
    /// The owner pre-check that used to cost one RPC round trip per row is one
    /// `state_queryStorageAt` for the whole set. Per-row behaviour is
    /// unchanged: owned by the candidate → `ASSIGNED`, owned by anyone else →
    /// terminal, unowned → submit. A failed read re-queues the rows it covered
    /// the way a failed batch is re-queued — unchanged `attempt`, one shared
    /// backoff; unknown is never read as free.
    async fn triage_people<'r>(
        &mut self,
        guard: &Guard,
        due: &'r [Reservation],
    ) -> anyhow::Result<Vec<(&'r Reservation, [u8; 32])>> {
        let mut parsed = Vec::with_capacity(due.len());
        for r in due {
            match parse_account(&r.candidate_account_id) {
                Ok(candidate) => parsed.push((r, candidate)),
                Err(_) => {
                    People::record(
                        &self.pool,
                        guard,
                        r,
                        Outcome::Failed("invalid candidate SS58"),
                    )
                    .await?
                }
            }
        }
        if parsed.is_empty() {
            return Ok(Vec::new());
        }

        let names: Vec<&str> = parsed
            .iter()
            .map(|(r, _)| r.full_username.as_str())
            .collect();
        let owners = match self.chain.owners(&names).await {
            Ok(owners) => owners,
            Err(e) => {
                // One read now covers the whole claimed set, so one bad
                // response defers all of them rather than one — and that makes
                // it a whole-batch fault, not any row's. Spending an attempt
                // each would send an entire claimed set to `FAILED_TERMINAL`
                // after eight flapping-RPC passes, and a per-row `2^attempt`
                // would put the whole set back into the very next pass at once,
                // re-forming the identical batch against the identical read.
                self.retry_people_batch(guard, &parsed, &format!("owner read failed: {e}"))
                    .await?;
                return Ok(Vec::new());
            }
        };

        let mut submittable = Vec::with_capacity(parsed.len());
        for (r, candidate) in parsed {
            match owners.get(&r.full_username) {
                Some(owner) if *owner == candidate => {
                    People::record(&self.pool, guard, r, Outcome::Observed).await?
                }
                Some(_) => {
                    People::record(
                        &self.pool,
                        guard,
                        r,
                        Outcome::Failed("username owned by another account"),
                    )
                    .await?
                }
                None => submittable.push((r, candidate)),
            }
        }
        Ok(submittable)
    }

    /// Submit one registration on its own. Row-level chain failures are
    /// recorded on the row (retry/fail); only a lost lease returns `Err`.
    ///
    /// The pre-batching path, unchanged, reached when triage leaves exactly one
    /// row submittable.
    async fn process_one(
        &mut self,
        guard: &Guard,
        r: &Reservation,
        candidate: [u8; 32],
    ) -> anyhow::Result<()> {
        let payload = build_registration_tx(r, &candidate, self.proxy_for.as_ref());
        let nonce = match self.nonce().await {
            Ok(n) => n,
            Err(e) => {
                return People::record(
                    &self.pool,
                    guard,
                    r,
                    Outcome::Retry(&format!("nonce fetch: {e}")),
                )
                .await
            }
        };

        match self.submit(guard, r, &payload, nonce).await {
            Ok(()) => {
                self.next_nonce = Some(nonce + 1);
                // A lone row still proves the lane works, so it grows the size
                // back toward the max after a halving search.
                self.people_batch.succeeded(self.batch_max);
                People::record(&self.pool, guard, r, Outcome::Landed).await
            }
            Err(e) => {
                self.next_nonce = None;
                let reason = e.to_string();

                let observed_owner = self.chain.owner(&r.full_username).await.ok().flatten();
                match classify_submit_failure(
                    &reason,
                    observed_owner,
                    candidate,
                    r.attempt + 1,
                    self.config.max_attempts,
                ) {
                    SubmitFailureAction::Assign => {
                        People::record(&self.pool, guard, r, Outcome::Landed).await
                    }
                    SubmitFailureAction::Park => {
                        People::record(&self.pool, guard, r, Outcome::Park(&reason)).await
                    }
                    SubmitFailureAction::Retry => {
                        People::record(&self.pool, guard, r, Outcome::Retry(&reason)).await
                    }
                    SubmitFailureAction::Fail => {
                        People::record(
                            &self.pool,
                            guard,
                            r,
                            Outcome::Failed(&terminal_reason(&reason)),
                        )
                        .await
                    }
                }
            }
        }
    }

    /// Submit a whole claimed set as one `Utility.force_batch`.
    ///
    /// Everything that can go wrong splits in two, and the split is the whole
    /// point:
    /// - a **whole-batch** failure (nonce, signing, transport, a proxy
    ///   rejection of the batch itself) is nobody's row's fault. It re-queues
    ///   the set at an unchanged `attempt` and halves the batch size. Without
    ///   this, eight flapping-RPC passes would send an entire claimed set to
    ///   `FAILED_TERMINAL` for a fault no row caused.
    /// - a **per-item** failure is that row's own, and spends its attempt
    ///   budget exactly as a single submission would.
    async fn process_people_batch(
        &mut self,
        guard: &Guard,
        rows: &[(&Reservation, [u8; 32])],
    ) -> anyhow::Result<()> {
        let payload = build_registration_batch_tx(rows, self.proxy_for.as_ref());
        let nonce = match self.nonce().await {
            Ok(n) => n,
            Err(e) => {
                return self
                    .retry_people_batch(guard, rows, &format!("nonce fetch: {e}"))
                    .await
            }
        };

        match self.submit_batch(guard, rows, &payload, nonce).await {
            Ok(items) => {
                self.next_nonce = Some(nonce + 1);
                self.people_batch.succeeded(self.batch_max);
                self.apply_people_items(guard, rows, items).await
            }
            Err(e) => {
                // Reset the cached nonce; re-fetch on the next attempt.
                self.next_nonce = None;
                self.retry_people_batch(guard, rows, &e.to_string()).await
            }
        }
    }

    /// Re-queue a whole batch **without** spending anyone's attempt, on one
    /// shared backoff.
    ///
    /// The backoff is shared deliberately: a per-row `2^attempt` would put the
    /// entire set back into the very next pass simultaneously, which is the
    /// same batch failing the same way.
    async fn retry_people_batch(
        &mut self,
        guard: &Guard,
        rows: &[(&Reservation, [u8; 32])],
        reason: &str,
    ) -> anyhow::Result<()> {
        let backoff = self.people_batch.failed(self.batch_max);
        tracing::warn!(
            batch = rows.len(),
            backoff_secs = backoff.whole_seconds(),
            next_batch_size = self.people_batch.size,
            reason,
            "registration batch failed as a whole; re-queued without spending an attempt"
        );
        self.defer_people_rows(guard, rows, backoff, reason).await
    }

    /// Re-queue a set of rows at an unchanged `attempt`, on one shared
    /// `not_before`. The lane accounting is the caller's: this is also the path
    /// for a batch that *did* submit and had to be reconciled, where the lane
    /// is not at fault.
    async fn defer_people_rows(
        &self,
        guard: &Guard,
        rows: &[(&Reservation, [u8; 32])],
        backoff: time::Duration,
        reason: &str,
    ) -> anyhow::Result<()> {
        let until = OffsetDateTime::now_utc() + backoff;
        for (r, _) in rows {
            let outcome = Outcome::Defer {
                until,
                reason,
                cause: Defer::Batch,
            };
            People::record(&self.pool, guard, r, outcome).await?;
        }
        Ok(())
    }

    /// Re-queue rows from a batch that **submitted** but whose per-item outcome
    /// had to be read from chain state instead.
    ///
    /// Deliberately not [`Writer::retry_people_batch`]: this path is only
    /// reachable after `submit_batch` returned `Ok` and the lane already
    /// recorded a success, so halving the size and counting a whole-batch
    /// failure would grow and then shrink the lane over one good submission and
    /// report a chain rejection that never happened — which is exactly the
    /// reading `docs/operations.md` gives `dub_chain_batch_failed_total`.
    async fn defer_reconciled_people(
        &self,
        guard: &Guard,
        rows: &[(&Reservation, [u8; 32])],
        reason: &str,
    ) -> anyhow::Result<()> {
        metrics::counter!("dub_chain_batch_reconciled_total", "lane" => "people")
            .increment(rows.len() as u64);
        tracing::warn!(
            batch = rows.len(),
            backoff_secs = BATCH_RECONCILE_BACKOFF.whole_seconds(),
            reason,
            "registration batch reconciled from chain state; \
             unlanded rows re-queued without spending an attempt"
        );
        self.defer_people_rows(guard, rows, BATCH_RECONCILE_BACKOFF, reason)
            .await
    }

    /// Decide each row from its own item result.
    ///
    /// The count guard is the safety valve: `ASSIGNED` may never be inferred
    /// from a positional mapping that does not line up with the calls
    /// submitted, because that is the one failure mode that would mark a row
    /// registered when it never landed.
    async fn apply_people_items(
        &mut self,
        guard: &Guard,
        rows: &[(&Reservation, [u8; 32])],
        items: Vec<Result<(), String>>,
    ) -> anyhow::Result<()> {
        if items.len() != rows.len() {
            tracing::error!(
                items = items.len(),
                calls = rows.len(),
                "force_batch reported a different number of items than calls submitted;                  discarding the positional mapping and reconciling against chain state"
            );
            return self
                .reconcile_people_batch(
                    guard,
                    rows,
                    "batch item events did not match the calls submitted",
                )
                .await;
        }

        // One read for every item the chain rejected: `AlreadyRegistered` is
        // success, and only chain state can tell that from a real failure.
        let failed: Vec<&str> = rows
            .iter()
            .zip(&items)
            .filter(|(_, item)| item.is_err())
            .map(|((r, _), _)| r.full_username.as_str())
            .collect();
        metrics::counter!("dub_chain_batch_item_failed_total", "lane" => "people")
            .increment(failed.len() as u64);
        let owners = match self.chain.owners(&failed).await {
            Ok(owners) => owners,
            Err(e) => {
                // Best-effort, exactly as the single-submit path's reconcile
                // read is: an unread owner simply means the row retries.
                tracing::warn!(error = %e, "post-batch owner read failed; failed items will retry");
                HashMap::new()
            }
        };

        for ((r, candidate), item) in rows.iter().zip(items) {
            let Err(reason) = item else {
                People::record(&self.pool, guard, r, Outcome::Landed).await?;
                continue;
            };
            let observed = owners.get(&r.full_username).copied();
            match classify_submit_failure(
                &reason,
                observed,
                *candidate,
                r.attempt + 1,
                self.config.max_attempts,
            ) {
                SubmitFailureAction::Assign => {
                    People::record(&self.pool, guard, r, Outcome::Landed).await?
                }
                SubmitFailureAction::Park => {
                    People::record(&self.pool, guard, r, Outcome::Park(&reason)).await?
                }
                SubmitFailureAction::Retry => {
                    People::record(&self.pool, guard, r, Outcome::Retry(&reason)).await?
                }
                SubmitFailureAction::Fail => {
                    People::record(
                        &self.pool,
                        guard,
                        r,
                        Outcome::Failed(&terminal_reason(&reason)),
                    )
                    .await?
                }
            }
        }
        Ok(())
    }

    /// Resolve a batch whose per-item outcomes cannot be trusted, from chain
    /// state alone.
    ///
    /// Rows the chain shows as registered are `ASSIGNED`; the rest are
    /// re-queued at an unchanged `attempt`, because nothing here is
    /// attributable to a row.
    async fn reconcile_people_batch(
        &mut self,
        guard: &Guard,
        rows: &[(&Reservation, [u8; 32])],
        reason: &str,
    ) -> anyhow::Result<()> {
        let names: Vec<&str> = rows.iter().map(|(r, _)| r.full_username.as_str()).collect();
        let owners = match self.chain.owners(&names).await {
            Ok(owners) => owners,
            Err(e) => {
                return self
                    .defer_reconciled_people(
                        guard,
                        rows,
                        &format!("{reason}; owner read failed: {e}"),
                    )
                    .await
            }
        };

        let mut unlanded = Vec::new();
        for (r, candidate) in rows {
            if owners.get(&r.full_username) == Some(candidate) {
                People::record(&self.pool, guard, r, Outcome::Landed).await?;
            } else {
                unlanded.push((*r, *candidate));
            }
        }
        if unlanded.is_empty() {
            return Ok(());
        }
        self.defer_reconciled_people(guard, &unlanded, reason).await
    }

    /// Sign + submit one batch, recording `SUBMITTING` for **every** row (with
    /// the shared tx hash and nonce) before awaiting inclusion, so a crash
    /// mid-flight reconciles per row instead of resubmitting.
    ///
    /// Returns the ordered per-item results. `Err` is a whole-batch failure.
    async fn submit_batch(
        &self,
        guard: &Guard,
        rows: &[(&Reservation, [u8; 32])],
        payload: &DynamicPayload<Vec<Value>>,
        nonce: u64,
    ) -> anyhow::Result<Vec<Result<(), String>>> {
        let params = PeopleExtrinsicParamsBuilder::new().nonce(nonce).build();
        let mut tx_client = self.chain.online().tx().await?;
        let signed = tx_client
            .create_signed(payload, &self.signer, params)
            .await?;
        let tx_hash = format!("{:?}", signed.hash());

        for (r, _) in rows {
            if !outbox::mark_submitting(
                &self.pool,
                guard,
                r.id,
                &tx_hash,
                nonce as i64,
                r.attempt + 1,
            )
            .await?
            {
                anyhow::bail!("lease lost before submit");
            }
        }
        tracing::info!(
            batch = rows.len(),
            nonce,
            tx = %tx_hash,
            "submitting registration batch"
        );
        metrics::histogram!("dub_chain_batch_items", "lane" => "people").record(rows.len() as f64);

        let (events, metadata) = self
            .finalize(guard, signed.submit_and_watch().await?, "submit")
            .await?;
        check_proxied_call(&events, &metadata)?;
        item_results(&events, &metadata)
    }

    /// Sign + submit, recording `SUBMITTING` (tx hash + nonce) before awaiting
    /// inclusion so a crash mid-flight reconciles instead of resubmitting.
    async fn submit(
        &self,
        guard: &Guard,
        r: &Reservation,
        payload: &DynamicPayload<Vec<Value>>,
        nonce: u64,
    ) -> anyhow::Result<()> {
        let params = PeopleExtrinsicParamsBuilder::new().nonce(nonce).build();
        let mut tx_client = self.chain.online().tx().await?;
        let signed = tx_client
            .create_signed(payload, &self.signer, params)
            .await?;
        let tx_hash = format!("{:?}", signed.hash());

        if !outbox::mark_submitting(
            &self.pool,
            guard,
            r.id,
            &tx_hash,
            nonce as i64,
            r.attempt + 1,
        )
        .await?
        {
            anyhow::bail!("lease lost before submit");
        }
        tracing::info!(id = r.id, username = %r.full_username, nonce, tx = %tx_hash, "submitting registration");

        let (events, metadata) = self
            .finalize(guard, signed.submit_and_watch().await?, "submit")
            .await?;
        check_proxied_call(&events, &metadata)
    }

    /// Await finalization of a submitted extrinsic, returning its events and
    /// the metadata of the runtime that executed it.
    async fn finalize<T, C>(
        &self,
        guard: &Guard,
        progress: TransactionProgress<T, C>,
        what: &'static str,
    ) -> anyhow::Result<(ExtrinsicEvents<T>, ArcMetadata)>
    where
        T: subxt::Config,
        C: OnlineClientAtBlockT<T>,
    {
        let wait = async {
            let in_block = progress.wait_for_finalized().await?;
            let events = in_block.wait_for_success().await?;
            let metadata = in_block.at().await?.metadata();
            anyhow::Ok((events, metadata))
        };
        let watched = async move {
            tokio::pin!(wait);
            let mut renew = tokio::time::interval(self.config.lease_ttl / 3);
            renew.tick().await; // consume the immediate first tick
            loop {
                tokio::select! {
                    result = &mut wait => return result,
                    _ = renew.tick() => {
                        if !self.heartbeat(guard).await? {
                            anyhow::bail!("lost writer lease during {what}");
                        }
                    }
                }
            }
        };
        tokio::time::timeout(self.config.finalize_timeout, watched)
            .await
            .map_err(|_| anyhow::anyhow!("finalization timed out"))?
    }

    /// Drain `SUBMITTING` rows left by a previous writer: reconcile each against
    /// chain state (owned -> assigned; otherwise re-queue).
    ///
    /// One batched read for the whole set. A writer that died mid-batch leaves
    /// as many `SUBMITTING` rows as the batch was wide, and startup should not
    /// cost one round trip each.
    async fn reconcile_submitting(&self, guard: &Guard) -> anyhow::Result<()> {
        let stuck = outbox::submitting(&self.pool).await?;
        let mut parsed = Vec::with_capacity(stuck.len());
        for r in &stuck {
            match parse_account(&r.candidate_account_id) {
                Ok(candidate) => parsed.push((r, candidate)),
                Err(_) => {
                    People::record(
                        &self.pool,
                        guard,
                        r,
                        Outcome::Failed("invalid candidate SS58"),
                    )
                    .await?
                }
            }
        }
        if parsed.is_empty() {
            return Ok(());
        }

        // Chunked, and a failed chunk does not abandon the rest. `submitting()`
        // has no `LIMIT`, so one read over the whole set would make every stuck
        // row hostage to a single timeout or unanswered key — and the rows it
        // leaves behind wait for the next *lease acquisition*, which the active
        // loop may not reach for a long time.
        let mut unread = 0usize;
        for chunk in parsed.chunks(RECONCILE_READ_CHUNK) {
            let names: Vec<&str> = chunk
                .iter()
                .map(|(r, _)| r.full_username.as_str())
                .collect();
            let owners = match self.chain.owners(&names).await {
                Ok(owners) => owners,
                Err(e) => {
                    // Left `SUBMITTING` rather than guessed about: unknown is
                    // never read as not-yet-landed.
                    tracing::warn!(
                        error = %e,
                        rows = chunk.len(),
                        "reconcile owner read failed; those rows stay SUBMITTING"
                    );
                    unread += chunk.len();
                    continue;
                }
            };
            for (r, candidate) in chunk {
                if owners.get(&r.full_username) == Some(candidate) {
                    People::record(&self.pool, guard, r, Outcome::Observed).await?;
                } else {
                    People::record(
                        &self.pool,
                        guard,
                        r,
                        Outcome::Retry("reconcile: not yet on-chain, re-queued"),
                    )
                    .await?;
                }
            }
        }
        if unread > 0 {
            anyhow::bail!(
                "reconcile could not read {unread} of {} SUBMITTING rows",
                parsed.len()
            );
        }
        Ok(())
    }

    async fn nonce(&mut self) -> anyhow::Result<u64> {
        if let Some(n) = self.next_nonce {
            return Ok(n);
        }
        let n = self
            .chain
            .online()
            .tx()
            .await?
            .account_nonce(&self.signer_account)
            .await?;
        self.next_nonce = Some(n);
        Ok(n)
    }

    async fn nonce_ah(&mut self, asset_hub: &AssetHub) -> anyhow::Result<u64> {
        if let Some(n) = self.next_nonce_ah {
            return Ok(n);
        }
        let n = asset_hub
            .online()
            .tx()
            .await?
            .account_nonce(&self.signer_account)
            .await?;
        self.next_nonce_ah = Some(n);
        Ok(n)
    }

    async fn dotns_client(&mut self) -> Option<(AssetHub, ValidityWindow)> {
        let now = Instant::now();
        match self.dotns_lane.dial_state(now) {
            DotnsDial::Skip => return None,
            DotnsDial::Ready => {
                let DotnsLane::Enabled {
                    connected: Some(up),
                    ..
                } = &self.dotns_lane
                else {
                    return None;
                };
                return Some(up.clone());
            }
            DotnsDial::Dial => {}
        }
        let DotnsLane::Enabled { rpc_url, .. } = &self.dotns_lane else {
            return None;
        };
        let rpc_url = rpc_url.clone();
        match connect_asset_hub(&rpc_url).await {
            Ok(up) => {
                tracing::info!(
                    asset_hub_rpc = %rpc_url,
                    max_validity_secs = up.1.max_validity_secs,
                    max_future_skew_secs = up.1.max_future_skew_secs,
                    "dotns lane connected"
                );
                metrics::gauge!("dub_dotns_lane_connected").set(1.0);
                self.dotns_lane.record_dial_success(up.clone());
                Some(up)
            }
            Err(e) => {
                let reason = format!("{e:#}");
                if self.dotns_lane.record_dial_failure(reason.clone(), now) {
                    tracing::warn!(
                        asset_hub_rpc = %rpc_url,
                        error = %reason,
                        retry_secs = DOTNS_RECONNECT_INTERVAL.as_secs(),
                        "dotns lane parked; People registration is unaffected"
                    );
                }
                metrics::gauge!("dub_dotns_lane_connected").set(0.0);
                None
            }
        }
    }

    async fn dotns_pass(&mut self, guard: &Guard) -> anyhow::Result<()> {
        let Some((asset_hub, window)) = self.dotns_client().await else {
            return Ok(());
        };
        let due = outbox::claim_dotns_due(&self.pool, i64::from(self.dotns_batch.size)).await?;
        if due.is_empty() {
            return Ok(());
        }
        if !self.heartbeat(guard).await? {
            anyhow::bail!("lost writer lease");
        }
        let submittable = self.triage_dotns(guard, &asset_hub, window, &due).await?;
        match submittable.len() {
            0 => Ok(()),
            1 => {
                let (r, candidate) = submittable[0];
                self.process_dotns_one(guard, &asset_hub, r, candidate)
                    .await
            }
            _ => {
                self.process_dotns_batch(guard, &asset_hub, &submittable)
                    .await
            }
        }
    }

    /// Resolve every dotNS row that can be decided without submitting anything.
    ///
    /// The offline gates run **per row before the batch is built** — a
    /// future-dated, expired, or badly-signed row is excluded rather than
    /// carried in, so it never spends an item slot or a fee. Survivors are then
    /// checked against one batched `LiteLabelOwner` read.
    ///
    /// Every failure here lands on `dotns_status`. The People `status` is never
    /// touched.
    async fn triage_dotns<'r>(
        &mut self,
        guard: &Guard,
        asset_hub: &AssetHub,
        window: ValidityWindow,
        due: &'r [Reservation],
    ) -> anyhow::Result<Vec<(&'r Reservation, [u8; 32])>> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut gated = Vec::with_capacity(due.len());
        for r in due {
            let Ok(candidate) = parse_account(&r.candidate_account_id) else {
                Dotns::record(
                    &self.pool,
                    guard,
                    r,
                    Outcome::Failed("invalid candidate SS58"),
                )
                .await?;
                continue;
            };
            match check_dotns_submittable(r, &candidate, &self.config.attester, window, now) {
                Ok(()) => gated.push((r, candidate)),
                Err(reject) => self.reject_dotns(guard, r, reject, window, now).await?,
            }
        }
        if gated.is_empty() {
            return Ok(Vec::new());
        }

        let labels: Vec<&str> = gated
            .iter()
            .map(|(r, _)| r.full_username.as_str())
            .collect();
        let owners = match asset_hub.owners(&labels).await {
            Ok(owners) => owners,
            Err(e) => {
                // One read covers every gated row, so a bad response is a
                // whole-batch fault rather than any row's: unchanged
                // `dotns_attempt`, one shared backoff. Spending an attempt each
                // would walk a whole set to `DOTNS_FAILED` on a flapping Asset
                // Hub, and a per-row `2^attempt` would return the entire set to
                // the very next pass at once.
                self.retry_dotns_batch(guard, &gated, &format!("label owner read failed: {e}"))
                    .await?;
                return Ok(Vec::new());
            }
        };

        let mut submittable = Vec::with_capacity(gated.len());
        for (r, candidate) in gated {
            match owners.get(&r.full_username) {
                Some(owner) if *owner == candidate => {
                    Dotns::record(&self.pool, guard, r, Outcome::Landed).await?
                }
                Some(_) => {
                    Dotns::record(
                        &self.pool,
                        guard,
                        r,
                        Outcome::Failed("lite label reserved by another account"),
                    )
                    .await?
                }
                None => submittable.push((r, candidate)),
            }
        }
        Ok(submittable)
    }

    /// Record one offline gate's verdict on the row.
    ///
    /// Each gate has its own terminal state; only `FutureDated` is recoverable
    /// by the passage of time, and it is deferred rather than failed.
    async fn reject_dotns(
        &self,
        guard: &Guard,
        r: &Reservation,
        reject: DotnsReject,
        window: ValidityWindow,
        now: i64,
    ) -> anyhow::Result<()> {
        {
            match reject {
                DotnsReject::Expired {
                    signed_at,
                    deadline_secs,
                } => {
                    Dotns::record(
                        &self.pool,
                        guard,
                        r,
                        Outcome::Expired(&format!(
                            "reservation signature expired: signed_at={signed_at}, window \
                             {deadline_secs}s, now={now}. Only the client can re-sign."
                        )),
                    )
                    .await
                }
                DotnsReject::NotInLane => {
                    Dotns::record(
                        &self.pool,
                        guard,
                        r,
                        Outcome::Failed("row has no complete dotns block"),
                    )
                    .await
                }
                DotnsReject::BadSignature => {
                    Dotns::record(
                        &self.pool,
                        guard,
                        r,
                        Outcome::Failed("dotns signature does not verify"),
                    )
                    .await
                }
                DotnsReject::UnbuildableLabel(why) | DotnsReject::UnbuildableReserved(why) => {
                    Dotns::record(&self.pool, guard, r, Outcome::Failed(&why)).await
                }
                DotnsReject::FutureDated {
                    signed_at,
                    submittable_at,
                } => {
                    let until = OffsetDateTime::from_unix_timestamp(submittable_at)
                        .unwrap_or_else(|_| OffsetDateTime::now_utc());
                    Dotns::record(
                        &self.pool,
                        guard,
                        r,
                        Outcome::Defer {
                            until,
                            reason: &format!(
                                "reservation signature is future-dated: signed_at={signed_at}, \
                                 now={now}, gateway tolerates {}s of skew. Re-queued until \
                                 {submittable_at}.",
                                window.max_future_skew_secs
                            ),
                            cause: Defer::NotYet,
                        },
                    )
                    .await
                }
            }
        }
    }

    /// Submit one dotNS reservation on its own.
    ///
    /// The pre-batching path, unchanged, reached when triage leaves exactly one
    /// row submittable. Row-level failures are recorded on `dotns_status`; they
    /// never touch the People `status`.
    async fn process_dotns_one(
        &mut self,
        guard: &Guard,
        asset_hub: &AssetHub,
        r: &Reservation,
        candidate: [u8; 32],
    ) -> anyhow::Result<()> {
        let payload = build_reserve_name_tx(r, &candidate, self.proxy_for.as_ref());
        let nonce = match self.nonce_ah(asset_hub).await {
            Ok(n) => n,
            Err(e) => {
                let reason = format!("asset hub nonce fetch: {e}");
                return Dotns::record(&self.pool, guard, r, Outcome::Retry(&reason)).await;
            }
        };

        match self
            .submit_dotns(guard, asset_hub, r, &payload, nonce)
            .await
        {
            Ok(()) => {
                self.next_nonce_ah = Some(nonce + 1);
                self.dotns_batch.succeeded(self.batch_max);
                Dotns::record(&self.pool, guard, r, Outcome::Landed).await
            }
            Err(e) => {
                self.next_nonce_ah = None;
                let reason = e.to_string();
                let observed = asset_hub.owner(&r.full_username).await.ok().flatten();
                match classify_submit_failure(
                    &reason,
                    observed,
                    candidate,
                    r.dotns_attempt + 1,
                    self.config.max_attempts,
                ) {
                    SubmitFailureAction::Assign => {
                        Dotns::record(&self.pool, guard, r, Outcome::Landed).await
                    }
                    SubmitFailureAction::Park => {
                        Dotns::record(&self.pool, guard, r, Outcome::Park(&reason)).await
                    }
                    SubmitFailureAction::Retry => {
                        Dotns::record(&self.pool, guard, r, Outcome::Retry(&reason)).await
                    }
                    SubmitFailureAction::Fail => {
                        Dotns::record(
                            &self.pool,
                            guard,
                            r,
                            Outcome::Failed(&terminal_reason(&reason)),
                        )
                        .await
                    }
                }
            }
        }
    }

    /// Submit a whole dotNS pass as one `Utility.force_batch` on Asset Hub.
    ///
    /// The People lane's shape, on the other chain and the other state machine:
    /// whole-batch failures leave `dotns_attempt` untouched and halve this
    /// lane's own size; per-item failures spend the row's own budget. A batched
    /// Asset Hub failure never touches a valid People registration.
    async fn process_dotns_batch(
        &mut self,
        guard: &Guard,
        asset_hub: &AssetHub,
        rows: &[(&Reservation, [u8; 32])],
    ) -> anyhow::Result<()> {
        let payload = build_reserve_name_batch_tx(rows, self.proxy_for.as_ref());
        let nonce = match self.nonce_ah(asset_hub).await {
            Ok(n) => n,
            Err(e) => {
                return self
                    .retry_dotns_batch(guard, rows, &format!("asset hub nonce fetch: {e}"))
                    .await
            }
        };

        match self
            .submit_dotns_batch(guard, asset_hub, rows, &payload, nonce)
            .await
        {
            Ok(items) => {
                self.next_nonce_ah = Some(nonce + 1);
                self.dotns_batch.succeeded(self.batch_max);
                self.apply_dotns_items(guard, asset_hub, rows, items).await
            }
            Err(e) => {
                self.next_nonce_ah = None;
                self.retry_dotns_batch(guard, rows, &e.to_string()).await
            }
        }
    }

    /// Re-queue a whole dotNS batch on one shared backoff, without spending any
    /// row's `dotns_attempt`.
    async fn retry_dotns_batch(
        &mut self,
        guard: &Guard,
        rows: &[(&Reservation, [u8; 32])],
        reason: &str,
    ) -> anyhow::Result<()> {
        let backoff = self.dotns_batch.failed(self.batch_max);
        tracing::warn!(
            batch = rows.len(),
            backoff_secs = backoff.whole_seconds(),
            next_batch_size = self.dotns_batch.size,
            reason,
            "dotns reservation batch failed as a whole; re-queued without spending an attempt.              The People registrations are unaffected"
        );
        self.defer_dotns_rows(guard, rows, backoff, reason).await
    }

    /// [`Writer::defer_people_rows`] for the dotNS lane: re-queue a set at an
    /// unchanged `dotns_attempt` on one shared `not_before`, leaving the lane
    /// accounting to the caller.
    async fn defer_dotns_rows(
        &self,
        guard: &Guard,
        rows: &[(&Reservation, [u8; 32])],
        backoff: time::Duration,
        reason: &str,
    ) -> anyhow::Result<()> {
        let until = OffsetDateTime::now_utc() + backoff;
        for (r, _) in rows {
            let outcome = Outcome::Defer {
                until,
                reason,
                cause: Defer::Batch,
            };
            Dotns::record(&self.pool, guard, r, outcome).await?;
        }
        Ok(())
    }

    /// [`Writer::defer_reconciled_people`] for the dotNS lane. Same reason for
    /// existing: the batch submitted, so the lane must not record a whole-batch
    /// failure against a size that worked.
    async fn defer_reconciled_dotns(
        &self,
        guard: &Guard,
        rows: &[(&Reservation, [u8; 32])],
        reason: &str,
    ) -> anyhow::Result<()> {
        metrics::counter!("dub_chain_batch_reconciled_total", "lane" => "dotns")
            .increment(rows.len() as u64);
        tracing::warn!(
            batch = rows.len(),
            backoff_secs = BATCH_RECONCILE_BACKOFF.whole_seconds(),
            reason,
            "dotns reservation batch reconciled from chain state; \
             unreserved rows re-queued without spending an attempt"
        );
        self.defer_dotns_rows(guard, rows, BATCH_RECONCILE_BACKOFF, reason)
            .await
    }

    /// Decide each dotNS row from its own item result, behind the same count
    /// guard as the People lane.
    async fn apply_dotns_items(
        &mut self,
        guard: &Guard,
        asset_hub: &AssetHub,
        rows: &[(&Reservation, [u8; 32])],
        items: Vec<Result<(), String>>,
    ) -> anyhow::Result<()> {
        if items.len() != rows.len() {
            tracing::error!(
                items = items.len(),
                calls = rows.len(),
                "dotns force_batch reported a different number of items than calls submitted;                  discarding the positional mapping and reconciling against chain state"
            );
            return self
                .reconcile_dotns_batch(
                    guard,
                    asset_hub,
                    rows,
                    "batch item events did not match the calls submitted",
                )
                .await;
        }

        let failed: Vec<&str> = rows
            .iter()
            .zip(&items)
            .filter(|(_, item)| item.is_err())
            .map(|((r, _), _)| r.full_username.as_str())
            .collect();
        metrics::counter!("dub_chain_batch_item_failed_total", "lane" => "dotns")
            .increment(failed.len() as u64);
        let owners = match asset_hub.owners(&failed).await {
            Ok(owners) => owners,
            Err(e) => {
                tracing::warn!(error = %e, "post-batch label owner read failed; failed items will retry");
                HashMap::new()
            }
        };

        for ((r, candidate), item) in rows.iter().zip(items) {
            let Err(reason) = item else {
                Dotns::record(&self.pool, guard, r, Outcome::Landed).await?;
                continue;
            };
            let observed = owners.get(&r.full_username).copied();
            match classify_submit_failure(
                &reason,
                observed,
                *candidate,
                r.dotns_attempt + 1,
                self.config.max_attempts,
            ) {
                SubmitFailureAction::Assign => {
                    Dotns::record(&self.pool, guard, r, Outcome::Landed).await?
                }
                SubmitFailureAction::Park => {
                    Dotns::record(&self.pool, guard, r, Outcome::Park(&reason)).await?
                }
                SubmitFailureAction::Retry => {
                    Dotns::record(&self.pool, guard, r, Outcome::Retry(&reason)).await?
                }
                SubmitFailureAction::Fail => {
                    Dotns::record(
                        &self.pool,
                        guard,
                        r,
                        Outcome::Failed(&terminal_reason(&reason)),
                    )
                    .await?
                }
            }
        }
        Ok(())
    }

    /// Resolve a dotNS batch whose per-item outcomes cannot be trusted, from
    /// `LiteLabelOwner` alone.
    async fn reconcile_dotns_batch(
        &mut self,
        guard: &Guard,
        asset_hub: &AssetHub,
        rows: &[(&Reservation, [u8; 32])],
        reason: &str,
    ) -> anyhow::Result<()> {
        let labels: Vec<&str> = rows.iter().map(|(r, _)| r.full_username.as_str()).collect();
        let owners = match asset_hub.owners(&labels).await {
            Ok(owners) => owners,
            Err(e) => {
                return self
                    .defer_reconciled_dotns(
                        guard,
                        rows,
                        &format!("{reason}; label owner read failed: {e}"),
                    )
                    .await
            }
        };

        let mut unlanded = Vec::new();
        for (r, candidate) in rows {
            if owners.get(&r.full_username) == Some(candidate) {
                Dotns::record(&self.pool, guard, r, Outcome::Landed).await?;
            } else {
                unlanded.push((*r, *candidate));
            }
        }
        if unlanded.is_empty() {
            return Ok(());
        }
        self.defer_reconciled_dotns(guard, &unlanded, reason).await
    }

    /// Signs and submits one dotNS batch, recording `SUBMITTING` for every row
    /// before awaiting inclusion.
    ///
    /// Returns the ordered per-item results. `Err` is a whole-batch failure.
    async fn submit_dotns_batch(
        &self,
        guard: &Guard,
        asset_hub: &AssetHub,
        rows: &[(&Reservation, [u8; 32])],
        payload: &DynamicPayload<Vec<Value>>,
        nonce: u64,
    ) -> anyhow::Result<Vec<Result<(), String>>> {
        let params = AssetHubExtrinsicParamsBuilder::new().nonce(nonce).build();
        let mut tx_client = asset_hub.online().tx().await?;
        let signed = tx_client
            .create_signed(payload, &self.signer, params)
            .await?;
        let tx_hash = format!("{:?}", signed.hash());

        for (r, _) in rows {
            if !outbox::mark_dotns_submitting(
                &self.pool,
                guard,
                r.id,
                &tx_hash,
                r.dotns_attempt + 1,
            )
            .await?
            {
                anyhow::bail!("lease lost before dotns submit");
            }
        }
        tracing::info!(
            batch = rows.len(),
            nonce,
            tx = %tx_hash,
            "submitting dotns reservation batch"
        );
        metrics::histogram!("dub_chain_batch_items", "lane" => "dotns").record(rows.len() as f64);

        let (events, metadata) = self
            .finalize(guard, signed.submit_and_watch().await?, "dotns submit")
            .await?;
        check_proxied_call(&events, &metadata)?;
        item_results(&events, &metadata)
    }

    async fn submit_dotns(
        &self,
        guard: &Guard,
        asset_hub: &AssetHub,
        r: &Reservation,
        payload: &DynamicPayload<Vec<Value>>,
        nonce: u64,
    ) -> anyhow::Result<()> {
        let params = AssetHubExtrinsicParamsBuilder::new().nonce(nonce).build();
        let mut tx_client = asset_hub.online().tx().await?;
        let signed = tx_client
            .create_signed(payload, &self.signer, params)
            .await?;
        let tx_hash = format!("{:?}", signed.hash());

        if !outbox::mark_dotns_submitting(&self.pool, guard, r.id, &tx_hash, r.dotns_attempt + 1)
            .await?
        {
            anyhow::bail!("lease lost before dotns submit");
        }
        tracing::info!(
            id = r.id,
            username = %r.full_username,
            nonce,
            tx = %tx_hash,
            "submitting dotns reservation"
        );

        let (events, metadata) = self
            .finalize(guard, signed.submit_and_watch().await?, "dotns submit")
            .await?;
        check_proxied_call(&events, &metadata)
    }

    async fn reconcile_dotns_submitting(&mut self, guard: &Guard) -> anyhow::Result<()> {
        let Some((asset_hub, _)) = self.dotns_client().await else {
            return Ok(());
        };
        for r in outbox::dotns_submitting(&self.pool).await? {
            let Some(candidate) = parse_account(&r.candidate_account_id).ok() else {
                Dotns::record(
                    &self.pool,
                    guard,
                    &r,
                    Outcome::Failed("invalid candidate SS58"),
                )
                .await?;
                continue;
            };
            match asset_hub.owner(&r.full_username).await? {
                Some(owner) if owner == candidate => {
                    Dotns::record(&self.pool, guard, &r, Outcome::Landed).await?
                }
                _ => {
                    Dotns::record(
                        &self.pool,
                        guard,
                        &r,
                        Outcome::Retry("reconcile: not yet on Asset Hub, re-queued"),
                    )
                    .await?
                }
            }
        }
        Ok(())
    }

    async fn log_attester_resources(&mut self) -> anyhow::Result<()> {
        let allowance_account = self.config.attester;
        let allowance = self.chain.attestation_allowance(allowance_account).await?;
        let signer_balance = self.chain.free_balance(self.signer_account.0).await?;
        let primary_balance = match self.proxy_for {
            Some(primary) => Some(self.chain.free_balance(primary).await?),
            None => None,
        };

        tracing::info!(
            allowance,
            allowance_account = %hex_account(&allowance_account),
            signer = %hex_account(&self.signer_account.0),
            signer_balance_planck = signer_balance,
            primary_balance_planck = primary_balance,
            "attester_resources"
        );
        metrics::gauge!("dub_attester_allowance").set(allowance as f64);
        record_spec_version("people", self.chain.online()).await;
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

        if allowance < self.config.allowance_floor {
            tracing::warn!(
                allowance,
                floor = self.config.allowance_floor,
                allowance_account = %hex_account(&allowance_account),
                "attestation allowance below floor; registration stops at zero"
            );
        }
        if signer_balance < self.config.signer_balance_floor_planck {
            tracing::warn!(
                signer_balance_planck = signer_balance,
                floor_planck = self.config.signer_balance_floor_planck,
                signer = %hex_account(&self.signer_account.0),
                "chain-writer signer balance below floor; registrations will fail to pay fees"
            );
        }

        if let Some((asset_hub, _)) = self.dotns_client().await {
            let allowance = asset_hub.attestation_allowance(allowance_account).await?;
            let ah_signer_balance = asset_hub.free_balance(self.signer_account.0).await?;
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

            if allowance < self.config.allowance_floor {
                tracing::warn!(
                    allowance,
                    floor = self.config.allowance_floor,
                    allowance_account = %hex_account(&allowance_account),
                    "dotns gateway allowance below floor; reservations stop at zero"
                );
            }
            if ah_signer_balance < self.config.signer_balance_floor_planck {
                tracing::warn!(
                    signer_balance_planck = ah_signer_balance,
                    floor_planck = self.config.signer_balance_floor_planck,
                    signer = %hex_account(&self.signer_account.0),
                    "chain-writer signer balance on Asset Hub below floor; \
                     failed reservations will not pay their fees"
                );
            }
        }
        Ok(())
    }
}

fn parse_account(ss58: &str) -> anyhow::Result<[u8; 32]> {
    Ok(AccountId32::from_str(ss58)
        .map_err(|e| anyhow::anyhow!("invalid SS58 account {ss58}: {e}"))?
        .0)
}

fn hex_account(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    const FROM_ENV_VARS: &[&str] = &[
        "DEVICE_ATTESTATION_DATABASE_URL",
        "PEOPLE_RPC_URL",
        "CHAIN_WRITER_SIGNER_SURI",
        "ATTESTER_ACCOUNT",
        "CHAIN_WRITER_HOLDER_ID",
        "CHAIN_WRITER_LEASE_NAME",
        "CHAIN_WRITER_LEASE_TTL_SECS",
        "CHAIN_WRITER_POLL_SECS",
        "CHAIN_WRITER_BATCH_SIZE",
        "CHAIN_WRITER_FINALIZE_SECS",
        "CHAIN_WRITER_MAX_ATTEMPTS",
        "QUEUE_ENABLED",
        "QUEUE_FALLBACK_AFTER_SECS",
        "PAYMENT_POLL_INTERVAL_SECS",
        "ATTESTER_RESOURCE_POLL_SECS",
        "ATTESTER_ALLOWANCE_FLOOR",
        "ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK",
    ];

    const REQUIRED_ENV: &[(&str, &str)] = &[
        (
            "DEVICE_ATTESTATION_DATABASE_URL",
            "postgres://writer:pw@localhost/device_attestation",
        ),
        ("CHAIN_WRITER_SIGNER_SURI", "//Writer"),
        ("ATTESTER_ACCOUNT", ALICE_SS58),
    ];

    const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

    const ALICE_HEX: &str = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

    #[test]
    fn a_failing_lane_halves_its_batch_and_backs_off_once_per_failure() {
        let mut lane = BatchLane::new("test", 25);
        assert_eq!(lane.size, 25);

        assert_eq!(lane.failed(25), time::Duration::seconds(2));
        assert_eq!(lane.size, 12);
        assert_eq!(lane.failed(25), time::Duration::seconds(4));
        assert_eq!(lane.size, 6);

        lane.succeeded(25);
        assert_eq!(lane.size, 7);
        assert_eq!(lane.failed(25), time::Duration::seconds(2));

        let mut floored = BatchLane::new("test", 25);
        for _ in 0..10 {
            floored.failed(25);
        }
        assert_eq!(floored.size, 1);

        assert_eq!(floored.failed(25), time::Duration::seconds(64));
    }

    #[test]
    fn a_size_that_failed_is_remembered_and_only_re_probed_after_a_clean_run() {
        let mut lane = BatchLane::new("test", 25);

        while lane.size > 1 {
            lane.failed(25);
        }
        assert_eq!(lane.size, 1);
        assert_eq!(lane.ceiling, Some(3));

        lane.succeeded(25);
        assert_eq!(lane.size, 2);
        lane.failed(25);
        assert_eq!(lane.size, 1);
        assert_eq!(
            lane.ceiling,
            Some(2),
            "2 is the smallest size known to fail"
        );

        for _ in 0..(CEILING_PROBE_RUN - 1) {
            lane.succeeded(25);
            assert_eq!(lane.size, 1);
        }

        lane.succeeded(25);
        assert_eq!(lane.ceiling, Some(3));
        assert_eq!(lane.size, 2);

        let mut healthy = BatchLane::new("test", 25);
        healthy.size = 1;
        for _ in 0..5 {
            healthy.succeeded(25);
        }
        assert_eq!(healthy.size, 6);
        assert_eq!(healthy.ceiling, None);
    }

    #[test]
    fn failed_attest_retries_then_fails_without_becoming_assigned() {
        let candidate = [7; 32];
        let reason = "PeopleLite.InvalidAttestationSignature";

        assert_eq!(
            classify_submit_failure(reason, None, candidate, 1, 3),
            SubmitFailureAction::Retry
        );
        assert_eq!(
            classify_submit_failure(reason, None, candidate, 3, 3),
            SubmitFailureAction::Fail
        );
    }

    const UNFUNDED_ERROR: &str = "max attempts reached: Error during transaction progress: \
         The transaction is not valid: Invalid transaction: Inability to pay some fees \
         (e.g. account balance too low)";

    #[test]
    fn an_unfunded_signer_parks_and_never_becomes_terminal() {
        let candidate = [7; 32];

        assert_eq!(
            classify_submit_failure(UNFUNDED_ERROR, None, candidate, 1, 3),
            SubmitFailureAction::Park
        );
        assert_eq!(
            classify_submit_failure(UNFUNDED_ERROR, None, candidate, 99, 3),
            SubmitFailureAction::Park
        );
        assert_eq!(
            classify_submit_failure(UNFUNDED_ERROR, Some(candidate), candidate, 99, 3),
            SubmitFailureAction::Assign
        );
    }

    #[test]
    fn a_deterministic_rejection_fails_on_the_first_pass() {
        let candidate = [7; 32];
        let reason = "proxied call failed: Resources::UsernameReservationTaken";

        assert_eq!(
            classify_submit_failure(reason, None, candidate, 1, 8),
            SubmitFailureAction::Fail
        );
        assert_eq!(
            classify_submit_failure(reason, Some(candidate), candidate, 1, 8),
            SubmitFailureAction::Assign
        );
        assert_eq!(
            classify_submit_failure(
                "proxied call failed: Resources::Whatever",
                None,
                candidate,
                1,
                8
            ),
            SubmitFailureAction::Retry
        );
    }

    #[test]
    fn every_reservation_leg_rejection_fails_on_the_first_pass() {
        let candidate = [7; 32];
        // All three abort `attest` before the lite username is written, and the
        // consumer signature covers `reserved_username`, so no resubmission
        // this writer can build would land. Retrying only spends fees.
        for error in [
            "Resources::UsernameReservationTaken",
            "Resources::QueueFull",
            "Resources::AlreadyHasReservation",
        ] {
            let reason = format!("proxied call failed: {error}");
            assert_eq!(
                classify_submit_failure(&reason, None, candidate, 1, 8),
                SubmitFailureAction::Fail,
                "{error} should not be retried"
            );
            assert!(
                terminal_reason(&reason).starts_with("rejected deterministically, not retried"),
                "{error} should be reported as a deterministic rejection"
            );
        }
    }

    #[test]
    fn a_queue_full_from_another_pallet_still_retries() {
        // The match is a substring test, so the guard is the pallet prefix.
        // Only `Resources`' queue bounds the reservation leg.
        let candidate = [7; 32];
        assert_eq!(
            classify_submit_failure(
                "proxied call failed: DotnsGateway::QueueFull",
                None,
                candidate,
                1,
                8
            ),
            SubmitFailureAction::Retry
        );
    }

    #[test]
    fn terminal_text_names_the_rule_that_ended_the_row() {
        assert!(terminal_reason("Resources::UsernameReservationTaken")
            .starts_with("rejected deterministically, not retried"));
        assert!(terminal_reason("dispatch failed").starts_with("max attempts reached"));
    }

    #[test]
    fn submit_error_assigns_only_after_successful_reconciliation() {
        let candidate = [7; 32];

        assert_eq!(
            classify_submit_failure("finalization timed out", Some(candidate), candidate, 1, 3),
            SubmitFailureAction::Assign
        );
        assert_eq!(
            classify_submit_failure(ALREADY_REGISTERED, None, candidate, 1, 3),
            SubmitFailureAction::Assign
        );
        assert_eq!(
            classify_submit_failure("dispatch failed", Some([8; 32]), candidate, 1, 3),
            SubmitFailureAction::Retry
        );
    }

    fn from_env_with(vars: &[(&str, &str)]) -> anyhow::Result<WriterConfig> {
        for key in FROM_ENV_VARS {
            std::env::remove_var(key);
        }
        for (key, value) in vars {
            std::env::set_var(key, value);
        }
        let result = WriterConfig::from_env();
        for key in FROM_ENV_VARS {
            std::env::remove_var(key);
        }
        result
    }

    #[test]
    fn from_env_reads_and_validates_the_environment() {
        let _guard = crate::ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let config = from_env_with(&[
            (
                "DEVICE_ATTESTATION_DATABASE_URL",
                "postgres://writer:pw@localhost/device_attestation",
            ),
            ("PEOPLE_RPC_URL", "wss://people.example"),
            ("CHAIN_WRITER_SIGNER_SURI", "//Writer"),
            ("ATTESTER_ACCOUNT", ALICE_SS58),
            ("CHAIN_WRITER_HOLDER_ID", "writer-test-1"),
            ("CHAIN_WRITER_LEASE_NAME", "custom-lease"),
            ("CHAIN_WRITER_LEASE_TTL_SECS", "45"),
            ("CHAIN_WRITER_POLL_SECS", "3"),
            ("CHAIN_WRITER_BATCH_SIZE", "50"),
            ("CHAIN_WRITER_FINALIZE_SECS", "90"),
            ("CHAIN_WRITER_MAX_ATTEMPTS", "4"),
            ("QUEUE_ENABLED", "yes"),
            ("QUEUE_FALLBACK_AFTER_SECS", " 90 "),
            ("PAYMENT_POLL_INTERVAL_SECS", "15"),
            ("ATTESTER_RESOURCE_POLL_SECS", "120"),
            ("ATTESTER_ALLOWANCE_FLOOR", "250"),
            ("ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK", "123456789012"),
        ])
        .unwrap();
        assert_eq!(
            config.database_url.expose_secret(),
            "postgres://writer:pw@localhost/device_attestation"
        );
        assert_eq!(config.people_rpc_url, "wss://people.example");
        assert_eq!(config.signer_suri.expose_secret(), "//Writer");
        let alice: [u8; 32] = hex::decode(ALICE_HEX).unwrap().try_into().unwrap();
        assert_eq!(config.attester, alice);
        assert_eq!(config.holder_id, "writer-test-1");
        assert_eq!(config.lease_name, "custom-lease");
        assert_eq!(config.lease_ttl, Duration::from_secs(45));
        assert_eq!(config.poll_interval, Duration::from_secs(3));
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.finalize_timeout, Duration::from_secs(90));
        assert_eq!(config.max_attempts, 4);
        assert!(config.queue_enabled);
        assert_eq!(config.queue_fallback_after, Duration::from_secs(90));
        assert_eq!(config.payment_poll_interval, Duration::from_secs(15));
        assert_eq!(config.resource_poll_interval, Duration::from_secs(120));
        assert_eq!(config.allowance_floor, 250);
        assert_eq!(config.signer_balance_floor_planck, 123_456_789_012);

        let config = from_env_with(REQUIRED_ENV).unwrap();
        assert_eq!(
            config.people_rpc_url,
            "wss://previewnet.substrate.dev/people"
        );
        assert!(
            config
                .holder_id
                .starts_with(&format!("writer-{}-", std::process::id())),
            "unexpected default holder id {:?}",
            config.holder_id
        );
        assert_eq!(config.lease_name, "people-chain-writer");
        assert_eq!(config.lease_ttl, Duration::from_secs(30));
        assert_eq!(config.poll_interval, Duration::from_secs(2));
        assert_eq!(config.batch_size, 25);
        assert_eq!(config.finalize_timeout, Duration::from_secs(120));
        assert_eq!(config.max_attempts, 8);
        assert!(!config.queue_enabled);
        assert_eq!(config.queue_fallback_after, Duration::from_secs(60));
        assert_eq!(config.payment_poll_interval, Duration::from_secs(30));
        assert_eq!(config.resource_poll_interval, Duration::from_secs(60));
        assert_eq!(config.allowance_floor, 100);
        assert_eq!(config.signer_balance_floor_planck, 10_000_000_000);

        let mut vars = REQUIRED_ENV.to_vec();
        vars.push(("CHAIN_WRITER_HOLDER_ID", "   "));
        let config = from_env_with(&vars).unwrap();
        assert!(config.holder_id.starts_with("writer-"));

        let err = from_env_with(&[("CHAIN_WRITER_SIGNER_SURI", "//Writer")]).unwrap_err();
        assert!(
            err.to_string().contains("DEVICE_ATTESTATION_DATABASE_URL"),
            "{err}"
        );
        let err =
            from_env_with(&[("DEVICE_ATTESTATION_DATABASE_URL", "postgres://x")]).unwrap_err();
        assert!(
            err.to_string()
                .contains("CHAIN_WRITER_SIGNER_SURI is required"),
            "{err}"
        );

        let mut vars = vec![
            (
                "DEVICE_ATTESTATION_DATABASE_URL",
                "postgres://writer:pw@localhost/device_attestation",
            ),
            ("CHAIN_WRITER_SIGNER_SURI", "//Writer"),
        ];
        vars.push(("ATTESTER_ACCOUNT", "not-an-account"));
        let err = from_env_with(&vars).unwrap_err();
        assert!(err.to_string().contains("ATTESTER_ACCOUNT"), "{err}");

        let mut vars = REQUIRED_ENV.to_vec();
        vars.push(("QUEUE_ENABLED", "maybe"));
        let err = from_env_with(&vars).unwrap_err();
        assert!(err.to_string().contains("QUEUE_ENABLED"), "{err}");

        for key in [
            "QUEUE_FALLBACK_AFTER_SECS",
            "PAYMENT_POLL_INTERVAL_SECS",
            "ATTESTER_RESOURCE_POLL_SECS",
            "ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK",
        ] {
            let mut vars = REQUIRED_ENV.to_vec();
            vars.push((key, "30s"));
            let err = from_env_with(&vars).unwrap_err();
            assert!(err.to_string().contains(key), "{key}: {err}");
        }

        let mut vars = REQUIRED_ENV.to_vec();
        vars.push(("ATTESTER_ALLOWANCE_FLOOR", "4294967296"));
        let err = from_env_with(&vars).unwrap_err();
        assert!(
            err.to_string()
                .contains("ATTESTER_ALLOWANCE_FLOOR must fit a u32"),
            "{err}"
        );

        let mut vars = REQUIRED_ENV.to_vec();
        vars.push(("CHAIN_WRITER_LEASE_TTL_SECS", "garbage"));
        vars.push(("CHAIN_WRITER_BATCH_SIZE", "lots"));
        let config = from_env_with(&vars).unwrap();
        assert_eq!(config.lease_ttl, Duration::from_secs(30));
        assert_eq!(config.batch_size, 25);
    }

    #[test]
    fn rendered_already_registered_still_assigns() {
        assert_eq!(
            classify_submit_failure(
                "proxied call failed: PeopleLite::AlreadyRegistered",
                None,
                [7; 32],
                1,
                3
            ),
            SubmitFailureAction::Assign
        );
        assert_eq!(
            classify_submit_failure(
                "proxied call failed: DotnsGateway::AlreadyRegistered",
                None,
                [7; 32],
                1,
                3
            ),
            SubmitFailureAction::Retry
        );
    }

    #[test]
    fn a_fresh_verified_reservation_passes_the_gates() {
        let (r, candidate, attester) = signed_reservation();
        assert_eq!(
            check_dotns_submittable(&r, &candidate, &attester, BOUNDS, SIGNED_AT + 60),
            Ok(())
        );
    }

    #[test]
    fn a_parked_dotns_lane_backs_off_and_logs_each_cause_once() {
        let t0 = Instant::now();
        let mut lane = DotnsLane::Enabled {
            rpc_url: "wss://example.invalid".to_string(),
            connected: None,
            last_error: None,
            retry_at: None,
        };

        assert_eq!(lane.dial_state(t0), DotnsDial::Dial);

        assert!(lane.record_dial_failure("unreachable".to_string(), t0));
        assert_eq!(lane.dial_state(t0), DotnsDial::Skip);
        assert_eq!(
            lane.dial_state(t0 + DOTNS_RECONNECT_INTERVAL - Duration::from_secs(1)),
            DotnsDial::Skip
        );
        let t1 = t0 + DOTNS_RECONNECT_INTERVAL;
        assert_eq!(lane.dial_state(t1), DotnsDial::Dial);

        assert!(!lane.record_dial_failure("unreachable".to_string(), t1));
        assert_eq!(lane.dial_state(t1), DotnsDial::Skip);

        let t2 = t1 + DOTNS_RECONNECT_INTERVAL;
        assert!(lane.record_dial_failure("reserve_name shape mismatch".to_string(), t2));
        let t3 = t2 + DOTNS_RECONNECT_INTERVAL;
        assert!(lane.record_dial_failure("unreachable".to_string(), t3));

        assert_eq!(DotnsLane::Disabled.dial_state(t0), DotnsDial::Skip);
        assert!(!DotnsLane::Disabled.record_dial_failure("ignored".to_string(), t0));
    }

    #[test]
    fn a_future_dated_reservation_is_deferred_not_failed() {
        let (r, candidate, attester) = signed_reservation();

        assert_eq!(
            check_dotns_submittable(&r, &candidate, &attester, BOUNDS, SIGNED_AT - SKEW as i64),
            Ok(())
        );

        assert_eq!(
            check_dotns_submittable(
                &r,
                &candidate,
                &attester,
                BOUNDS,
                SIGNED_AT - SKEW as i64 - 1
            ),
            Err(DotnsReject::FutureDated {
                signed_at: SIGNED_AT,
                submittable_at: SIGNED_AT - SKEW as i64,
            })
        );

        assert_eq!(
            check_dotns_submittable(
                &r,
                &candidate,
                &[99; 32],
                BOUNDS,
                SIGNED_AT - SKEW as i64 - 1
            ),
            Err(DotnsReject::FutureDated {
                signed_at: SIGNED_AT,
                submittable_at: SIGNED_AT - SKEW as i64,
            })
        );

        let absurd = ValidityWindow {
            max_validity_secs: WINDOW,
            max_future_skew_secs: u64::MAX,
        };
        assert_eq!(
            check_dotns_submittable(&r, &candidate, &attester, absurd, SIGNED_AT),
            Ok(())
        );
    }

    #[test]
    fn each_offline_gate_maps_to_its_own_terminal_state() {
        let (r, candidate, attester) = signed_reservation();

        assert_eq!(
            check_dotns_submittable(
                &r,
                &candidate,
                &attester,
                BOUNDS,
                SIGNED_AT + WINDOW as i64 + 1
            ),
            Err(DotnsReject::Expired {
                signed_at: SIGNED_AT,
                deadline_secs: WINDOW
            })
        );
        assert_eq!(
            check_dotns_submittable(&r, &candidate, &attester, BOUNDS, SIGNED_AT + WINDOW as i64),
            Ok(())
        );

        assert_eq!(
            check_dotns_submittable(&r, &candidate, &[99; 32], BOUNDS, SIGNED_AT),
            Err(DotnsReject::BadSignature)
        );

        assert_eq!(
            check_dotns_submittable(&reservation(), &candidate, &attester, BOUNDS, SIGNED_AT),
            Err(DotnsReject::NotInLane)
        );

        let mut no_digits = r.clone();
        no_digits.full_username = "testing".to_string();
        assert!(matches!(
            check_dotns_submittable(&no_digits, &candidate, &attester, BOUNDS, SIGNED_AT),
            Err(DotnsReject::UnbuildableLabel(_))
        ));

        let mut long_label = r.clone();
        long_label.full_username = format!("{}.42", "a".repeat(30));
        assert!(matches!(
            check_dotns_submittable(&long_label, &candidate, &attester, BOUNDS, SIGNED_AT),
            Err(DotnsReject::UnbuildableLabel(_))
        ));

        let mut long_reserved = r.clone();
        long_reserved.reserved_username = Some("a".repeat(33));
        assert!(matches!(
            check_dotns_submittable(&long_reserved, &candidate, &attester, BOUNDS, SIGNED_AT),
            Err(DotnsReject::UnbuildableReserved(_))
        ));
    }

    #[test]
    fn expiry_is_reported_ahead_of_a_bad_signature() {
        let (mut r, candidate, attester) = signed_reservation();
        r.dotns_signature = Some(vec![0; 64]);
        assert!(matches!(
            check_dotns_submittable(
                &r,
                &candidate,
                &attester,
                BOUNDS,
                SIGNED_AT + WINDOW as i64 + 1
            ),
            Err(DotnsReject::Expired { .. })
        ));
    }
}
