// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use secrecy::{ExposeSecret as _, SecretString};
use sqlx::PgPool;
use subxt::utils::AccountId32;

use chain_client::WriterSigner;

use super::{lease, outbox::Guard, people::PeopleChain};
use crate::config::ConfigError;
mod dotns;
mod engine;
mod error;
mod events;
#[cfg(test)]
mod fixtures;
mod lane;
mod link;
mod observe;
mod passes;
mod people;
mod tx;

use dotns::Dotns;
use engine::{Cx, Drain};
use error::Op;
pub use error::WriterError;
use link::{DotnsLink, PeopleLink};
use observe::{record_writer_info, zero_init_submit_outcomes};
use passes::Passes;
use people::People;

/// The claim size a writer uses when `CHAIN_WRITER_BATCH_SIZE` is unset or
/// unusable. Also the AIMD ceiling every lane climbs back to.
const DEFAULT_BATCH_SIZE: u16 = 25;

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
    /// Cadence of the attester-resources pass: read the attestation allowance
    /// and the account balances that registration silently dies without.
    pub resource_poll_interval: Duration,
    /// WARN below this many remaining attestations.
    pub allowance_floor: u32,
    /// WARN below this signer free balance, in planck (transaction fees come
    /// from the signer, not the proxied primary).
    pub signer_balance_floor_planck: u128,
    /// Asset Hub RPC endpoint. Required.
    pub asset_hub_rpc_url: String,
}

impl WriterConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = http_common::config::required_var("DEVICE_ATTESTATION_DATABASE_URL")?;
        let people_rpc_url = std::env::var("PEOPLE_RPC_URL")
            .unwrap_or_else(|_| "wss://previewnet.substrate.dev/people".to_string());
        let signer_suri = http_common::config::required_var("CHAIN_WRITER_SIGNER_SURI")?;
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
            queue_fallback_after: Duration::from_secs(strict("QUEUE_FALLBACK_AFTER_SECS", 60)?),
            resource_poll_interval: Duration::from_secs(strict("ATTESTER_RESOURCE_POLL_SECS", 60)?),
            allowance_floor: u32::try_from(strict("ATTESTER_ALLOWANCE_FLOOR", 100)?).map_err(
                |_| ConfigError::Invalid {
                    key: "ATTESTER_ALLOWANCE_FLOOR",
                    reason: "must fit a u32".to_string(),
                },
            )?,
            signer_balance_floor_planck: u128::from(strict(
                "ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK",
                10_000_000_000,
            )?),
            asset_hub_rpc_url: http_common::config::required_var("ASSET_HUB_RPC_URL")?,
        })
    }
}

pub async fn run(config: WriterConfig) -> Result<(), WriterError> {
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

    tracing::info!(
        asset_hub_rpc = %config.asset_hub_rpc_url,
        "dotns lane connects on the first pass"
    );
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
    let chain_for_lane = chain.clone();
    let config_attester = config.attester;
    let asset_hub_rpc = config.asset_hub_rpc_url.clone();
    let passes = Passes::new(&config);
    let mut writer = Writer {
        pool,
        chain,
        signer,
        signer_account,
        proxy_for,
        config,
        people: Drain::new(batch_max, PeopleLink(chain_for_lane)),
        dotns: Drain::new(batch_max, DotnsLink::new(asset_hub_rpc, config_attester)),
        passes,
    };
    writer.run_forever().await
}

struct Writer {
    pool: PgPool,
    chain: PeopleChain,
    signer: WriterSigner,
    signer_account: AccountId32,
    proxy_for: Option<[u8; 32]>,
    config: WriterConfig,
    people: Drain<People>,
    dotns: Drain<Dotns>,
    /// The periodic work this process hosts because it holds the lease.
    passes: Passes,
}

impl Writer {
    async fn run_forever(&mut self) -> Result<(), WriterError> {
        loop {
            let guard = self.acquire_lease().await?;
            tracing::info!(epoch = guard.epoch, "acquired writer lease");
            self.people.reset_nonce();
            self.dotns.reset_nonce();
            self.reconcile(&guard).await;
            if let Err(e) = self.active_loop(&guard).await {
                tracing::warn!(error = %e, "writer loop exited; re-acquiring lease");
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    async fn acquire_lease(&self) -> Result<Guard, WriterError> {
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

    async fn heartbeat(&self, guard: &Guard) -> Result<bool, WriterError> {
        Ok(lease::renew(
            &self.pool,
            &guard.lease_name,
            &guard.holder_id,
            guard.epoch,
            self.config.lease_ttl,
        )
        .await?)
    }

    async fn active_loop(&mut self, guard: &Guard) -> Result<(), WriterError> {
        loop {
            if !self.heartbeat(guard).await? {
                return Err(WriterError::LeaseLost(Op::Draining));
            }
            self.periodic().await;

            let people_idle = self.people_pass(guard).await?;
            self.dotns_pass(guard).await?;
            if people_idle {
                tokio::time::sleep(self.config.poll_interval).await;
            }
        }
    }

    async fn periodic(&mut self) {
        let Writer {
            pool,
            chain,
            signer_account,
            proxy_for,
            config,
            dotns,
            passes,
            ..
        } = self;
        passes
            .tick(pool, chain, dotns, signer_account, *proxy_for, config)
            .await;
    }

    async fn people_pass(&mut self, guard: &Guard) -> Result<bool, WriterError> {
        let (cx, drain) = self.people_pass_parts(guard);
        drain.pass(&cx).await
    }

    async fn dotns_pass(&mut self, guard: &Guard) -> Result<bool, WriterError> {
        let (cx, drain) = self.dotns_pass_parts(guard);
        drain.pass(&cx).await
    }

    async fn reconcile(&mut self, guard: &Guard) {
        let (cx, drain) = self.people_pass_parts(guard);
        if let Err(e) = drain.reconcile_submitting(&cx).await {
            tracing::warn!(error = %e, lane = "people", "startup reconcile failed");
        }
        let (cx, drain) = self.dotns_pass_parts(guard);
        if let Err(e) = drain.reconcile_submitting(&cx).await {
            tracing::warn!(error = %e, lane = "dotns", "startup reconcile failed");
        }
    }
    fn people_pass_parts<'a>(&'a mut self, guard: &'a Guard) -> (Cx<'a>, &'a mut Drain<People>) {
        let Writer {
            pool,
            signer,
            signer_account,
            proxy_for,
            config,
            people,
            ..
        } = self;
        (
            cx_of(pool, guard, signer, signer_account, *proxy_for, config),
            people,
        )
    }

    fn dotns_pass_parts<'a>(&'a mut self, guard: &'a Guard) -> (Cx<'a>, &'a mut Drain<Dotns>) {
        let Writer {
            pool,
            signer,
            signer_account,
            proxy_for,
            config,
            dotns,
            ..
        } = self;
        (
            cx_of(pool, guard, signer, signer_account, *proxy_for, config),
            dotns,
        )
    }
}

fn hex_account(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// [`crate::queue::env_u64_strict`] in this module's error vocabulary. That
/// helper still returns `anyhow` and is shared with the queue role, so the
/// mapping lives here rather than being pushed onto its other caller.
fn strict(key: &'static str, default: u64) -> Result<u64, ConfigError> {
    crate::queue::env_u64_strict(key, default).map_err(|e| ConfigError::Invalid {
        key,
        reason: e.to_string(),
    })
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

fn cx_of<'a>(
    pool: &'a PgPool,
    guard: &'a Guard,
    signer: &'a WriterSigner,
    signer_account: &'a AccountId32,
    proxy_for: Option<[u8; 32]>,
    config: &WriterConfig,
) -> Cx<'a> {
    Cx {
        pool,
        guard,
        signer,
        signer_account,
        proxy_for,
        max_attempts: config.max_attempts,
        batch_max: config.batch_size,
        finalize_timeout: config.finalize_timeout,
        lease_ttl: config.lease_ttl,
    }
}

#[cfg(test)]
mod tests {
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
        "ATTESTER_RESOURCE_POLL_SECS",
        "ATTESTER_ALLOWANCE_FLOOR",
        "ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK",
        "ASSET_HUB_RPC_URL",
    ];

    const REQUIRED_ENV: &[(&str, &str)] = &[
        (
            "DEVICE_ATTESTATION_DATABASE_URL",
            "postgres://writer:pw@localhost/device_attestation",
        ),
        ("CHAIN_WRITER_SIGNER_SURI", "//Writer"),
        ("ATTESTER_ACCOUNT", ALICE_SS58),
        ("ASSET_HUB_RPC_URL", "wss://asset-hub.invalid"),
    ];

    const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

    const ALICE_HEX: &str = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

    fn from_env_with(vars: &[(&str, &str)]) -> Result<WriterConfig, ConfigError> {
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
            ("ATTESTER_RESOURCE_POLL_SECS", "120"),
            ("ATTESTER_ALLOWANCE_FLOOR", "250"),
            ("ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK", "123456789012"),
            ("ASSET_HUB_RPC_URL", "wss://asset-hub.example"),
        ])
        .unwrap();
        assert_eq!(
            config.database_url.expose_secret(),
            "postgres://writer:pw@localhost/device_attestation"
        );
        assert_eq!(config.people_rpc_url, "wss://people.example");
        assert_eq!(config.asset_hub_rpc_url, "wss://asset-hub.example");
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
            err.to_string().contains("CHAIN_WRITER_SIGNER_SURI"),
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
        let err = err.to_string();
        assert!(err.contains("ATTESTER_ALLOWANCE_FLOOR"), "{err}");
        assert!(err.contains("must fit a u32"), "{err}");

        let mut vars = REQUIRED_ENV.to_vec();
        vars.push(("CHAIN_WRITER_LEASE_TTL_SECS", "garbage"));
        vars.push(("CHAIN_WRITER_BATCH_SIZE", "lots"));
        let config = from_env_with(&vars).unwrap();
        assert_eq!(config.lease_ttl, Duration::from_secs(30));
        assert_eq!(config.batch_size, 25);
    }
}
