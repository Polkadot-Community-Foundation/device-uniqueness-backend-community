// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use chain_types::people;
use chain_types::people::runtime_types::indiv_support::traits::reality::RingExponent;
use subxt::ext::codec::Decode as _;
use verifiable::ring::bandersnatch::BandersnatchVrfVerifiable;
use verifiable::ring::RingDomainSize;

/// Canonical personhood collections accepted by proof-authorized issuance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersonhoodCollection {
    PeopleLite,
    People,
}

impl PersonhoodCollection {
    pub const ALL: [Self; 2] = [Self::PeopleLite, Self::People];

    /// The canonical 32-byte on-chain collection id.
    pub const fn id(self) -> [u8; 32] {
        match self {
            Self::PeopleLite => *b"pop:polkadot.network/people-lite",
            Self::People => *b"pop:polkadot.network/people     ",
        }
    }

    /// Parse a hex-encoded collection id, accepting only the canonical pair.
    pub fn from_hex(raw: &str) -> Option<Self> {
        let id: [u8; 32] = hex::decode(raw.trim().trim_start_matches("0x"))
            .ok()?
            .try_into()
            .ok()?;
        Self::ALL
            .into_iter()
            .find(|collection| collection.id() == id)
    }
}

/// The ring commitment type proofs are validated against.
pub type Members = <BandersnatchVrfVerifiable as verifiable::GenerateVerifiable>::Members;

/// One root a proof may be verified against.
#[derive(Clone)]
pub struct AcceptedRoot {
    pub ring_index: u32,
    pub revision: u32,
    pub members: Members,
}

/// Accepted roots from one refresh.
#[derive(Clone)]
pub struct Snapshot {
    /// Ring domain from the collection's configured `RingExponent`.
    pub domain: RingDomainSize,
    /// Accepted roots, current revision before previous, ring-ascending.
    pub roots: Arc<Vec<AcceptedRoot>>,
}

/// Thread-safe latest snapshot, with the time it was observed.
///
/// An RPC outage deliberately preserves the last snapshot so issuance survives
/// a blip, but membership is revocable: a member removed from the ring would
/// keep verifying for as long as the outage lasted. Readers therefore ask for
/// a maximum age and fail closed past it.
pub struct RootCache {
    inner: RwLock<Option<(Snapshot, Instant)>>,
}

impl RootCache {
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(None),
        })
    }

    /// Replace the snapshot, stamping it with the current time.
    pub fn set(&self, snapshot: Snapshot) {
        *self.inner.write().expect("root cache lock") = Some((snapshot, Instant::now()));
    }

    /// Clear the snapshot immediately, causing subsequent verification to fail
    /// closed (503).
    pub fn clear(&self) {
        *self.inner.write().expect("root cache lock") = None;
    }

    /// Return the latest snapshot if it was observed within `max_age`.
    ///
    /// `None` means either "never refreshed" or "too old to trust"; both are
    /// the same 503 to a caller, and neither may verify a proof.
    pub fn snapshot(&self, max_age: Duration) -> Option<Snapshot> {
        let guard = self.inner.read().expect("root cache lock");
        let (snapshot, observed_at) = guard.as_ref()?;
        (observed_at.elapsed() <= max_age).then(|| snapshot.clone())
    }
}

/// One independently refreshed cache for each accepted personhood collection.
#[derive(Clone)]
pub struct RootCaches {
    people_lite: Arc<RootCache>,
    people: Arc<RootCache>,
}

impl RootCaches {
    pub fn empty() -> Self {
        Self {
            people_lite: RootCache::empty(),
            people: RootCache::empty(),
        }
    }

    /// Select exactly the cache named by the request's allowlisted collection.
    pub fn get(&self, collection: PersonhoodCollection) -> Arc<RootCache> {
        match collection {
            PersonhoodCollection::PeopleLite => self.people_lite.clone(),
            PersonhoodCollection::People => self.people.clone(),
        }
    }
}

/// Chain-facing configuration for the refresher.
#[derive(Clone)]
pub struct RootsConfig {
    pub rpc_url: String,
    /// Collection whose rings are accepted, such as `people-lite`.
    pub collection: [u8; 32],
    /// Expected genesis hash; mismatches fail closed.
    pub genesis: [u8; 32],
    pub refresh: Duration,
}

/// Spawn the background refresher without blocking the listener.
pub fn spawn_refresher(cache: Arc<RootCache>, config: RootsConfig) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(config.refresh);
        let api = chain_client::connect(&config.rpc_url).await.unwrap();
        loop {
            let Ok(api) = api.at_current_block().await else {
                continue;
            };
            let genesis = api.genesis_hash();
            if genesis.is_some_and(|genesis| genesis.0 != config.genesis) {
                tracing::error!(
                    collection = %hex::encode(config.collection),
                    chain_genesis = %hex::encode(genesis.unwrap_or_default()),
                    configured = %hex::encode(config.genesis),
                    "proof root refresher: genesis mismatch — refusing to serve roots"
                );
                interval.tick().await;
                cache.clear();
                continue;
            }
            loop {
                interval.tick().await;
                match refresh(&api.online_client(), config.collection).await {
                    Ok(snapshot) => {
                        tracing::debug!(
                            collection = %hex::encode(config.collection),
                            roots = snapshot.roots.len(),
                            "proof roots refreshed"
                        );
                        cache.set(snapshot);
                    }
                    Err(error) => {
                        tracing::warn!(
                            collection = %hex::encode(config.collection),
                            %error,
                            "proof root refresh failed; retrying and re-verifying genesis"
                        );
                        break;
                    }
                }
            }
        }
    });
}

/// Read every ring's current and retained previous root.
async fn refresh(
    api: &subxt::OnlineClient<chain_types::PeopleConfig>,
    collection: [u8; 32],
) -> anyhow::Result<Snapshot> {
    use anyhow::Context as _;

    let at = api.at_current_block().await?;

    let info = at
        .storage()
        .try_fetch(people::storage().members().collections(), (collection,))
        .await?
        .context("collection not found on chain")?
        .decode()?;
    let domain = match info.ring_size {
        RingExponent::R2e9 => RingDomainSize::Domain11,
        RingExponent::R2e10 => RingDomainSize::Domain12,
        RingExponent::R2e14 => RingDomainSize::Domain16,
    };

    let current_ring = at
        .storage()
        .try_fetch(
            subxt::dynamic::storage::<([u8; 32],), subxt::ext::scale_value::Value>(
                "Members",
                "CurrentRingIndex",
            ),
            (collection,),
        )
        .await?
        .map(|value| u32::decode(&mut value.bytes()))
        .transpose()?
        .unwrap_or(0);

    let mut roots = Vec::new();
    for ring_index in 0..=current_ring {
        let Some(value) = at
            .storage()
            .try_fetch(
                subxt::dynamic::storage::<([u8; 32], u32), subxt::ext::scale_value::Value>(
                    "Members", "Root",
                ),
                (collection, ring_index),
            )
            .await?
        else {
            continue;
        };
        let mut cursor = value.bytes();
        let members = Members::decode(&mut cursor).map_err(|e| {
            anyhow::anyhow!("ring {ring_index} root is not the pinned encoding: {e}")
        })?;
        let revision = u32::decode(&mut cursor)?;
        roots.push(AcceptedRoot {
            ring_index,
            revision,
            members,
        });

        // Accept the previous revision too (root rotation window), if kept.
        let Some(previous) = revision.checked_sub(1) else {
            continue;
        };
        let old = at
            .storage()
            .try_fetch(
                subxt::dynamic::storage::<([u8; 32], u32, [u8; 4]), subxt::ext::scale_value::Value>(
                    "Members", "OldRoots",
                ),
                (collection, ring_index, previous.to_be_bytes()),
            )
            .await?;
        if let Some(old) = old {
            let members = Members::decode(&mut old.bytes()).map_err(|e| {
                anyhow::anyhow!("ring {ring_index} old root {previous} does not decode: {e}")
            })?;
            roots.push(AcceptedRoot {
                ring_index,
                revision: previous,
                members,
            });
        }
    }

    Ok(Snapshot {
        domain,
        roots: Arc::new(roots),
    })
}
