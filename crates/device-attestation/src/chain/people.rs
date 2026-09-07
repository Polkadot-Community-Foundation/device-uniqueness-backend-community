// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{BTreeSet, HashMap};

use anyhow::Context as _;
use chain_client::storage;
use chain_types::{people, PeopleConfig};
use subxt::{config::RpcConfigFor, OnlineClient};
use subxt_rpcs::{LegacyRpcMethods, RpcClient};

const DISCRIMINATORS: u8 = 100;

const HEALTH_PROBE_USERNAME: &str = "readyz-probe.00";

fn owner_key(
    username: impl AsRef<[u8]>,
) -> people::runtime_types::bounded_collections::bounded_vec::BoundedVec<u8> {
    people::runtime_types::bounded_collections::bounded_vec::BoundedVec(username.as_ref().to_vec())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReservationState {
    /// The bare name is owned as a full-person username.
    pub full_name_owned: bool,
    /// Accounts queued for the bare name.
    pub queue_len: u32,
    pub queue_capacity: u32,
}

impl ReservationState {
    pub fn queue_full(&self) -> bool {
        self.queue_len >= self.queue_capacity
    }

    pub fn rejects(&self) -> bool {
        self.full_name_owned || self.queue_full()
    }
}

/// Everything under one base username that decides whether a claim can land, checked at a
/// single block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaseState {
    /// Discriminators `00..=99` already owned under this base.
    pub taken: BTreeSet<u8>,
    /// The bare base is owned as a full-person username.
    pub full_name_owned: bool,
    /// Accounts queued for the bare base.
    pub queue_len: u32,
    pub queue_capacity: u32,
}

impl BaseState {
    pub fn reservation(&self) -> ReservationState {
        ReservationState {
            full_name_owned: self.full_name_owned,
            queue_len: self.queue_len,
            queue_capacity: self.queue_capacity,
        }
    }

    pub fn reservation_queue_full(&self) -> bool {
        self.reservation().queue_full()
    }

    pub fn rejects_reservations(&self) -> bool {
        self.reservation().rejects()
    }
}

fn decode_queue_len(bytes: &[u8]) -> anyhow::Result<u32> {
    use subxt::ext::codec::{Compact, Decode as _};

    let mut input = bytes;
    let Compact(len) = Compact::<u32>::decode(&mut input)
        .context("decoding Resources::UsernameReservationQueue length")?;
    Ok(len)
}

#[derive(Clone)]
pub struct PeopleChain {
    client: OnlineClient<PeopleConfig>,
    rpc: LegacyRpcMethods<RpcConfigFor<PeopleConfig>>,
}

impl PeopleChain {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let (client, rpc) = chain_client::connect_with_rpc(url).await?;
        Ok(Self::from_parts(client, rpc))
    }

    pub fn from_parts(client: OnlineClient<PeopleConfig>, rpc: RpcClient) -> Self {
        Self {
            client,
            rpc: LegacyRpcMethods::new(rpc),
        }
    }

    pub async fn health(&self) -> anyhow::Result<()> {
        let at = self
            .client
            .at_current_block()
            .await
            .context("People Chain unreachable")?;
        let key = at
            .storage()
            .entry(people::storage().resources().username_owner_of())?
            .fetch_key((owner_key(HEALTH_PROBE_USERNAME),))?;
        self.rpc
            .state_query_storage_at([key.as_slice()], Some(at.block_hash()))
            .await
            .context("People Chain does not serve state_queryStorageAt")?;
        Ok(())
    }

    pub fn online(&self) -> &OnlineClient<PeopleConfig> {
        &self.client
    }

    pub async fn username_owner(&self, full_username: &str) -> anyhow::Result<Option<[u8; 32]>> {
        let at = self.client.at_current_block().await?;
        let address = people::storage().resources().username_owner_of();
        let owner = at
            .storage()
            .try_fetch(address, (owner_key(full_username),))
            .await?;
        match owner {
            Some(value) => Ok(Some(value.decode()?.0)),
            None => Ok(None),
        }
    }

    pub async fn free_balance(&self, account: [u8; 32]) -> anyhow::Result<u128> {
        let at = self.client.at_current_block().await?;
        let address = people::storage().system().account();
        let info = at
            .storage()
            .try_fetch(address, (subxt::utils::AccountId32(account),))
            .await?;
        match info {
            Some(value) => Ok(value.decode()?.data.free),
            None => Ok(0),
        }
    }

    pub async fn attestation_allowance(&self, account: [u8; 32]) -> anyhow::Result<u32> {
        let at = self.client.at_current_block().await?;
        let address = people::storage().people_lite().attestation_allowance();
        let allowance = at
            .storage()
            .try_fetch(address, (subxt::utils::AccountId32(account),))
            .await?;
        match allowance {
            Some(value) => Ok(value.decode()?),
            None => Ok(0),
        }
    }

    pub async fn taken_discriminators(&self, base: &str) -> anyhow::Result<BTreeSet<u8>> {
        Ok(self.base_state(base).await?.taken)
    }

    pub async fn taken_discriminators_at(
        &self,
        base: &str,
        at: &subxt::client::ClientAtBlock<
            PeopleConfig,
            subxt::client::OnlineClientAtBlockImpl<PeopleConfig>,
        >,
    ) -> anyhow::Result<BTreeSet<u8>> {
        Ok(self.base_state_at(base, at).await?.taken)
    }

    pub async fn base_state(&self, base: &str) -> anyhow::Result<BaseState> {
        let at = self.client.at_current_block().await?;
        self.base_state_at(base, &at).await
    }

    pub async fn base_state_at(
        &self,
        base: &str,
        at: &subxt::client::ClientAtBlock<
            PeopleConfig,
            subxt::client::OnlineClientAtBlockImpl<PeopleConfig>,
        >,
    ) -> anyhow::Result<BaseState> {
        let block_hash = at.block_hash();
        let owners = at
            .storage()
            .entry(people::storage().resources().username_owner_of())?;
        let queue = at
            .storage()
            .entry(people::storage().resources().username_reservation_queue())?;

        let mut keys = (0..DISCRIMINATORS)
            .map(|discriminator| {
                owners.fetch_key((owner_key(format!("{base}.{discriminator:02}")),))
            })
            .collect::<Result<Vec<_>, _>>()?;
        keys.push(owners.fetch_key((owner_key(base),))?);
        keys.push(queue.fetch_key((owner_key(base),))?);

        let values = storage::fetch_many(&self.rpc, &keys, block_hash)
            .await
            .context("reading username owners")?;
        let [discriminators @ .., full_name, reservation_queue] = values.as_slice() else {
            anyhow::bail!("batched base-state read returned too few values");
        };

        Ok(BaseState {
            taken: storage::present_of(discriminators.to_vec())
                .into_iter()
                .map(|i| i as u8)
                .collect(),
            full_name_owned: full_name.is_some(),
            queue_len: match reservation_queue {
                Some(bytes) => decode_queue_len(bytes)?,
                None => 0,
            },
            queue_capacity: at
                .constants()
                .entry(
                    people::constants()
                        .resources()
                        .max_reservation_queue_length(),
                )
                .context("reading Resources::MaxReservationQueueLength")?,
        })
    }

    /// The reservation state of one bare full-person name.
    pub async fn reservation_state(&self, name: &str) -> anyhow::Result<ReservationState> {
        let at = self.client.at_current_block().await?;
        let block_hash = at.block_hash();
        let owners = at
            .storage()
            .entry(people::storage().resources().username_owner_of())?;
        let queue = at
            .storage()
            .entry(people::storage().resources().username_reservation_queue())?;
        let keys = [
            owners.fetch_key((owner_key(name),))?,
            queue.fetch_key((owner_key(name),))?,
        ];

        let values = storage::fetch_many(&self.rpc, &keys, block_hash)
            .await
            .context("reading username reservation state")?;
        let [full_name, reservation_queue] = values.as_slice() else {
            anyhow::bail!("batched reservation-state read returned too few values");
        };

        Ok(ReservationState {
            full_name_owned: full_name.is_some(),
            queue_len: match reservation_queue {
                Some(bytes) => decode_queue_len(bytes)?,
                None => 0,
            },
            queue_capacity: at
                .constants()
                .entry(
                    people::constants()
                        .resources()
                        .max_reservation_queue_length(),
                )
                .context("reading Resources::MaxReservationQueueLength")?,
        })
    }

    pub async fn username_owners(
        &self,
        names: &[&str],
    ) -> anyhow::Result<HashMap<String, [u8; 32]>> {
        if names.is_empty() {
            return Ok(HashMap::new());
        }
        let unique: BTreeSet<&str> = names.iter().copied().collect();

        let at = self.client.at_current_block().await?;
        let block_hash = at.block_hash();
        let entry = at
            .storage()
            .entry(people::storage().resources().username_owner_of())?;
        let keys = unique
            .iter()
            .map(|name| entry.fetch_key((owner_key(name),)))
            .collect::<Result<Vec<_>, _>>()?;

        let values = storage::fetch_many(&self.rpc, &keys, block_hash)
            .await
            .context("reading username owners")?;
        Ok(storage::owners_by_name(&unique, values)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use subxt::ext::codec::Encode as _;

    fn queue(entries: usize) -> Vec<u8> {
        (0..entries)
            .map(|i| ([i as u8; 32], 1_750_000_000u64 + i as u64))
            .collect::<Vec<_>>()
            .encode()
    }

    #[test]
    fn queue_length_is_read_without_decoding_the_entries() {
        for entries in [0usize, 1, 9, 10, 64] {
            assert_eq!(decode_queue_len(&queue(entries)).unwrap(), entries as u32);
        }
    }

    #[test]
    fn a_truncated_queue_value_is_an_error_not_a_zero() {
        assert!(decode_queue_len(&[]).is_err());
    }

    #[test]
    fn a_full_queue_rejects_reservations_and_a_free_one_does_not() {
        let state = |queue_len, full_name_owned| BaseState {
            taken: BTreeSet::new(),
            full_name_owned,
            queue_len,
            queue_capacity: 10,
        };

        assert!(!state(9, false).rejects_reservations());
        assert!(state(10, false).rejects_reservations());
        assert!(state(11, false).rejects_reservations());
        assert!(state(0, true).rejects_reservations());
    }

    #[test]
    fn the_reservation_half_of_a_base_state_matches_a_standalone_read() {
        for (queue_len, full_name_owned) in
            [(0, false), (9, false), (10, false), (11, false), (0, true)]
        {
            let base = BaseState {
                taken: BTreeSet::from([1, 2, 3]),
                full_name_owned,
                queue_len,
                queue_capacity: 10,
            };
            let standalone = ReservationState {
                full_name_owned,
                queue_len,
                queue_capacity: 10,
            };

            assert_eq!(base.reservation(), standalone);
            assert_eq!(base.rejects_reservations(), standalone.rejects());
            assert_eq!(base.reservation_queue_full(), standalone.queue_full());
        }
    }
}
