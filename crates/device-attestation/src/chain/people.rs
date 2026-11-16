// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{BTreeSet, HashMap};

use anyhow::Context as _;
use chain_client::storage;
use chain_types::{people, PeopleConfig};
use subxt::{config::RpcConfigFor, utils::AccountId32, OnlineClient};
use subxt_rpcs::{LegacyRpcMethods, RpcClient};

use crate::chain::attest::AttestShape;
use crate::chain::registry::Claim;
use crate::{check_pallet_call_arg_names, extract_call_fields, Pallet};

/// The People Chain client pinned to one block.
pub type PeopleAt = subxt::client::ClientAtBlock<
    PeopleConfig,
    subxt::client::OnlineClientAtBlockImpl<PeopleConfig>,
>;

/// How many `.NN` suffixes a base has, `00` included: the keys an
/// availability read asks for.
pub(crate) const DISCRIMINATORS: u8 = 100;

const PALLET: &str = "PeopleLite";

/// The pallet that keeps consumer records. Read dynamically, because the
/// username removal changes `Consumers`' value type, which a vendored storage
/// address would refuse to read.
const RESOURCES_PALLET: &str = "Resources";

/// The account whose `PeopleLite::AttestationAllowance` key `/readyz` asks
/// for. Any account works: the probe needs the read served, not a value.
const HEALTH_PROBE_ACCOUNT: [u8; 32] = [0; 32];

fn owner_key(
    username: impl AsRef<[u8]>,
) -> people::runtime_types::bounded_collections::bounded_vec::BoundedVec<u8> {
    people::runtime_types::bounded_collections::bounded_vec::BoundedVec(username.as_ref().to_vec())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReservationState {
    /// The bare name is owned as a personhood username.
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
    /// The bare base is owned as a personhood username.
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
        let self_ = Self::from_parts(client, rpc);
        self_.check_attest_shape().await?;
        Ok(self_)
    }

    /// Refuses to start against a runtime whose `attest` this backend cannot
    /// build: the arguments must be the vendored ones by name, and the consumer
    /// registration one of the two shapes [`AttestShape`] knows. Which of the
    /// two is read again per pass, since the runtime can upgrade while we run.
    async fn check_attest_shape(&self) -> anyhow::Result<()> {
        let vendored_call = extract_call_fields(
            chain_types::metadata_arc(),
            PALLET,
            "attest",
            /* vendored= */ true,
        )?;
        let metadata = self.client.at_current_block().await?.metadata();
        let call = extract_call_fields(
            metadata.clone(),
            PALLET,
            "attest",
            /* vendored= */ false,
        )?;
        check_pallet_call_arg_names(
            vendored_call.fields.as_slice(),
            Pallet::PeopleLite,
            call.fields.as_slice(),
        )?;
        let shape = AttestShape::try_from(&*metadata)?;
        tracing::info!(
            ?shape,
            payload_version = %shape.payload_version(),
            "connected People runtime's attest shape"
        );
        Ok(())
    }

    pub fn from_parts(client: OnlineClient<PeopleConfig>, rpc: RpcClient) -> Self {
        Self {
            client,
            rpc: LegacyRpcMethods::new(rpc),
        }
    }

    /// Proves the node serves `state_queryStorageAt`, which every batched read
    /// here relies on. The key is `PeopleLite::AttestationAllowance`, which
    /// exists before and after the username removal.
    pub async fn health(&self) -> anyhow::Result<()> {
        let at = self
            .client
            .at_current_block()
            .await
            .context("People Chain unreachable")?;
        let address = subxt::dynamic::storage::<_, u32>(PALLET, "AttestationAllowance");
        let key = at
            .storage()
            .entry(address)?
            .fetch_key((AccountId32(HEALTH_PROBE_ACCOUNT),))?;
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

    /// The reservation state of one bare personhood name.
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
        let at = self.client.at_current_block().await?;
        self.username_owners_at(names, &at).await
    }

    /// The owners of those of `names` registered in
    /// `Resources::UsernameOwnerOf` at `at`, in one batched read.
    async fn username_owners_at(
        &self,
        names: &[&str],
        at: &PeopleAt,
    ) -> anyhow::Result<HashMap<String, [u8; 32]>> {
        let unique: BTreeSet<&str> = names.iter().copied().collect();
        let entry = at
            .storage()
            .entry(people::storage().resources().username_owner_of())?;
        let keys = unique
            .iter()
            .map(|name| entry.fetch_key((owner_key(name),)))
            .collect::<Result<Vec<_>, _>>()?;

        let values = storage::fetch_many(&self.rpc, &keys, at.block_hash())
            .await
            .context("reading username owners")?;
        Ok(storage::owners_by_name(&unique, values)?)
    }

    /// Which of `claims` the People Chain shows as registered to their
    /// candidate, keyed by name, at the current block. The writer's "already
    /// landed" read.
    ///
    /// A runtime whose `attest` takes the username records it in
    /// `Resources::UsernameOwnerOf`, so the name is the key and its owner may
    /// be someone else. One without it records only the consumer, so a claim
    /// has landed once its candidate is in `Resources::Consumers`. The shape
    /// is read at the same block as the storage, so a read that straddles the
    /// runtime upgrade still asks the storage that block has.
    ///
    /// The account-keyed read only tests for presence, so it is right while
    /// the stepped migration is still translating `Consumers` records.
    pub async fn registered_owners(
        &self,
        claims: &[Claim<'_>],
    ) -> anyhow::Result<HashMap<String, [u8; 32]>> {
        if claims.is_empty() {
            return Ok(HashMap::new());
        }
        let at = self.client.at_current_block().await?;
        match AttestShape::try_from(at.metadata_ref())? {
            AttestShape::WithUsername => {
                let names: Vec<&str> = claims.iter().map(|(name, _)| *name).collect();
                self.username_owners_at(&names, &at).await
            }
            AttestShape::WithoutUsername => self.registered_consumers_at(claims, &at).await,
        }
    }

    /// Each of `claims` whose candidate has a `Resources::Consumers` record at
    /// `at`, as `name -> candidate`, in one batched read.
    async fn registered_consumers_at(
        &self,
        claims: &[Claim<'_>],
        at: &PeopleAt,
    ) -> anyhow::Result<HashMap<String, [u8; 32]>> {
        let address =
            subxt::dynamic::storage::<_, subxt::dynamic::Value>(RESOURCES_PALLET, "Consumers");
        let entry = at.storage().entry(address)?;
        let mut keys: Vec<Vec<u8>> = Vec::with_capacity(claims.len());
        for (_, candidate) in claims {
            keys.push(entry.fetch_key((AccountId32(*candidate),))?);
        }

        let present = storage::fetch_present(&self.rpc, &keys, at.block_hash())
            .await
            .context("reading consumer records")?;
        Ok(owners_of_registered(claims, &present))
    }

    pub async fn next_nonce(&self, account: &AccountId32) -> anyhow::Result<u64> {
        self.rpc
            .system_account_next_index(account)
            .await
            .context("system_accountNextIndex on People Chain")
    }
}

/// Each claim whose candidate's key is in `present`, as `name -> candidate`.
#[must_use]
fn owners_of_registered(
    claims: &[Claim<'_>],
    present: &BTreeSet<usize>,
) -> HashMap<String, [u8; 32]> {
    claims
        .iter()
        .enumerate()
        .filter(|(index, _)| present.contains(index))
        .map(|(_, (name, candidate))| ((*name).to_owned(), *candidate))
        .collect()
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
    fn a_claim_whose_candidate_is_a_consumer_reads_as_owned_by_it() {
        let claims: [Claim<'_>; 3] = [
            ("alice.01", [1; 32]),
            ("bob.02", [2; 32]),
            ("carol.03", [3; 32]),
        ];
        let present = BTreeSet::from([0, 2]);

        let owners = owners_of_registered(&claims, &present);

        assert_eq!(
            owners,
            HashMap::from([
                ("alice.01".to_owned(), [1; 32]),
                ("carol.03".to_owned(), [3; 32])
            ]),
            "only the claims whose consumer record exists have landed, each to its own candidate"
        );
    }

    #[test]
    fn no_consumer_record_means_nothing_landed() {
        let claims: [Claim<'_>; 1] = [("alice.01", [1; 32])];

        assert!(
            owners_of_registered(&claims, &BTreeSet::new()).is_empty(),
            "an absent consumer record must leave the claim submittable"
        );
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
