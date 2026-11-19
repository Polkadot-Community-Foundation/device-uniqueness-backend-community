// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use anyhow::Context as _;
use chain_client::storage;
use chain_types::AssetHubConfig;
use subxt::config::RpcConfigFor;
use subxt::dynamic::{At as _, Value};
use subxt::ext::scale_value::ValueDef;
use subxt::utils::AccountId32;
use subxt::OnlineClient;
use subxt_rpcs::{LegacyRpcMethods, RpcClient};
use tokio::sync::OnceCell;

use crate::chain::dotns::revive_address;
use crate::chain::dotns::AssetHubAt;
use crate::chain::dotns::Contracts;
use crate::chain::people::ReservationState;
use crate::chain::people::DISCRIMINATORS;
use crate::{check_pallet_call_args, extract_call_fields, Pallet};

const PALLET: &str = "DotnsGateway";

#[derive(Debug, Clone, Copy)]
pub struct ValidityWindow {
    pub max_validity_secs: u64,
    pub max_future_skew_secs: u64,
}

#[derive(Clone)]
pub struct AssetHub {
    client: OnlineClient<AssetHubConfig>,
    rpc: LegacyRpcMethods<RpcConfigFor<AssetHubConfig>>,
    /// The dotNS contracts, resolved on first use and kept for the process's
    /// life: a governance change to `DotnsGateway::DispatcherAddress` is
    /// picked up on restart.
    dotns: Arc<OnceCell<Contracts>>,
}

impl AssetHub {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let (client, rpc) = chain_client::connect_asset_hub_with_rpc(url).await?;
        let this = Self::from_parts(client, rpc);
        this.check_reserve_name_shape()
            .await
            .with_context(|| format!("Asset Hub at {url}"))?;
        Ok(this)
    }

    /// Connects for reads only, without the `reserve_name` shape check
    /// [`Self::connect`] makes. For `device-attestation-api`, which reads
    /// `LiteLabelOwner` for availability and never submits.
    pub async fn connect_for_reads(url: &str) -> anyhow::Result<Self> {
        let (client, rpc) = chain_client::connect_asset_hub_with_rpc(url).await?;
        Ok(Self::from_parts(client, rpc))
    }

    /// Wraps an already-constructed online client and the RPC client it was
    /// built on. For offline replay tests.
    pub fn from_parts(client: OnlineClient<AssetHubConfig>, rpc: RpcClient) -> Self {
        Self {
            client,
            rpc: LegacyRpcMethods::new(rpc),
            dotns: Arc::new(OnceCell::new()),
        }
    }

    pub fn online(&self) -> &OnlineClient<AssetHubConfig> {
        &self.client
    }

    pub async fn health(&self) -> anyhow::Result<()> {
        self.client
            .at_current_block()
            .await
            .context("Asset Hub unreachable")?;
        Ok(())
    }

    async fn check_reserve_name_shape(&self) -> anyhow::Result<()> {
        let vendored_call = extract_call_fields(
            chain_types::asset_hub::metadata_arc(),
            PALLET,
            "reserve_name",
            true,
        )?;
        let call = extract_call_fields(
            self.client.at_current_block().await?.metadata(),
            PALLET,
            "reserve_name",
            false,
        )?;
        check_pallet_call_args(
            vendored_call.fields.as_slice(),
            Pallet::DotnsGateway,
            call.fields.as_slice(),
        )?;
        Ok(())
    }

    pub async fn lite_label_owner(&self, lite_label: &str) -> anyhow::Result<Option<[u8; 32]>> {
        let at = self.client.at_current_block().await?;
        let address = subxt::dynamic::storage::<_, AccountId32>(PALLET, "LiteLabelOwner");
        let owner = at
            .storage()
            .try_fetch(address, (label_key(lite_label),))
            .await?;
        match owner {
            Some(value) => Ok(Some(value.decode()?.0)),
            None => Ok(None),
        }
    }

    /// The discriminators `00..=99` whose `base.NN` lite label is in
    /// `DotnsGateway::LiteLabelOwner`, in one batched read. Every lite label
    /// is there, since only the gateway issues them.
    pub async fn taken_discriminators(&self, base: &str) -> anyhow::Result<BTreeSet<u8>> {
        let at = self.client.at_current_block().await?;
        let entry = at
            .storage()
            .entry(subxt::dynamic::storage::<_, AccountId32>(
                PALLET,
                "LiteLabelOwner",
            ))?;
        let mut keys: Vec<Vec<u8>> = Vec::with_capacity(usize::from(DISCRIMINATORS));
        for discriminator in 0..DISCRIMINATORS {
            let label = format!("{base}.{discriminator:02}");
            keys.push(entry.fetch_key((label_key(&label),))?);
        }

        let present = storage::fetch_present(&self.rpc, &keys, at.block_hash())
            .await
            .context("reading dotNS lite label owners")?;
        Ok(discriminators_of(present))
    }

    /// The reservation state of the bare personhood name `name` on the dotNS
    /// contracts: whether it exists on `DotnsRegistrar` or holds a live grant
    /// on the name whitelist, and how full its `DotnsPopController`
    /// reservation queue is. A claim reserving a name any of them rejects
    /// reverts on chain, device name included.
    pub async fn personhood_reservation(&self, name: &str) -> anyhow::Result<ReservationState> {
        let at = self.client.at_current_block().await?;
        let contracts = self.dotns_contracts(&at).await?;
        contracts
            .reservation(&at, name)
            .await
            .with_context(|| format!("reading the dotNS reservation state of {name}"))
    }

    /// The dotNS contracts, resolved at `at` on first use.
    pub(crate) async fn dotns_contracts(&self, at: &AssetHubAt) -> anyhow::Result<Contracts> {
        let contracts = self
            .dotns
            .get_or_try_init(|| Contracts::resolve(at))
            .await
            .context("resolving the dotNS contracts from DotnsGateway::DispatcherAddress")?;
        Ok(*contracts)
    }

    /// Whether pallet-revive has `account` mapped, which a signed origin needs
    /// before it can call a contract.
    pub async fn is_revive_mapped(&self, account: &[u8; 32]) -> anyhow::Result<bool> {
        if account[20..] == [0xee; 12] {
            // Ethereum-derived accounts are mapped without a storage entry.
            return Ok(true);
        }
        let address = revive_address(account);
        let at = self.client.at_current_block().await?;
        let entry = subxt::dynamic::storage::<_, AccountId32>("Revive", "OriginalAccount");
        let original = at.storage().try_fetch(entry, (address,)).await?;
        Ok(original.is_some())
    }

    pub async fn lite_label_owners(
        &self,
        labels: &[&str],
    ) -> anyhow::Result<HashMap<String, [u8; 32]>> {
        if labels.is_empty() {
            return Ok(HashMap::new());
        }
        let unique: BTreeSet<&str> = labels.iter().copied().collect();

        let at = self.client.at_current_block().await?;
        let block_hash = at.block_hash();
        let entry = at
            .storage()
            .entry(subxt::dynamic::storage::<_, AccountId32>(
                PALLET,
                "LiteLabelOwner",
            ))?;
        let keys = unique
            .iter()
            .map(|label| entry.fetch_key((label_key(label),)))
            .collect::<Result<Vec<_>, _>>()?;

        let values = storage::fetch_many(&self.rpc, &keys, block_hash)
            .await
            .context("reading dotNS lite label owners")?;
        Ok(storage::owners_by_name(&unique, values)?)
    }

    pub async fn attestation_allowance(&self, account: [u8; 32]) -> anyhow::Result<u32> {
        let at = self.client.at_current_block().await?;
        let address = subxt::dynamic::storage::<_, u32>(PALLET, "AttestationAllowance");
        let allowance = at
            .storage()
            .try_fetch(address, (AccountId32(account),))
            .await?;
        match allowance {
            Some(value) => Ok(value.decode()?),
            None => Ok(0),
        }
    }

    pub async fn free_balance(&self, account: [u8; 32]) -> anyhow::Result<u128> {
        let at = self.client.at_current_block().await?;
        let address = subxt::dynamic::storage::<_, Value>("System", "Account");
        let info = at
            .storage()
            .try_fetch(address, (AccountId32(account),))
            .await?;
        let Some(info) = info else { return Ok(0) };
        let value = info.decode()?;
        let free = value
            .at("data")
            .and_then(|data| data.at("free"))
            .and_then(|free| free.as_u128())
            .context("System::Account has no data.free field")?;
        Ok(free)
    }

    pub async fn validity_window(&self) -> anyhow::Result<ValidityWindow> {
        let at = self.client.at_current_block().await?;
        let constants = at.constants();
        Ok(ValidityWindow {
            max_validity_secs: constants
                .entry(subxt::dynamic::constant::<u64>(
                    PALLET,
                    "MaxValiditySeconds",
                ))
                .context("reading DotnsGateway::MaxValiditySeconds")?,
            max_future_skew_secs: constants
                .entry(subxt::dynamic::constant::<u64>(
                    PALLET,
                    "MaxFutureSkewSeconds",
                ))
                .context("reading DotnsGateway::MaxFutureSkewSeconds")?,
        })
    }

    /// The `(ref_time, proof_size)` weight one normal extrinsic may use:
    /// `System::BlockWeights.per_class.normal.max_extrinsic`.
    pub async fn max_extrinsic_weight(&self) -> anyhow::Result<(u64, u64)> {
        let at = self.client.at_current_block().await?;
        let weights: Value = at
            .constants()
            .entry(subxt::dynamic::constant::<Value>("System", "BlockWeights"))
            .context("reading System::BlockWeights")?;
        let max = weights
            .at("per_class")
            .and_then(|classes| classes.at("normal"))
            .and_then(|normal| normal.at("max_extrinsic"))
            .context("BlockWeights has no per_class.normal.max_extrinsic")?;
        let ValueDef::Variant(max) = &max.value else {
            anyhow::bail!("max_extrinsic is not an Option");
        };
        let weight = max
            .values
            .values()
            .next()
            .context("normal extrinsics have no max_extrinsic")?;
        let part = |name: &str| {
            weight
                .at(name)
                .and_then(Value::as_u128)
                .and_then(|part| u64::try_from(part).ok())
                .with_context(|| format!("max_extrinsic has no {name}"))
        };
        Ok((part("ref_time")?, part("proof_size")?))
    }

    pub async fn next_nonce(&self, account: &AccountId32) -> anyhow::Result<u64> {
        self.rpc
            .system_account_next_index(account)
            .await
            .context("system_accountNextIndex on Asset Hub")
    }
}

/// The discriminators at the positions of `present`, which index keys built
/// for `00..DISCRIMINATORS` in order.
#[must_use]
fn discriminators_of(present: BTreeSet<usize>) -> BTreeSet<u8> {
    present
        .into_iter()
        .filter_map(|index| u8::try_from(index).ok())
        .collect()
}

fn label_key(lite_label: &str) -> Value {
    Value::from_bytes(lite_label.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn present_keys_map_back_to_their_discriminators() {
        assert_eq!(
            discriminators_of(BTreeSet::from([0, 7, 99])),
            BTreeSet::from([0, 7, 99]),
            "key i was built for base.{{i:02}}"
        );
    }
}
