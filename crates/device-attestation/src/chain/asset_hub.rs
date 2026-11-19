// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{BTreeSet, HashMap};

use anyhow::Context as _;
use chain_client::storage;
use chain_types::AssetHubConfig;
use subxt::config::RpcConfigFor;
use subxt::dynamic::{At as _, Value};
use subxt::utils::AccountId32;
use subxt::OnlineClient;
use subxt_rpcs::{LegacyRpcMethods, RpcClient};

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

    /// Wraps an already-constructed online client and the RPC client it was
    /// built on. For offline replay tests.
    pub fn from_parts(client: OnlineClient<AssetHubConfig>, rpc: RpcClient) -> Self {
        Self {
            client,
            rpc: LegacyRpcMethods::new(rpc),
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

    pub async fn next_nonce(&self, account: &AccountId32) -> anyhow::Result<u64> {
        self.rpc
            .system_account_next_index(account)
            .await
            .context("system_accountNextIndex on Asset Hub")
    }
}

fn label_key(lite_label: &str) -> Value {
    Value::from_bytes(lite_label.as_bytes())
}
