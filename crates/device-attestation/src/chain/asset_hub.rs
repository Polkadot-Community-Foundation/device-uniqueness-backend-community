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

use crate::dotns;

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
        let metadata = self.client.at_current_block().await?.metadata();
        let pallet = metadata
            .pallet_by_name(PALLET)
            .with_context(|| format!("runtime declares no {PALLET} pallet"))?;
        let call = pallet
            .call_variant_by_name("reserve_name")
            .with_context(|| format!("{PALLET} declares no reserve_name call"))?;
        let fields: Vec<&str> = call
            .fields
            .iter()
            .map(|field| field.name.as_deref().unwrap_or("<unnamed>"))
            .collect();
        dotns::check_reserve_name_shape(&fields)?;
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
}

/// One `DotnsGateway::AccountNames` record: the account it belongs to and the
/// raw SCALE value (used only as a change detector by the settlement cache).
#[derive(Debug, Clone)]
pub struct AccountNameRecord {
    pub account: [u8; 32],
    pub raw: Vec<u8>,
}

impl AssetHub {
    /// `DotnsGateway::DispatcherAddress`: the PoP controller the gateway
    /// dispatches into. `None` until governance sets it.
    pub async fn dispatcher_address(&self) -> anyhow::Result<Option<[u8; 20]>> {
        let at = self.client.at_current_block().await?;
        let address = subxt::dynamic::storage::<(), Value>(PALLET, "DispatcherAddress");
        let value = at.storage().try_fetch(address, ()).await?;
        let Some(value) = value else { return Ok(None) };
        let bytes = crate::chain::settle::composite_bytes(&value.decode()?);
        let mut out = [0u8; 20];
        anyhow::ensure!(bytes.len() == 20, "DispatcherAddress is not 20 bytes");
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }

    /// Every `DotnsGateway::AccountNames` entry. The map key is
    /// `blake2_128concat(AccountId32)`, so the account is the key's last 32
    /// bytes; the value is kept raw as a change detector.
    pub async fn account_names(&self) -> anyhow::Result<Vec<AccountNameRecord>> {
        let at = self.client.at_current_block().await?;
        let address = subxt::dynamic::storage::<(AccountId32,), Value>(PALLET, "AccountNames");
        let entry = at.storage().entry(address)?;
        let mut stream = entry.iter(()).await?;
        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            let item = item.context("iterating DotnsGateway::AccountNames")?;
            let key = item.key_bytes();
            anyhow::ensure!(key.len() >= 32, "AccountNames key shorter than an account");
            let mut account = [0u8; 32];
            account.copy_from_slice(&key[key.len() - 32..]);
            out.push(AccountNameRecord {
                account,
                raw: item.value().bytes().to_vec(),
            });
        }
        Ok(out)
    }

    /// Whether `account` has a revive address mapping (`Revive::OriginalAccount`
    /// keyed by its H160). A substrate signer needs one before it can call a
    /// contract.
    pub async fn is_revive_mapped(&self, account: &[u8; 32]) -> anyhow::Result<bool> {
        let h160 = crate::chain::settle::to_h160(account);
        let at = self.client.at_current_block().await?;
        let address = subxt::dynamic::storage::<_, Value>("Revive", "OriginalAccount");
        let value = at
            .storage()
            .try_fetch(address, (Value::from_bytes(h160),))
            .await?;
        Ok(value.is_some())
    }

    /// Dry-runs a contract call through the `ReviveApi_call` runtime API from
    /// `origin`, returning the gas and deposit the real call needs plus its
    /// return data.
    pub async fn revive_dry_run(
        &self,
        origin: &[u8; 32],
        dest: &[u8; 20],
        input: Vec<u8>,
    ) -> anyhow::Result<crate::chain::settle::DryRun> {
        let call = subxt::dynamic::runtime_api_call::<Vec<Value>, Value>(
            "ReviveApi",
            "call",
            vec![
                Value::from_bytes(origin),
                Value::from_bytes(dest),
                Value::u128(0),
                Value::unnamed_variant("None", []),
                Value::unnamed_variant("None", []),
                Value::from_bytes(input),
            ],
        );
        let value = self
            .client
            .at_current_block()
            .await?
            .runtime_apis()
            .call(call)
            .await
            .context("ReviveApi_call dry run")?;
        crate::chain::settle::decode_dry_run(&value)
    }
}

fn label_key(lite_label: &str) -> Value {
    Value::from_bytes(lite_label.as_bytes())
}
