// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use chain_types::PeopleConfig;
use subxt::{backend::LegacyBackend, client::Blocks, config::RpcConfigFor, OnlineClient};
use subxt_rpcs::client::{ReconnectingRpcClient, RpcClient};
use subxt_rpcs::LegacyRpcMethods;

/// Boxed chain transport or metadata error.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// People Chain connection or query failure.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("connecting to People Chain at {url}: {source}")]
    Connect {
        url: String,
        #[source]
        source: BoxError,
    },
    /// Online client metadata initialization failed.
    #[error("initializing People Chain client: {0}")]
    Initialize(#[source] BoxError),
    #[error("querying People Chain finalized snapshot: {0}")]
    Query(#[source] BoxError),
    /// `chain_getHeader` answered, but with no header at all.
    #[error("People Chain reported no best header")]
    NoBestHeader,
}

/// Connected People Chain client using a reconnecting legacy backend.
#[derive(Clone)]
pub struct PeopleChain {
    client: OnlineClient<PeopleConfig>,
    rpc: LegacyRpcMethods<RpcConfigFor<PeopleConfig>>,
}

impl PeopleChain {
    /// Connect and configure bounded legacy storage paging.
    pub async fn connect(url: &str, storage_page_size: u32) -> Result<Self, ChainError> {
        let reconnecting = ReconnectingRpcClient::builder()
            .build(url)
            .await
            .map_err(|source| ChainError::Connect {
                url: url.to_string(),
                source: Box::new(source),
            })?;
        let rpc_client = RpcClient::new(reconnecting);
        let backend = LegacyBackend::<PeopleConfig>::builder()
            .storage_page_size(storage_page_size)
            .build(rpc_client.clone());
        let client = OnlineClient::from_backend(Arc::new(backend))
            .await
            .map_err(|source| ChainError::Initialize(Box::new(source)))?;
        Ok(Self::from_parts(client, rpc_client))
    }

    /// Wrap an already-constructed online client (offline replay tests).
    pub fn from_parts(client: OnlineClient<PeopleConfig>, rpc: RpcClient) -> Self {
        Self {
            client,
            rpc: LegacyRpcMethods::new(rpc),
        }
    }

    pub fn online(&self) -> &OnlineClient<PeopleConfig> {
        &self.client
    }

    pub async fn best_blocks(&self) -> Result<Blocks<PeopleConfig>, ChainError> {
        self.client
            .stream_best_blocks()
            .await
            .map_err(|source| ChainError::Query(Box::new(source)))
    }

    pub async fn finalized_head_number(&self) -> Result<u64, ChainError> {
        Ok(self
            .client
            .at_current_block()
            .await
            .map_err(|source| ChainError::Query(Box::new(source)))?
            .block_number())
    }

    pub async fn best_head_number(&self) -> Result<u64, ChainError> {
        let header = self
            .rpc
            .chain_get_header(None)
            .await
            .map_err(|source| ChainError::Query(Box::new(source)))?
            .ok_or(ChainError::NoBestHeader)?;
        Ok(header.number)
    }

    /// Verify that a current finalized block is reachable.
    pub async fn health(&self) -> Result<(), ChainError> {
        self.client
            .at_current_block()
            .await
            .map_err(|source| ChainError::Query(Box::new(source)))?;
        Ok(())
    }
}
