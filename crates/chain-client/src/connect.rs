// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use chain_types::{AssetHubConfig, PeopleConfig};
use subxt::OnlineClient;
use subxt_rpcs::client::{ReconnectingRpcClient, RpcClient};

#[derive(Debug, thiserror::Error)]
/// A chain that could not be reached, or whose metadata would not load.
pub enum ConnectError {
    /// The websocket never came up.
    #[error("connecting to {chain} at {url}")]
    Transport {
        /// Which chain, for the message.
        chain: &'static str,
        /// The endpoint dialled.
        url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The connection came up but the runtime metadata would not load.
    #[error("building the {chain} client at {url}")]
    Client {
        /// Which chain, for the message.
        chain: &'static str,
        /// The endpoint dialled.
        url: String,
        #[source]
        source: subxt::error::OnlineClientError,
    },
}

/// Connect to a People Chain RPC and load its metadata.
pub async fn connect(url: &str) -> Result<OnlineClient<PeopleConfig>, ConnectError> {
    connect_as::<PeopleConfig>(
        url,
        "People Chain",
        Some(chain_types::vendored_spec_version()),
    )
    .await
}

/// [`connect`], also handing back the RPC client the online client was built
/// on — what the batched reads in [`crate::storage`] need.
pub async fn connect_with_rpc(
    url: &str,
) -> Result<(OnlineClient<PeopleConfig>, RpcClient), ConnectError> {
    connect_as_with_rpc::<PeopleConfig>(
        url,
        "People Chain",
        Some(chain_types::vendored_spec_version()),
    )
    .await
}

/// Connect to an Asset Hub RPC and load its metadata.
pub async fn connect_asset_hub(url: &str) -> Result<OnlineClient<AssetHubConfig>, ConnectError> {
    connect_as::<AssetHubConfig>(url, "Asset Hub", None).await
}

pub async fn connect_asset_hub_with_rpc(
    url: &str,
) -> Result<(OnlineClient<AssetHubConfig>, RpcClient), ConnectError> {
    connect_as_with_rpc::<AssetHubConfig>(url, "Asset Hub", None).await
}

async fn connect_as_with_rpc<T: subxt::Config + Default>(
    url: &str,
    chain: &'static str,
    vendored_spec_version: Option<u32>,
) -> Result<(OnlineClient<T>, RpcClient), ConnectError> {
    let rpc = reconnecting_rpc_client(url, chain).await?;
    let client = OnlineClient::<T>::from_rpc_client(rpc.clone())
        .await
        .map_err(|source| ConnectError::Client {
            chain,
            url: url.to_string(),
            source,
        })?;
    report_runtime_version(&client, chain, url, vendored_spec_version).await;
    Ok((client, rpc))
}

async fn connect_as<T: subxt::Config + Default>(
    url: &str,
    chain: &'static str,
    vendored_spec_version: Option<u32>,
) -> Result<OnlineClient<T>, ConnectError> {
    let client = OnlineClient::<T>::from_rpc_client(reconnecting_rpc_client(url, chain).await?)
        .await
        .map_err(|source| ConnectError::Client {
            chain,
            url: url.to_string(),
            source,
        })?;
    report_runtime_version(&client, chain, url, vendored_spec_version).await;
    Ok(client)
}

/// Log what the live runtime is at connect. Warn when it has
/// moved past the metadata the codegen was built from.
async fn report_runtime_version<T: subxt::Config>(
    client: &OnlineClient<T>,
    chain: &'static str,
    url: &str,
    vendored_spec_version: Option<u32>,
) {
    let at_block = match client.at_current_block().await {
        Ok(at_block) => at_block,
        Err(error) => {
            tracing::warn!(
                chain,
                url,
                ?error,
                "could not read the live runtime version"
            );
            return;
        }
    };
    let spec_version = at_block.spec_version();
    let transaction_version = at_block.transaction_version();

    match vendored_spec_version {
        Some(vendored) if vendored != spec_version => tracing::warn!(
            chain,
            url,
            spec_version,
            transaction_version,
            vendored_spec_version = vendored,
            "live runtime and the vendored metadata disagree; refresh \
             crates/chain-types/metadata/people.scale (or repoint at a node \
             on the version it was built from) — until then any signed call \
             whose types changed is rejected as not compatible with the live \
             chain"
        ),
        _ => tracing::info!(
            chain,
            url,
            spec_version,
            transaction_version,
            "connected to the chain"
        ),
    }
}

async fn reconnecting_rpc_client(
    url: &str,
    chain: &'static str,
) -> Result<RpcClient, ConnectError> {
    let rpc_client = ReconnectingRpcClient::builder()
        .build(url)
        .await
        .map_err(|source| ConnectError::Transport {
            chain,
            url: url.to_string(),
            source: Box::new(source),
        })?;
    Ok(RpcClient::new(rpc_client))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;

    use anyhow::Context as _;
    use jsonrpsee_core::server::RpcModule;
    use jsonrpsee_server::{ServerBuilder, ServerHandle};
    use subxt_rpcs::rpc_params;

    use super::*;

    #[tokio::test]
    async fn reconnecting_rpc_client_recovers_after_server_restart() -> anyhow::Result<()> {
        let (server, url) = TestRpcServer::start(None).await?;
        let rpc = reconnecting_rpc_client(&url, "test RPC").await?;

        let first: String = rpc.request("ping", rpc_params![]).await?;
        assert_eq!(first, "pong");

        server.stop().await?;
        let addr = url
            .strip_prefix("ws://")
            .context("test RPC URL should be ws://")?
            .parse::<SocketAddr>()?;
        let (_server, _) = TestRpcServer::start(Some(addr)).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let second = tokio::time::timeout(
            Duration::from_secs(5),
            rpc.request::<String>("ping", rpc_params![]),
        )
        .await??;
        assert_eq!(second, "pong");

        Ok(())
    }

    struct TestRpcServer {
        handle: ServerHandle,
    }

    impl TestRpcServer {
        async fn start(addr: Option<SocketAddr>) -> anyhow::Result<(Self, String)> {
            let addr = addr.unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into());
            let server = ServerBuilder::default().build(addr).await?;
            let addr = server.local_addr()?;
            let mut module = RpcModule::new(());
            module.register_async_method("ping", |_, _, _| async { "pong" })?;
            let handle = server.start(module);

            Ok((Self { handle }, format!("ws://{addr}")))
        }

        async fn stop(self) -> anyhow::Result<()> {
            self.handle.stop()?;
            self.handle.stopped().await;
            Ok(())
        }
    }
}
