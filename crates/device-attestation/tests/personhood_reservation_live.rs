// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use device_attestation::chain::asset_hub::AssetHub;

#[tokio::test]
#[ignore = "requires a reachable Asset Hub RPC (ASSET_HUB_RPC_URL, or the Paseo default); \
            run with --ignored"]
async fn an_unregistered_personhood_name_reads_as_free_on_the_dotns_contracts() {
    let url = std::env::var("ASSET_HUB_RPC_URL")
        .unwrap_or_else(|_| "wss://paseo-asset-hub-next-rpc.polkadot.io".to_string());
    let asset_hub = AssetHub::connect_for_reads(&url)
        .await
        .expect("live Asset Hub RPC");

    let state = asset_hub
        .personhood_reservation("qzxwvkjqzxwvkjqzxwvk")
        .await
        .expect("the dotNS contracts resolve and answer");

    assert!(
        !state.personhood_name_unavailable,
        "nobody registered or was granted this name: {state:?}"
    );
    assert_eq!(state.queue_len, 0, "nobody queued for this name: {state:?}");
    assert!(
        state.queue_capacity > 0,
        "MAX_RESERVATION_QUEUE is read: {state:?}"
    );
}
