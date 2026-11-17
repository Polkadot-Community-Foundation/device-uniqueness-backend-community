// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

// A role serving `/turn/issue-with-proof` returns 503 for every proof until its
// root cache contains the chain's rings, so the refresh is what makes the route
// usable at all.

use std::time::{Duration, Instant};

use turn::config::{Config, ProofConfig, ProviderConfig, PROOF_MAX_ROOT_AGE};
use turn::proof::roots::PersonhoodCollection;
use turn::AppState;

const LOAD_TIMEOUT: Duration = Duration::from_secs(90);

fn rpc_url() -> String {
    std::env::var("PEOPLE_RPC_URL")
        .unwrap_or_else(|_| "wss://paseo-people-next-system-rpc.polkadot.io".to_string())
}

async fn chain_genesis(rpc_url: &str) -> [u8; 32] {
    let client = chain_client::connect(rpc_url)
        .await
        .expect("People Chain unreachable");
    let block = client.at_current_block().await.expect("no current block");
    block.genesis_hash().expect("no genesis hash").0
}

#[tokio::test]
#[ignore = "requires a People Chain RPC: PEOPLE_RPC_URL, or the public Paseo default"]
async fn people_lite_root_refresh() {
    // A refresher reports why it cannot load roots only through tracing.
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let rpc_url = rpc_url();
    let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let state = AppState::start(Config {
        bind_addr: "127.0.0.1:0".parse().expect("invalid address"),
        ttl_secs: 1800,
        provider: ProviderConfig::Coturn {
            secret: b"relay-shared-secret".to_vec(),
            algorithm: turn::credentials::Algorithm::Sha1,
            realm: "example.org".to_string(),
            ice_servers: vec!["turn:turn.example.org:3478?transport=udp".to_string()],
        },
        jwt_verifier: jwt_verify::Verifier::from_public_key(None, key.verifying_key().as_bytes()),
        rate_limit: 30,
        rate_window: Duration::from_secs(60),
        proof: Some(ProofConfig {
            genesis: chain_genesis(&rpc_url).await,
            rpc_url,
            contexts: Default::default(),
            concurrency: 1,
        }),
    });
    let roots = state
        .proof
        .as_ref()
        .expect("proof state missing with proof configured")
        .roots
        .get(PersonhoodCollection::PeopleLite);

    let deadline = Instant::now() + LOAD_TIMEOUT;
    while roots.snapshot(PROOF_MAX_ROOT_AGE).is_none() {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
