// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Selects the network this build targets from `DUB_NETWORK`. Two values,
//! because two People runtimes: `testnet` covers previewnet and paseo-next-v2,
//! which differ only in their endpoints.

/// Every accepted network, and whether its runtime has `Game` / `ProofOfInk`.
const NETWORKS: &[(&str, bool)] = &[("testnet", true), ("polkadot", false)];

const DEFAULT_NETWORK: &str = "testnet";

fn main() {
    println!("cargo::rerun-if-env-changed=DUB_NETWORK");
    println!("cargo::rustc-check-cfg=cfg(dub_network, values(\"testnet\", \"polkadot\"))");
    println!("cargo::rustc-check-cfg=cfg(invite_tickets)");

    let network = std::env::var("DUB_NETWORK")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_NETWORK.to_string());
    let Some(&(_, invite_tickets)) = NETWORKS.iter().find(|(name, _)| *name == network) else {
        let accepted: Vec<&str> = NETWORKS.iter().map(|(name, _)| *name).collect();
        panic!(
            "DUB_NETWORK={network:?} is not a known network; expected one of {}",
            accepted.join(", ")
        );
    };

    println!("cargo::rustc-cfg=dub_network=\"{network}\"");
    println!("cargo::rustc-env=DUB_NETWORK={network}");
    if invite_tickets {
        println!("cargo::rustc-cfg=invite_tickets");
    }
}
