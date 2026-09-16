// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

// Only on networks whose People runtime has Game and ProofOfInk
#[cfg(not(invite_tickets))]
fn main() {
    eprintln!("seed_pool: this build's DUB_NETWORK has no invite tickets");
    std::process::exit(2);
}

#[cfg(invite_tickets)]
use std::str::FromStr as _;

#[cfg(invite_tickets)]
use invite_tickets::sign::{self, TicketKeypair};
#[cfg(invite_tickets)]
use invite_tickets::tickets::{self, Dim, Network};

/// Dev placeholder inviter (Alice), stamped into seeded rows.
#[cfg(invite_tickets)]
const DEV_INVITER: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

#[cfg(invite_tickets)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: seed_pool <Game|ProofOfInk> <westend2|paseo|polkadot> <count>";
    let dim = Dim::from_str(&args.next().ok_or_else(|| anyhow::anyhow!(usage))?)
        .map_err(|()| anyhow::anyhow!(usage))?;
    let network = Network::from_str(&args.next().ok_or_else(|| anyhow::anyhow!(usage))?)
        .map_err(|()| anyhow::anyhow!(usage))?;
    let count: u32 = args
        .next()
        .ok_or_else(|| anyhow::anyhow!(usage))?
        .parse()
        .map_err(|_| anyhow::anyhow!(usage))?;

    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?;
    let pool = invite_tickets::db::connect(&database_url).await?;

    for _ in 0..count {
        let seed = sign::generate_seed();
        let keypair = TicketKeypair::from_stored_secret(&seed)?;
        tickets::insert_available(
            &pool,
            &keypair.public_bytes(),
            &seed,
            dim,
            network,
            DEV_INVITER,
        )
        .await?;
    }

    let available = tickets::count_available(&pool, dim, network).await?;
    println!(
        "seeded {count} unregistered dev ticket(s); pool {}/{} now has {available} available",
        dim.as_str(),
        network.as_str(),
    );
    Ok(())
}
