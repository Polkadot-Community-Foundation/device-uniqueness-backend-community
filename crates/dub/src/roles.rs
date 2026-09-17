// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub mod all_in_one;
pub mod device_attestation_api;
pub mod device_attestation_chain_writer;
#[cfg(invite_tickets)]
pub mod invite_tickets_api;
#[cfg(invite_tickets)]
pub mod invite_tickets_pool;
pub mod notify_relay;
pub mod registration_queue;
pub mod turn_api;
pub mod username_indexer;

/// Every role this binary accepts, in deployment order (the HTTP services,
/// then the single-instance workers).
///
/// This slice is the authority: `--list-roles` prints it, and the deployment
/// gate compares the compose services and chart workloads against that output
/// rather than against a second hand-written list.
///
/// The invite-tickets roles are compiled in only where the People runtime has
/// `Game` and `ProofOfInk`: `DUB_NETWORK=testnet`, but not `polkadot`.
pub const ROLES: &[&str] = &[
    "device-attestation-api",
    "username-indexer",
    #[cfg(invite_tickets)]
    "invite-tickets-api",
    "turn-api",
    "notify-relay",
    "device-attestation-chain-writer",
    "registration-queue",
    #[cfg(invite_tickets)]
    "invite-tickets-pool",
];

/// The invite-tickets roles, whether or not this build includes them. The edge
/// route table is shared by every network, so it names them even where they are
/// not deployed.
pub const INVITE_TICKETS_ROLES: &[&str] = &["invite-tickets-api", "invite-tickets-pool"];

/// The roles that make up the **small** topology's HTTP tier: one merged
/// process instead of the per-service ones.
///
/// Deliberately absent from [`ROLES`] — a deployment renders one topology or
/// the other, and `scripts/verify_role_split.sh` enforces that. Selecting it
/// also needs an explicit acknowledgement: it collapses the standard topology's
/// secret compartmentalisation (see `docs/architecture.md`).
pub const MERGED_ROLES: &[&str] = &["all-in-one"];

/// The single-instance workers, which belong to **both** topologies: each owns
/// a Postgres lease and a nonce lane, so they are never merged into anything.
pub const WORKER_ROLES: &[&str] = &[
    "device-attestation-chain-writer",
    "registration-queue",
    #[cfg(invite_tickets)]
    "invite-tickets-pool",
];

/// Every role `--role` accepts, in either topology.
pub fn accepts(role: &str) -> bool {
    ROLES.contains(&role) || MERGED_ROLES.contains(&role)
}

/// Become `role`. The caller has already checked it with [`accepts`].
pub async fn run(role: &str) -> anyhow::Result<()> {
    match role {
        "all-in-one" => all_in_one::run().await,
        "device-attestation-api" => device_attestation_api::run().await,
        "username-indexer" => username_indexer::run().await,
        #[cfg(invite_tickets)]
        "invite-tickets-api" => invite_tickets_api::run().await,
        "turn-api" => turn_api::run().await,
        "notify-relay" => notify_relay::run().await,
        "device-attestation-chain-writer" => device_attestation_chain_writer::run().await,
        "registration-queue" => registration_queue::run().await,
        #[cfg(invite_tickets)]
        "invite-tickets-pool" => invite_tickets_pool::run().await,
        // Unreachable via `main`, which validates against ROLES first. Kept
        // exhaustive rather than `unreachable!` so adding a name to ROLES
        // without a dispatch arm is a compile error, not a runtime one.
        other => anyhow::bail!("role {other} is listed but not dispatched"),
    }
}

#[cfg(test)]
mod tests {
    use super::ROLES;

    #[test]
    fn roles_are_unique() {
        let mut sorted = ROLES.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "duplicate role in ROLES");
    }

    #[test]
    fn deployable_roles_follow_the_network() {
        let expected = if cfg!(invite_tickets) { 8 } else { 6 };
        assert_eq!(ROLES.len(), expected, "ROLES: {ROLES:?}");
        for role in super::INVITE_TICKETS_ROLES {
            assert_eq!(ROLES.contains(role), cfg!(invite_tickets), "{role}");
        }
    }

    #[test]
    fn the_topologies_are_disjoint() {
        assert!(super::accepts("all-in-one"));
        for role in super::MERGED_ROLES {
            assert!(!ROLES.contains(role), "{role} is in both topologies");
        }
    }

    #[test]
    fn the_workers_are_deployable_in_both_topologies() {
        let expected = if cfg!(invite_tickets) { 3 } else { 2 };
        assert_eq!(super::WORKER_ROLES.len(), expected);
        for role in super::WORKER_ROLES {
            assert!(ROLES.contains(role), "{role} is not a deployable role");
        }
        for role in super::MERGED_ROLES {
            assert!(!super::WORKER_ROLES.contains(role));
        }
    }
}
