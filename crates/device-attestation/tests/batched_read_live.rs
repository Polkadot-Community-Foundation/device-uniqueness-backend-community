// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeSet;
use std::future::Future;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use chain_types::{people, PeopleConfig};
use device_attestation::chain::PeopleChain;

const DISCRIMINATORS: u8 = 100;

const STEP_TIMEOUT: Duration = Duration::from_secs(90);

fn rpc_url() -> String {
    std::env::var("PEOPLE_RPC_URL")
        .unwrap_or_else(|_| "wss://previewnet.substrate.dev/people".to_string())
}

async fn step<T>(what: &str, future: impl Future<Output = T>) -> T {
    match tokio::time::timeout(STEP_TIMEOUT, future).await {
        Ok(value) => value,
        Err(_) => panic!(
            "{what} exceeded {}s against {} — endpoint unreachable or overloaded",
            STEP_TIMEOUT.as_secs(),
            rpc_url()
        ),
    }
}

type PeopleBlock = subxt::client::ClientAtBlock<
    PeopleConfig,
    subxt::client::OnlineClientAtBlockImpl<PeopleConfig>,
>;

fn owner_key(
    username: impl AsRef<[u8]>,
) -> people::runtime_types::bounded_collections::bounded_vec::BoundedVec<u8> {
    people::runtime_types::bounded_collections::bounded_vec::BoundedVec(username.as_ref().to_vec())
}

async fn taken_discriminators_per_key(
    at: &PeopleBlock,
    base: &str,
) -> anyhow::Result<BTreeSet<u8>> {
    let storage = at.storage();
    let storage = &storage;

    let lookups = (0..DISCRIMINATORS).map(move |discriminator| async move {
        let username = format!("{base}.{discriminator:02}");
        let owned = storage
            .try_fetch(
                people::storage().resources().username_owner_of(),
                (owner_key(username),),
            )
            .await?
            .is_some();
        anyhow::Ok((discriminator, owned))
    });

    Ok(futures::future::try_join_all(lookups)
        .await?
        .into_iter()
        .filter_map(|(discriminator, owned)| owned.then_some(discriminator))
        .collect())
}

async fn some_registered_lite_username(at: &PeopleBlock) -> anyhow::Result<Option<(String, u8)>> {
    let entry = at
        .storage()
        .entry(people::storage().resources().username_owner_of())?;
    let mut entries = entry.iter(()).await?;

    while let Some(item) = entries.next().await {
        let (username,) = item?.key()?.decode()?;
        let username = String::from_utf8(username.0)?;
        let Some((base, suffix)) = username.rsplit_once('.') else {
            continue;
        };
        if suffix.len() != 2 || !suffix.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if base.is_empty() {
            continue;
        }
        return Ok(Some((base.to_string(), suffix.parse()?)));
    }
    Ok(None)
}

#[tokio::test]
#[ignore = "requires a live People Chain RPC; set PEOPLE_RPC_URL and run with --ignored"]
async fn batched_read_matches_per_key_read() {
    let chain = step("connect", PeopleChain::connect(&rpc_url()))
        .await
        .expect("connect");
    let at = step("selecting a block", chain.online().at_current_block())
        .await
        .expect("current block");

    let (owned_base, owned_discriminator) =
        step("scanning usernames", some_registered_lite_username(&at))
            .await
            .expect("iterate usernames")
            .expect(
                "no registered {base}.{NN} username on this chain: the comparison would only \
                 prove two empty sets agree — point PEOPLE_RPC_URL at a chain with registrations",
            );
    let free_base = format!("dubprobe{}", std::process::id());

    for base in [owned_base.clone(), free_base.clone()] {
        let per_key = step(
            "per-key read (100 requests)",
            taken_discriminators_per_key(&at, &base),
        )
        .await
        .expect("per-key read");
        let batched = step(
            "batched read (1 request)",
            chain.taken_discriminators_at(&base, &at),
        )
        .await
        .expect("batched read");

        assert_eq!(
            per_key, batched,
            "batched read disagreed with the per-key read for base {base}"
        );

        if base == owned_base {
            assert!(
                batched.contains(&owned_discriminator),
                "expected {owned_base}.{owned_discriminator:02} to read as taken; \
                 got {batched:?} — the comparison proved nothing"
            );
        } else {
            assert!(
                batched.is_empty(),
                "unregistered probe base {free_base} read as taken: {batched:?}"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires a live People Chain RPC; set PEOPLE_RPC_URL and run with --ignored"]
async fn base_state_reads_the_reservation_leg_from_the_same_batch() {
    let chain = step("connect", PeopleChain::connect(&rpc_url()))
        .await
        .expect("connect");
    let at = step("selecting a block", chain.online().at_current_block())
        .await
        .expect("current block");

    let (owned_base, _) = step("scanning usernames", some_registered_lite_username(&at))
        .await
        .expect("iterate usernames")
        .expect(
            "no registered {base}.{NN} username on this chain — point PEOPLE_RPC_URL at a chain \
             with registrations",
        );
    let free_base = format!("dubprobe{}", std::process::id());

    for base in [owned_base.clone(), free_base.clone()] {
        let state = step("batched base-state read", chain.base_state_at(&base, &at))
            .await
            .expect("base state");

        let per_key = step(
            "per-key read (100 requests)",
            taken_discriminators_per_key(&at, &base),
        )
        .await
        .expect("per-key read");
        assert_eq!(
            per_key, state.taken,
            "appending the reservation keys shifted the discriminator answers for {base}"
        );

        let full_name_owned = at
            .storage()
            .try_fetch(
                people::storage().resources().username_owner_of(),
                (owner_key(&base),),
            )
            .await
            .expect("per-key bare-name read")
            .is_some();
        assert_eq!(
            state.full_name_owned, full_name_owned,
            "batched bare-name answer disagreed with the per-key read for {base}"
        );

        let queue_len = at
            .storage()
            .try_fetch(
                people::storage().resources().username_reservation_queue(),
                (owner_key(&base),),
            )
            .await
            .expect("per-key queue read")
            .map(|value| value.decode().expect("decode queue").0.len() as u32)
            .unwrap_or(0);
        assert_eq!(
            state.queue_len, queue_len,
            "batched queue length disagreed with the per-key read for {base}"
        );

        assert!(
            state.queue_capacity > 0,
            "Resources::MaxReservationQueueLength read as zero"
        );

        if base == free_base {
            assert!(
                !state.full_name_owned && state.queue_len == 0,
                "unregistered probe base {free_base} has a reservation leg: {state:?}"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires a live People Chain RPC; set PEOPLE_RPC_URL and run with --ignored"]
async fn batched_owner_read_matches_per_name_read() {
    let chain = step("connect", PeopleChain::connect(&rpc_url()))
        .await
        .expect("connect");
    let at = step("selecting a block", chain.online().at_current_block())
        .await
        .expect("current block");

    let (owned_base, owned_discriminator) =
        step("scanning usernames", some_registered_lite_username(&at))
            .await
            .expect("iterate usernames")
            .expect(
                "no registered {base}.{NN} username on this chain: the comparison would only \
                 prove two empty maps agree — point PEOPLE_RPC_URL at a chain with registrations",
            );
    let owned = format!("{owned_base}.{owned_discriminator:02}");
    let free = format!("dubprobe{}.42", std::process::id());
    let names = [owned.as_str(), free.as_str()];

    let batched = step(
        "batched owner read (1 request)",
        chain.username_owners(&names),
    )
    .await
    .expect("batched owner read");

    for name in names {
        let per_name = step("per-name owner read", chain.username_owner(name))
            .await
            .expect("per-name owner read");
        assert_eq!(
            batched.get(name).copied(),
            per_name,
            "batched owner read disagreed with the per-name read for {name}"
        );
    }
    assert!(
        batched.contains_key(&owned),
        "expected {owned} to read as owned; the comparison proved nothing"
    );
    assert!(
        !batched.contains_key(&free),
        "unregistered probe name {free} read as owned"
    );

    // An empty set costs no request at all, and is not an error.
    assert!(chain
        .username_owners(&[])
        .await
        .expect("empty read")
        .is_empty());
}

/// `min / p50 / p95 / max` of a set of per-request durations, in ms.
fn percentiles(mut samples: Vec<u128>) -> (u128, u128, u128, u128) {
    samples.sort_unstable();
    let pick = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize];
    (
        samples[0],
        pick(0.50),
        pick(0.95),
        samples[samples.len() - 1],
    )
}

#[tokio::test]
#[ignore = "diagnostic probe; set PEOPLE_RPC_URL + BATCH_PROBE_CONCURRENCY and run with --ignored"]
async fn concurrent_load_probe_prints_latency() {
    let Some(raw) = std::env::var("BATCH_PROBE_CONCURRENCY").ok() else {
        eprintln!("BATCH_PROBE_CONCURRENCY unset: skipping the latency probe");
        return;
    };
    let concurrency: NonZeroUsize = raw
        .parse()
        .expect("BATCH_PROBE_CONCURRENCY must be a positive integer");
    let concurrency = concurrency.get();

    let chain = step("connect", PeopleChain::connect(&rpc_url()))
        .await
        .expect("connect");
    let online = chain.online().clone();

    let bases: Vec<String> = (0..concurrency)
        .map(|i| format!("dubload{}x{i}", std::process::id()))
        .collect();

    let at = step("selecting a block", online.at_current_block())
        .await
        .expect("current block");
    let _ = taken_discriminators_per_key(&at, &bases[0]).await;
    let _ = chain.taken_discriminators(&bases[0]).await;

    for round in 1..=2 {
        let wall = Instant::now();
        let per_key: Vec<u128> = futures::future::join_all(bases.iter().map(|base| async {
            let started = Instant::now();
            let at = online.at_current_block().await.expect("current block");
            taken_discriminators_per_key(&at, base)
                .await
                .expect("per-key read");
            started.elapsed().as_millis()
        }))
        .await;
        let per_key_wall = wall.elapsed().as_millis();

        let wall = Instant::now();
        let batched: Vec<u128> = futures::future::join_all(bases.iter().map(|base| {
            let chain = chain.clone();
            async move {
                let started = Instant::now();
                chain
                    .taken_discriminators(base)
                    .await
                    .expect("batched read");
                started.elapsed().as_millis()
            }
        }))
        .await;
        let batched_wall = wall.elapsed().as_millis();

        let (a_min, a_p50, a_p95, a_max) = percentiles(per_key);
        let (b_min, b_p50, b_p95, b_max) = percentiles(batched);
        eprintln!(
            "round {round} @ concurrency {concurrency}\n  \
             100 requests each ({} total): min {a_min} p50 {a_p50} p95 {a_p95} max {a_max} ms | wall {per_key_wall} ms\n  \
             1 request each ({concurrency} total):  min {b_min} p50 {b_p50} p95 {b_p95} max {b_max} ms | wall {batched_wall} ms",
            concurrency * 100
        );
    }
}
