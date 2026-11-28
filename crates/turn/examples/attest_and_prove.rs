// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::{bail, Context as _};
use chain_types::people;
use chain_types::people::runtime_types::indiv_support::traits::reality::RingExponent;
use chain_types::PeopleExtrinsicParamsBuilder;
use rand::RngCore as _;
use subxt::ext::codec::Decode as _;
use verifiable::ring::bandersnatch::BandersnatchVrfVerifiable;
use verifiable::ring::RingDomainSize;
use verifiable::GenerateVerifiable as _;

type Vrf = BandersnatchVrfVerifiable;
type Members = <Vrf as verifiable::GenerateVerifiable>::Members;

/// Collection id for `pop:polkadot.network/people-lite` (32 bytes, ASCII).
const PEOPLE_LITE: [u8; 32] = *b"pop:polkadot.network/people-lite";
/// The attestation message prefix from `pallets/people-lite` (30 bytes).
const ATTEST_PREFIX: &[u8] = b"pop:people-lite:register using";
/// Test message for standalone demo runs.
const MESSAGE: &[u8] = b"dub-turn-experiment/message";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let rpc = arg(&args, "--rpc").context("missing --rpc <url>")?;
    let state_path = arg(&args, "--state").context("missing --state <file>")?;

    match arg(&args, "--phase").as_deref() {
        Some("attest") => attest(&rpc, &state_path).await,
        Some("prove") => prove(&rpc, &state_path).await,
        other => bail!("--phase must be attest or prove (got {other:?})"),
    }
}

/// One generated candidate: an sr25519 account plus Bandersnatch entropy.
#[derive(serde::Serialize, serde::Deserialize)]
struct Candidate {
    account_seed_hex: String,
    entropy_hex: String,
    ring_key_hex: String,
    account_hex: String,
}

fn generate_candidate() -> anyhow::Result<Candidate> {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);

    let keypair = subxt_signer::sr25519::Keypair::from_secret_key(seed)
        .map_err(|e| anyhow::anyhow!("deriving candidate keypair: {e}"))?;
    let secret = Vrf::new_secret(entropy);
    let member = Vrf::member_from_secret(&secret);
    Ok(Candidate {
        account_seed_hex: hex::encode(seed),
        entropy_hex: hex::encode(entropy),
        ring_key_hex: hex::encode(member),
        account_hex: hex::encode(keypair.public_key().0),
    })
}

async fn attest(rpc: &str, state_path: &str) -> anyhow::Result<()> {
    let attester = chain_client::WriterSigner::from_secret(&secrecy::SecretString::from(
        std::env::var("ATTESTER_SURI").context("missing ATTESTER_SURI env var")?,
    ))?;
    let attester_account = subxt::utils::AccountId32(attester.public_bytes());
    println!("attester: {attester_account}");

    let api = chain_client::connect(rpc).await?;
    let at = api.at_current_block().await?;
    let nonce_info = at
        .storage()
        .try_fetch(people::storage().system().account(), (attester_account,))
        .await?
        .context("attester account not found on chain")?
        .decode()?;
    let nonce = u64::from(nonce_info.nonce);
    println!("attester nonce: {nonce}");

    let candidates: Vec<Candidate> = (0..3)
        .map(|_| generate_candidate())
        .collect::<Result<_, _>>()?;
    std::fs::write(state_path, serde_json::to_vec_pretty(&candidates)?)?;
    println!("candidate secrets saved to {state_path}");

    for (nonce, (i, c)) in (nonce..).zip(candidates.iter().enumerate()) {
        let seed: [u8; 32] = hex::decode(&c.account_seed_hex)?.try_into().unwrap();
        let entropy: [u8; 32] = hex::decode(&c.entropy_hex)?.try_into().unwrap();
        let keypair = subxt_signer::sr25519::Keypair::from_secret_key(seed)
            .map_err(|e| anyhow::anyhow!("deriving candidate keypair: {e}"))?;
        let candidate = subxt::utils::AccountId32(keypair.public_key().0);
        let secret = Vrf::new_secret(entropy);
        let ring_key = Vrf::member_from_secret(&secret);

        // msg = prefix ++ SCALE(candidate) ++ SCALE(ring_key), both raw 32B.
        let mut msg = ATTEST_PREFIX.to_vec();
        msg.extend_from_slice(&candidate.0);
        msg.extend_from_slice(&ring_key);

        let candidate_sig = keypair.sign(&msg).0;
        let ownership = Vrf::sign(&secret, &msg)
            .map_err(|e| anyhow::anyhow!("bandersnatch ownership signature: {e:?}"))?;

        let call = people::tx().people_lite().attest(
            candidate,
            people::runtime_types::sp_runtime::MultiSignature::Sr25519(candidate_sig),
            ring_key,
            ownership,
            None,
        );
        let params = PeopleExtrinsicParamsBuilder::new().nonce(nonce).build();
        let signed = api
            .tx()
            .await?
            .create_signed(&call, &attester, params)
            .await?;
        println!(
            "candidate {i} ({}): submitting attest (nonce {nonce}, tx {:?})",
            candidate,
            signed.hash()
        );
        let mut progress = signed.submit_and_watch().await?;
        while let Some(status) = progress.next().await {
            match status? {
                subxt::tx::TransactionStatus::InBestBlock(tx) => {
                    tx.wait_for_success().await?;
                    println!("candidate {i}: attest in block");
                    break;
                }
                subxt::tx::TransactionStatus::Error { message }
                | subxt::tx::TransactionStatus::Invalid { message }
                | subxt::tx::TransactionStatus::Dropped { message } => {
                    bail!("attest {i} failed: {message}")
                }
                _ => {}
            }
        }
    }
    println!("all attests submitted; wait for onboarding + re-root, then run --phase prove");
    Ok(())
}

async fn prove(rpc: &str, state_path: &str) -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    // Optional overrides so this can act as the client side of the Phase 1
    // demo: prove over the exact (context, message) a turn-api deployment
    // expects instead of the default `peopl.dot` context.
    let context: Vec<u8> = match arg(&args, "--context") {
        Some(hex) => hex::decode(hex.trim_start_matches("0x"))?,
        None => turn::proof::context::product_context("peopl.dot", 0).to_vec(),
    };
    let message: Vec<u8> = match arg(&args, "--message") {
        Some(hex) => hex::decode(hex.trim_start_matches("0x"))?,
        None => MESSAGE.to_vec(),
    };
    let candidates: Vec<Candidate> = serde_json::from_slice(&std::fs::read(state_path)?)?;
    let c = &candidates[0];
    let entropy: [u8; 32] = hex::decode(&c.entropy_hex)?.try_into().unwrap();
    let secret = Vrf::new_secret(entropy);
    let my_key = Vrf::member_from_secret(&secret);

    let api = chain_client::connect(rpc).await?;
    let at = api.at_current_block().await?;

    let info = at
        .storage()
        .try_fetch(people::storage().members().collections(), (PEOPLE_LITE,))
        .await?
        .context("people-lite collection not found")?
        .decode()?;
    let domain = match info.ring_size {
        RingExponent::R2e9 => RingDomainSize::Domain11,
        RingExponent::R2e10 => RingDomainSize::Domain12,
        RingExponent::R2e14 => RingDomainSize::Domain16,
    };

    // Find the ring + included keys containing our member key.
    let current_ring = at
        .storage()
        .try_fetch(
            subxt::dynamic::storage::<([u8; 32],), subxt::ext::scale_value::Value>(
                "Members",
                "CurrentRingIndex",
            ),
            (PEOPLE_LITE,),
        )
        .await?
        .map(|v| u32::decode(&mut v.bytes()))
        .transpose()?
        .unwrap_or(0);

    for ring_index in (0..=current_ring).rev() {
        let status = at
            .storage()
            .try_fetch(
                subxt::dynamic::storage::<([u8; 32], u32), subxt::ext::scale_value::Value>(
                    "Members",
                    "RingKeysStatus",
                ),
                (PEOPLE_LITE, ring_index),
            )
            .await?;
        let Some(status) = status else { continue };
        let mut cursor = status.bytes();
        let total = u32::decode(&mut cursor)?;
        let included = u32::decode(&mut cursor)?;

        let mut keys: Vec<[u8; 32]> = Vec::new();
        for page in 0u32.. {
            if keys.len() >= total as usize {
                break;
            }
            let Some(value) = at
                .storage()
                .try_fetch(
                    subxt::dynamic::storage::<([u8; 32], u32, u32), subxt::ext::scale_value::Value>(
                        "Members", "RingKeys",
                    ),
                    (PEOPLE_LITE, ring_index, page),
                )
                .await?
            else {
                break;
            };
            let page_keys = Vec::<[u8; 32]>::decode(&mut value.bytes())?;
            if page_keys.is_empty() {
                break;
            }
            keys.extend(page_keys);
        }

        let position = keys.iter().position(|k| *k == my_key);
        println!("ring {ring_index}: {total} keys, {included} included, our key at {position:?}");
        let Some(position) = position else { continue };
        // --prefix-count N builds the proof against the first N keys — the
        // commitment of an OLDER revision (keys are append-only). Used to
        // exercise the server's accepted-revision window; skips the local
        // current-root validation, which would rightly fail.
        let prefix: Option<usize> = arg(&args, "--prefix-count")
            .map(|raw| raw.parse())
            .transpose()?;
        let cut = prefix.unwrap_or(included as usize);
        if position >= cut {
            bail!(
                "our key (position {position}) is outside the requested prefix/included \
                 count {cut} — wait for the OCW to re-root and re-run --phase prove"
            );
        }
        keys.truncate(cut);

        // Create the proof with our secret against the real member list.
        let opening = Vrf::open(domain, &my_key, keys.iter().copied())
            .map_err(|e| anyhow::anyhow!("open failed: {e:?}"))?;
        let (proof, alias) = Vrf::create(opening, &secret, &context, &message)
            .map_err(|e| anyhow::anyhow!("create failed: {e:?}"))?;
        println!("proof created; prover-side alias: 0x{}", hex::encode(alias));

        if prefix.is_some() {
            let proof_path = format!("{state_path}.proof.bin");
            std::fs::write(&proof_path, &proof)?;
            println!("prefix proof written to {proof_path} (skipping current-root validation)");
            return Ok(());
        }

        // Verify it against the actual on-chain root.
        let root_value = at
            .storage()
            .try_fetch(
                subxt::dynamic::storage::<([u8; 32], u32), subxt::ext::scale_value::Value>(
                    "Members", "Root",
                ),
                (PEOPLE_LITE, ring_index),
            )
            .await?
            .context("ring root not found")?;
        let mut cursor = root_value.bytes();
        let onchain = Members::decode(&mut cursor)
            .map_err(|e| anyhow::anyhow!("root is not the pinned encoding: {e}"))?;
        let revision = u32::decode(&mut cursor)?;

        let verified = Vrf::validate(domain, &proof, &onchain, &context, &message)
            .map_err(|e| anyhow::anyhow!("proof did NOT verify against on-chain root: {e:?}"))?;
        if verified != alias {
            bail!("verifier alias differs from prover alias");
        }
        println!(
            "VERIFIED against on-chain Members::Root (ring {ring_index}, revision {revision}); \
             alias 0x{}",
            hex::encode(verified)
        );

        // Persist the proof in the same raw form a host emits, so
        // `verify_proof` and the endpoint both see the real wire bytes.
        let proof_path = format!("{state_path}.proof.bin");
        std::fs::write(&proof_path, &proof)?;
        println!(
            "proof written to {proof_path}; verify independently with:\n\
             verify_proof --rpc {rpc} --collection 0x{} --ring-index {ring_index} \
             --domain {} --proof-file {proof_path} --context 0x{} --message 0x{}",
            hex::encode(PEOPLE_LITE),
            match domain {
                RingDomainSize::Domain11 => 11,
                RingDomainSize::Domain12 => 12,
                RingDomainSize::Domain16 => 16,
            },
            hex::encode(&context),
            hex::encode(&message),
        );
        return Ok(());
    }
    bail!("our ring key was not found in any ring — has onboarding happened yet?");
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
