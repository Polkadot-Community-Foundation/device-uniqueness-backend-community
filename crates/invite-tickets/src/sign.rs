// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use schnorrkel::{ExpansionMode, MiniSecretKey};

/// The substrate signing context every sr25519 chain signature uses.
const SIGNING_CTX: &[u8] = b"substrate";

/// A ticket's sr25519 keypair, reconstructed from its stored secret.
pub struct TicketKeypair {
    keypair: schnorrkel::Keypair,
}

/// A stored ticket secret that could not be turned into a keypair — a data
/// defect (the pool only ever writes valid secrets), surfaced as a 500.
#[derive(Debug, thiserror::Error)]
pub enum TicketKeyError {
    #[error("stored ticket secret has invalid length {0} (expected 32 or 64)")]
    InvalidLength(usize),
    #[error("stored ticket secret is not a valid sr25519 key: {0}")]
    InvalidKey(String),
}

impl TicketKeypair {
    /// Rebuild a keypair from the stored secret: a 32-byte mini-secret seed
    /// (what the pool maintainer generates) or a 64-byte expanded secret (a
    /// row backfilled from the legacy table, which stored the polkadot.js
    /// expanded form).
    pub fn from_stored_secret(secret: &[u8]) -> Result<Self, TicketKeyError> {
        let keypair = match secret.len() {
            32 => MiniSecretKey::from_bytes(secret)
                .map_err(|e| TicketKeyError::InvalidKey(e.to_string()))?
                .expand_to_keypair(ExpansionMode::Ed25519),
            64 => {
                let secret = schnorrkel::SecretKey::from_ed25519_bytes(secret)
                    .map_err(|e| TicketKeyError::InvalidKey(e.to_string()))?;
                schnorrkel::Keypair {
                    public: secret.to_public(),
                    secret,
                }
            }
            n => return Err(TicketKeyError::InvalidLength(n)),
        };
        Ok(Self { keypair })
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.keypair.public.to_bytes()
    }

    /// Sign `payload` under the substrate signing context.
    pub fn sign(&self, payload: &[u8]) -> [u8; 64] {
        let context = schnorrkel::signing_context(SIGNING_CTX);
        self.keypair.sign(context.bytes(payload)).to_bytes()
    }
}

/// Generate a fresh random ticket secret (32-byte mini-secret seed).
pub fn generate_seed() -> [u8; 32] {
    use rand::RngCore as _;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

/// Verify a substrate-context sr25519 signature (test/diagnostic helper —
/// the claim path only ever signs).
pub fn verify(public_key: &[u8; 32], payload: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(public) = schnorrkel::PublicKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = schnorrkel::Signature::from_bytes(signature) else {
        return false;
    };
    public
        .verify_simple(SIGNING_CTX, payload, &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;

    #[test]
    fn seed_roundtrip_signs_verifiably() {
        let seed = generate_seed();
        let keypair = TicketKeypair::from_stored_secret(&seed).expect("valid seed");
        let payload = [7u8; 32];
        let signature = keypair.sign(&payload);
        assert!(verify(&keypair.public_bytes(), &payload, &signature));
        assert!(!verify(&keypair.public_bytes(), &[8u8; 32], &signature));
    }

    #[test]
    fn seed_path_matches_subxt_signer_keys_and_contexts() {
        let seed = [9u8; 32];
        let ours = TicketKeypair::from_stored_secret(&seed).expect("valid seed");
        let theirs = subxt_signer::sr25519::Keypair::from_secret_key(seed).expect("valid seed");
        assert_eq!(ours.public_bytes(), theirs.public_key().0);

        let payload = [3u8; 32];
        assert!(verify(
            &theirs.public_key().0,
            &payload,
            &ours.sign(&payload)
        ));
        assert!(verify(
            &ours.public_bytes(),
            &payload,
            &theirs.sign(&payload).0
        ));
    }

    #[test]
    fn expanded_secret_signs_under_the_same_public_key() {
        let seed = [5u8; 32];
        let from_seed = TicketKeypair::from_stored_secret(&seed).expect("valid seed");
        let expanded = MiniSecretKey::from_bytes(&seed)
            .expect("valid seed")
            .expand(ExpansionMode::Ed25519)
            .to_ed25519_bytes();
        let from_expanded =
            TicketKeypair::from_stored_secret(&expanded).expect("valid expanded secret");
        assert_eq!(from_seed.public_bytes(), from_expanded.public_bytes());

        let payload = [1u8; 32];
        assert!(verify(
            &from_seed.public_bytes(),
            &payload,
            &from_expanded.sign(&payload)
        ));
    }

    #[test]
    fn rejects_invalid_secret_lengths() {
        assert!(matches!(
            TicketKeypair::from_stored_secret(&[0u8; 16]),
            Err(TicketKeyError::InvalidLength(16))
        ));
        assert!(matches!(
            TicketKeypair::from_stored_secret(&[]),
            Err(TicketKeyError::InvalidLength(0))
        ));
    }

    #[test]
    fn signs_the_decoded_account_id_not_the_address_string() {
        let who = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";
        let account = subxt::utils::AccountId32::from_str(who).expect("valid SS58");
        let seed = generate_seed();
        let keypair = TicketKeypair::from_stored_secret(&seed).expect("valid seed");
        let signature = keypair.sign(&account.0);
        assert!(verify(&keypair.public_bytes(), &account.0, &signature));
        let wrong = keypair.sign(who.as_bytes());
        assert!(!verify(&keypair.public_bytes(), &account.0, &wrong));
    }
}
