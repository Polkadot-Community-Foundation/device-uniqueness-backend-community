// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::future::Future;
use std::str::FromStr as _;

use anyhow::Context as _;
use chain_types::{AssetHubConfig, PeopleConfig};
use secrecy::{ExposeSecret as _, SecretString};
use subxt::utils::{AccountId32, MultiSignature};

use crate::kms::{is_key_version_name, KmsSigner};

/// Text every [`SignError`] starts with, so a caller that only sees an error's
/// message (a row's recorded failure reason) can tell a signing failure from
/// a verdict on the transaction.
pub const SIGNER_UNAVAILABLE: &str = "chain signer unavailable";

/// A signature could not be produced. Nothing was signed that the caller can
/// submit, so it is never a verdict on the transaction: retry it later.
///
/// The text is generic on purpose (it can end up in a row's failure reason);
/// the detail goes to the log where it happened.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{SIGNER_UNAVAILABLE} ({why})")]
pub struct SignError {
    why: &'static str,
    transient: bool,
}

impl SignError {
    /// A failure that will not pass by itself: a refusal, a missing key, an
    /// answer that cannot be trusted.
    pub(crate) fn new(why: &'static str) -> Self {
        Self {
            why,
            transient: false,
        }
    }

    /// A failure likely to pass: unreachable, timed out, throttled, 5xx.
    pub(crate) fn transient(why: &'static str) -> Self {
        Self {
            why,
            transient: true,
        }
    }

    /// Whether retrying soon is likely to help.
    pub fn is_transient(&self) -> bool {
        self.transient
    }
}

/// Where a worker's chain signing key comes from, chosen by configuration.
#[derive(Clone)]
pub enum SignerSource {
    /// A secret URI or raw sr25519 secret held by the process.
    Secret(SecretString),
    /// A Cloud KMS Ed25519 key version, used with the workload's own identity.
    Kms(String),
}

/// Hand-written so a secret never reaches logs or errors.
impl std::fmt::Debug for SignerSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secret(_) => f.write_str("Secret(<redacted>)"),
            Self::Kms(name) => f.debug_tuple("Kms").field(name).finish(),
        }
    }
}

/// Why a [`SignerSource`] could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignerSourceError {
    #[error("set {secret} or {kms}")]
    Missing {
        secret: &'static str,
        kms: &'static str,
    },
    #[error("{secret} and {kms} are both set; set one signing key")]
    Both {
        secret: &'static str,
        kms: &'static str,
    },
    #[error(
        "{kms} is not a Cloud KMS key version name \
         (projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N)"
    )]
    InvalidKms { kms: &'static str },
}

impl SignerSource {
    /// Read the signer from `secret_var` or `kms_var` through `get`; exactly
    /// one must be set (a blank value counts as unset).
    pub fn from_getter<F>(
        get: F,
        secret_var: &'static str,
        kms_var: &'static str,
    ) -> Result<Self, SignerSourceError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let set = |key: &str| get(key).filter(|value| !value.trim().is_empty());
        match (set(secret_var), set(kms_var)) {
            (Some(_), Some(_)) => Err(SignerSourceError::Both {
                secret: secret_var,
                kms: kms_var,
            }),
            (None, None) => Err(SignerSourceError::Missing {
                secret: secret_var,
                kms: kms_var,
            }),
            (Some(secret), None) => Ok(Self::Secret(SecretString::from(secret))),
            (None, Some(name)) if is_key_version_name(&name) => Ok(Self::Kms(name)),
            (None, Some(_)) => Err(SignerSourceError::InvalidKms { kms: kms_var }),
        }
    }

    /// [`Self::from_getter`] over the process environment.
    pub fn from_env(
        secret_var: &'static str,
        kms_var: &'static str,
    ) -> Result<Self, SignerSourceError> {
        Self::from_getter(|key| std::env::var(key).ok(), secret_var, kms_var)
    }
}

/// A worker's chain signer: a key held in the process, or one held in Cloud KMS.
pub enum ChainSigner {
    /// An sr25519 key from a secret, signing in the process.
    Local(WriterSigner),
    /// An Ed25519 key in Cloud KMS, signing over the network.
    Kms(KmsSigner),
}

impl ChainSigner {
    /// Build the signer `source` names. For KMS this reads the public key, so
    /// the account is known before anything is signed.
    pub async fn from_source(source: &SignerSource) -> anyhow::Result<Self> {
        match source {
            SignerSource::Secret(secret) => {
                WriterSigner::from_secret(secret.expose_secret()).map(Self::Local)
            }
            SignerSource::Kms(name) => KmsSigner::connect(name).await.map(Self::Kms),
        }
    }

    /// The signing account's public key, which is also its account id.
    pub fn public_bytes(&self) -> [u8; 32] {
        match self {
            Self::Local(signer) => signer.public_bytes(),
            Self::Kms(signer) => signer.public_bytes(),
        }
    }

    /// `Some(primary)` when this key signs as a proxy for `primary`.
    pub fn proxy_for(&self, primary: AccountId32) -> Option<AccountId32> {
        (primary.0 != self.public_bytes()).then_some(primary)
    }

    /// A short, log-safe name for the key type and where it lives.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Local(_) => "sr25519-secret",
            Self::Kms(_) => "kms-ed25519",
        }
    }

    /// The KMS key version, for a KMS signer.
    pub fn kms_key_version(&self) -> Option<&str> {
        match self {
            Self::Local(_) => None,
            Self::Kms(signer) => Some(signer.key_version()),
        }
    }

    /// Sign an extrinsic's signer payload.
    pub async fn sign(&self, payload: &[u8]) -> Result<MultiSignature, SignError> {
        match self {
            Self::Local(signer) => Ok(MultiSignature::Sr25519(signer.sign_bytes(payload))),
            Self::Kms(signer) => signer.sign(payload).await.map(MultiSignature::Ed25519),
        }
    }
}

/// An extrinsic signer that may need to wait for its signature, as one held in
/// Cloud KMS does. [`crate::create_signed_v4`] signs through it.
pub trait ChainSign<T: subxt::Config>: Sync {
    fn account_id(&self) -> T::AccountId;
    fn sign_payload(
        &self,
        payload: &[u8],
    ) -> impl Future<Output = Result<T::Signature, SignError>> + Send;
}

impl ChainSign<PeopleConfig> for ChainSigner {
    fn account_id(&self) -> AccountId32 {
        AccountId32(self.public_bytes())
    }

    fn sign_payload(
        &self,
        payload: &[u8],
    ) -> impl Future<Output = Result<MultiSignature, SignError>> + Send {
        self.sign(payload)
    }
}

impl ChainSign<AssetHubConfig> for ChainSigner {
    fn account_id(&self) -> AccountId32 {
        AccountId32(self.public_bytes())
    }

    fn sign_payload(
        &self,
        payload: &[u8],
    ) -> impl Future<Output = Result<MultiSignature, SignError>> + Send {
        self.sign(payload)
    }
}

pub enum WriterSigner {
    /// Keypair derived from a `SecretUri` by `subxt-signer`.
    Uri(subxt_signer::sr25519::Keypair),
    /// Keypair built directly from a raw 64-byte expanded secret.
    Raw(schnorrkel::Keypair),
}

impl WriterSigner {
    pub fn from_secret(secret: &str) -> anyhow::Result<Self> {
        let trimmed = secret.trim();
        if let Some(hex) = trimmed.strip_prefix("0x") {
            if hex.len() == 128 {
                let bytes = hex::decode(hex).context("decoding raw sr25519 secret key")?;
                let secret = schnorrkel::SecretKey::from_ed25519_bytes(&bytes)
                    .map_err(|e| anyhow::anyhow!("invalid 64-byte sr25519 secret key: {e}"))?;
                let keypair = schnorrkel::Keypair {
                    public: secret.to_public(),
                    secret,
                };
                return Ok(Self::Raw(keypair));
            }
        }
        let uri =
            subxt_signer::SecretUri::from_str(trimmed).context("parsing signer secret URI")?;
        let keypair = subxt_signer::sr25519::Keypair::from_uri(&uri)
            .context("building signer keypair from SURI")?;
        Ok(Self::Uri(keypair))
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        match self {
            Self::Uri(k) => k.public_key().0,
            Self::Raw(k) => k.public.to_bytes(),
        }
    }

    pub fn proxy_for(&self, primary: AccountId32) -> Option<AccountId32> {
        (primary.0 != self.public_bytes()).then_some(primary)
    }

    fn sign_bytes(&self, payload: &[u8]) -> [u8; 64] {
        match self {
            Self::Uri(k) => k.sign(payload).0,
            Self::Raw(k) => {
                let context = schnorrkel::signing_context(b"substrate");
                k.sign(context.bytes(payload)).to_bytes()
            }
        }
    }
}

impl subxt::tx::Signer<PeopleConfig> for WriterSigner {
    fn account_id(&self) -> AccountId32 {
        AccountId32(self.public_bytes())
    }

    fn sign(&self, signer_payload: &[u8]) -> MultiSignature {
        MultiSignature::Sr25519(self.sign_bytes(signer_payload))
    }
}

impl subxt::tx::Signer<AssetHubConfig> for WriterSigner {
    fn account_id(&self) -> AccountId32 {
        AccountId32(self.public_bytes())
    }

    fn sign(&self, signer_payload: &[u8]) -> MultiSignature {
        MultiSignature::Sr25519(self.sign_bytes(signer_payload))
    }
}

#[cfg(test)]
mod tests {
    use schnorrkel::{ExpansionMode, MiniSecretKey};

    use super::*;

    #[test]
    fn uri_path_derives_dev_alice() {
        let signer = WriterSigner::from_secret("//Alice").expect("valid dev uri");
        let expected =
            hex::decode("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
                .unwrap();
        assert_eq!(signer.public_bytes().as_slice(), expected.as_slice());
    }

    #[test]
    fn raw_64_byte_secret_matches_seed_path() {
        let seed = [7u8; 32];
        let keypair = MiniSecretKey::from_bytes(&seed)
            .unwrap()
            .expand_to_keypair(ExpansionMode::Ed25519);
        let raw64 = keypair.secret.to_ed25519_bytes();

        let from_seed =
            WriterSigner::from_secret(&format!("0x{}", hex::encode(seed))).expect("valid seed");
        let from_raw =
            WriterSigner::from_secret(&format!("0x{}", hex::encode(raw64))).expect("valid raw");

        assert!(matches!(from_seed, WriterSigner::Uri(_)));
        assert!(matches!(from_raw, WriterSigner::Raw(_)));
        assert_eq!(from_seed.public_bytes(), keypair.public.to_bytes());
        assert_eq!(from_raw.public_bytes(), keypair.public.to_bytes());
    }

    #[test]
    fn raw_signature_verifies() {
        let seed = [9u8; 32];
        let keypair = MiniSecretKey::from_bytes(&seed)
            .unwrap()
            .expand_to_keypair(ExpansionMode::Ed25519);
        let raw64 = keypair.secret.to_ed25519_bytes();
        let signer =
            WriterSigner::from_secret(&format!("0x{}", hex::encode(raw64))).expect("valid raw");

        let message = b"dub";
        let sig = signer.sign_bytes(message);
        let public = schnorrkel::PublicKey::from_bytes(&signer.public_bytes()).unwrap();
        let signature = schnorrkel::Signature::from_bytes(&sig).unwrap();
        assert!(public
            .verify_simple(b"substrate", message, &signature)
            .is_ok());
    }

    fn source(pairs: &[(&str, &str)]) -> Result<SignerSource, SignerSourceError> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        SignerSource::from_getter(
            |key| pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()),
            "SIGNER_SURI",
            "SIGNER_KMS_KEY",
        )
    }

    const KMS_KEY: &str = "projects/example-project/locations/us-east1/keyRings/dub/cryptoKeys/chain-writer/cryptoKeyVersions/3";

    #[test]
    fn exactly_one_signer_source_is_accepted() {
        assert!(matches!(
            source(&[("SIGNER_SURI", "//Alice")]),
            Ok(SignerSource::Secret(_))
        ));
        assert!(
            matches!(source(&[("SIGNER_KMS_KEY", KMS_KEY)]), Ok(SignerSource::Kms(name)) if name == KMS_KEY)
        );
        // Blank counts as unset.
        assert!(matches!(
            source(&[("SIGNER_SURI", "//Alice"), ("SIGNER_KMS_KEY", "  ")]),
            Ok(SignerSource::Secret(_))
        ));
        assert_eq!(
            source(&[]).err(),
            Some(SignerSourceError::Missing {
                secret: "SIGNER_SURI",
                kms: "SIGNER_KMS_KEY"
            })
        );
        assert_eq!(
            source(&[("SIGNER_SURI", "//Alice"), ("SIGNER_KMS_KEY", KMS_KEY)]).err(),
            Some(SignerSourceError::Both {
                secret: "SIGNER_SURI",
                kms: "SIGNER_KMS_KEY"
            })
        );
        assert_eq!(
            source(&[(
                "SIGNER_KMS_KEY",
                "projects/p/locations/l/keyRings/r/cryptoKeys/k"
            )])
            .err(),
            Some(SignerSourceError::InvalidKms {
                kms: "SIGNER_KMS_KEY"
            })
        );
    }

    #[test]
    fn a_signer_source_never_prints_its_secret() {
        let secret = source(&[("SIGNER_SURI", "bottom drive obey lake//s3cret")]).unwrap();
        let printed = format!("{secret:?}");
        assert!(
            !printed.contains("s3cret") && printed.contains("<redacted>"),
            "{printed}"
        );
        let errors = [
            source(&[("SIGNER_SURI", "s3cret"), ("SIGNER_KMS_KEY", KMS_KEY)]).unwrap_err(),
            source(&[("SIGNER_KMS_KEY", "s3cret")]).unwrap_err(),
        ];
        for error in errors {
            assert!(!error.to_string().contains("s3cret"), "{error}");
        }
    }

    #[tokio::test]
    async fn a_local_signer_signs_sr25519_as_before() {
        let signer = ChainSigner::from_source(&SignerSource::Secret(SecretString::from("//Alice")))
            .await
            .unwrap();
        assert_eq!(signer.label(), "sr25519-secret");
        assert_eq!(signer.kms_key_version(), None);
        let MultiSignature::Sr25519(sig) = signer.sign(b"dub").await.unwrap() else {
            panic!("a local signer signs with sr25519");
        };
        let public = schnorrkel::PublicKey::from_bytes(&signer.public_bytes()).unwrap();
        assert!(public
            .verify_simple(
                b"substrate",
                b"dub",
                &schnorrkel::Signature::from_bytes(&sig).unwrap()
            )
            .is_ok());
    }

    #[test]
    fn every_signing_failure_names_itself_as_one() {
        assert!(SignError::new("kms timed out")
            .to_string()
            .starts_with(SIGNER_UNAVAILABLE));
    }

    #[test]
    fn proxy_mode_is_derived_from_the_primary() {
        let signer = WriterSigner::from_secret("//Alice").expect("valid dev uri");
        let own = AccountId32(signer.public_bytes());
        let other = AccountId32([2; 32]);

        assert_eq!(signer.proxy_for(other), Some(other));
        assert_eq!(signer.proxy_for(own), None);
    }
}
