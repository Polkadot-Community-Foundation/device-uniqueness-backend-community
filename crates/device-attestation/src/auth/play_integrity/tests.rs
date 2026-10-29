// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use base64::Engine as _;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::EncodePublicKey as _;
use sha2::{Digest as _, Sha256};

use super::verdict;
use super::{verify_token, PlayIntegrityError, PlayIntegrityMode, PolicyParams, VerifyParams};

const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

const PLAYSTORE_DIGEST: [u8; 32] = [0x11; 32];
const WEBSITE_DIGEST: [u8; 32] = [0x22; 32];
const EXPECTED_NONCE: [u8; 32] = [0x33; 32];
const PACKAGE: &str = "io.pcf.polkadotapp";

struct TestKeys {
    decryption_key: [u8; 32],
    signing_key: p256::ecdsa::SigningKey,
    verification_key_der: Vec<u8>,
}

impl TestKeys {
    fn new() -> Self {
        let signing_key = p256::ecdsa::SigningKey::generate();
        let verification_key_der = p256::PublicKey::from(signing_key.verifying_key())
            .to_public_key_der()
            .expect("spki der")
            .into_vec();
        Self {
            decryption_key: [0x42; 32],
            signing_key,
            verification_key_der,
        }
    }

    fn sign_jws(&self, payload_json: &str) -> String {
        let header = B64URL.encode(br#"{"alg":"ES256"}"#);
        let payload = B64URL.encode(payload_json.as_bytes());
        let signing_input = format!("{header}.{payload}");
        let prehash = Sha256::digest(signing_input.as_bytes());
        let signature: p256::ecdsa::Signature =
            self.signing_key.sign_prehash(&prehash).expect("signs");
        format!("{signing_input}.{}", B64URL.encode(signature.to_bytes()))
    }

    fn encrypt_jwe(&self, jws: &str) -> String {
        let header_b64 = B64URL.encode(br#"{"alg":"A256KW","enc":"A256GCM"}"#);

        let cek = [0x24u8; 32];
        let kek = aes_kw::KekAes256::from(self.decryption_key);
        let wrapped_cek = kek.wrap_vec(&cek).expect("wraps");

        let iv = [0x07u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&cek).expect("cek size");
        let mut ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: jws.as_bytes(),
                    aad: header_b64.as_bytes(),
                },
            )
            .expect("encrypts");
        let tag = ciphertext.split_off(ciphertext.len() - 16);

        format!(
            "{header_b64}.{}.{}.{}.{}",
            B64URL.encode(wrapped_cek),
            B64URL.encode(iv),
            B64URL.encode(ciphertext),
            B64URL.encode(tag)
        )
    }

    fn mint(&self, payload_json: &str) -> String {
        self.encrypt_jwe(&self.sign_jws(payload_json))
    }
}

fn payload(digest: &[u8; 32]) -> String {
    serde_json::json!({
        "requestDetails": {
            "requestPackageName": PACKAGE,
            "nonce": B64URL.encode(EXPECTED_NONCE),
            "timestampMillis": "1750000000000"
        },
        "appIntegrity": {
            "appRecognitionVerdict": "PLAY_RECOGNIZED",
            "packageName": PACKAGE,
            "certificateSha256Digest": [B64URL.encode(digest)],
            "versionCode": "42"
        },
        "deviceIntegrity": {
            "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]
        },
        "accountDetails": {
            "appLicensingVerdict": "LICENSED"
        }
    })
    .to_string()
}

fn params<'a>(keys: &'a TestKeys, mode: PlayIntegrityMode) -> VerifyParams<'a> {
    VerifyParams {
        decryption_key: &keys.decryption_key,
        verification_key_der: &keys.verification_key_der,
        policy: PolicyParams {
            expected_nonce: &EXPECTED_NONCE,
            mode,
            package_names: &[],
            playstore_digest: &PLAYSTORE_DIGEST,
            website_digest: &WEBSITE_DIGEST,
        },
    }
}

fn params_with_packages<'a>(
    keys: &'a TestKeys,
    mode: PlayIntegrityMode,
    packages: &'a [String],
) -> VerifyParams<'a> {
    let mut params = params(keys, mode);
    params.policy.package_names = packages;
    params
}

fn allow_listed() -> Vec<String> {
    vec![PACKAGE.to_string()]
}

#[test]
fn strict_green_path_classifies_the_store_channel() {
    let keys = TestKeys::new();
    let packages = allow_listed();

    let play = keys.mint(&payload(&PLAYSTORE_DIGEST));
    let from_store = verify_token(
        &play,
        &params_with_packages(&keys, PlayIntegrityMode::Strict, &packages),
    )
    .expect("valid token");
    assert!(from_store);

    let website = keys.mint(&payload(&WEBSITE_DIGEST));
    let from_store = verify_token(
        &website,
        &params_with_packages(&keys, PlayIntegrityMode::Strict, &packages),
    )
    .expect("valid token");
    assert!(!from_store);
}

#[test]
fn wrong_decryption_key_fails_decrypt() {
    let keys = TestKeys::new();
    let token = keys.mint(&payload(&PLAYSTORE_DIGEST));

    let mut wrong = TestKeys::new();
    wrong.decryption_key = [0x43; 32];
    wrong.verification_key_der = keys.verification_key_der.clone();
    let packages = allow_listed();
    assert!(matches!(
        verify_token(
            &token,
            &params_with_packages(&wrong, PlayIntegrityMode::Strict, &packages)
        ),
        Err(PlayIntegrityError::Decrypt(_))
    ));
}

#[test]
fn foreign_signing_key_fails_signature() {
    let keys = TestKeys::new();
    let foreign = TestKeys::new();
    let token = keys.mint(&payload(&PLAYSTORE_DIGEST));
    let packages = allow_listed();
    assert!(matches!(
        verify_token(
            &token,
            &params_with_packages(&foreign, PlayIntegrityMode::Strict, &packages)
        ),
        Err(PlayIntegrityError::Signature)
    ));
}

#[test]
fn nonce_mismatch_and_missing_nonce_are_rejected() {
    let keys = TestKeys::new();
    let packages = allow_listed();
    let mut params = params_with_packages(&keys, PlayIntegrityMode::Strict, &packages);
    let other_nonce = [0x99u8; 32];
    params.policy.expected_nonce = &other_nonce;

    let token = keys.mint(&payload(&PLAYSTORE_DIGEST));
    assert!(matches!(
        verify_token(&token, &params),
        Err(PlayIntegrityError::Nonce)
    ));

    let no_nonce = keys.mint(
        &serde_json::json!({
            "appIntegrity": { "appRecognitionVerdict": "PLAY_RECOGNIZED" }
        })
        .to_string(),
    );
    let params = params_with_packages(&keys, PlayIntegrityMode::Strict, &packages);
    assert!(matches!(
        verify_token(&no_nonce, &params),
        Err(PlayIntegrityError::Nonce)
    ));
}

#[test]
fn strict_rejects_basic_integrity_but_relaxed_device_accepts() {
    let keys = TestKeys::new();
    let packages = allow_listed();
    let basic = serde_json::json!({
        "requestDetails": { "nonce": B64URL.encode(EXPECTED_NONCE) },
        "appIntegrity": {
            "appRecognitionVerdict": "PLAY_RECOGNIZED",
            "packageName": PACKAGE,
            "certificateSha256Digest": [B64URL.encode(PLAYSTORE_DIGEST)]
        },
        "deviceIntegrity": { "deviceRecognitionVerdict": ["MEETS_BASIC_INTEGRITY"] },
        "accountDetails": { "appLicensingVerdict": "LICENSED" }
    })
    .to_string();
    let token = keys.mint(&basic);

    match verify_token(
        &token,
        &params_with_packages(&keys, PlayIntegrityMode::Strict, &packages),
    ) {
        Err(PlayIntegrityError::Rejected(codes)) => {
            assert_eq!(codes, vec![verdict::DEVICE_INTEGRITY_FAILED]);
        }
        other => panic!("expected rejection, got {other:?}"),
    }

    assert!(verify_token(
        &token,
        &params_with_packages(&keys, PlayIntegrityMode::RelaxedDevice, &packages)
    )
    .is_ok());
}

#[test]
fn relaxed_all_tolerates_sideloaded_unevaluated_tokens() {
    let keys = TestKeys::new();
    let packages = allow_listed();
    let sideloaded = serde_json::json!({
        "requestDetails": { "nonce": B64URL.encode(EXPECTED_NONCE) },
        "appIntegrity": { "appRecognitionVerdict": "UNEVALUATED" },
        "deviceIntegrity": {},
        "accountDetails": { "appLicensingVerdict": "UNLICENSED" }
    })
    .to_string();
    let token = keys.mint(&sideloaded);

    let from_store = verify_token(
        &token,
        &params_with_packages(&keys, PlayIntegrityMode::RelaxedAll, &packages),
    )
    .expect("relaxed_all accepts");
    assert!(!from_store);

    match verify_token(
        &token,
        &params_with_packages(&keys, PlayIntegrityMode::Strict, &packages),
    ) {
        Err(PlayIntegrityError::Rejected(codes)) => {
            assert_eq!(
                codes,
                vec![
                    verdict::APP_INTEGRITY_FAILED,
                    verdict::DEVICE_INTEGRITY_FAILED,
                    verdict::LICENSE_CHECK_FAILED,
                    verdict::APK_FINGERPRINT_MISMATCH,
                    verdict::PACKAGE_NAME_MISMATCH,
                ]
            );
        }
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[test]
fn play_signed_sideload_is_not_a_store_install_under_relaxed_all() {
    let keys = TestKeys::new();
    let packages = allow_listed();
    // The Play signing certificate on an install Play does not recognize or
    // license: the digest alone must not promote it to a store install.
    let play_signed_sideload = serde_json::json!({
        "requestDetails": { "nonce": B64URL.encode(EXPECTED_NONCE) },
        "appIntegrity": {
            "appRecognitionVerdict": "UNEVALUATED",
            "packageName": PACKAGE,
            "certificateSha256Digest": [B64URL.encode(PLAYSTORE_DIGEST)]
        },
        "deviceIntegrity": { "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"] },
        "accountDetails": { "appLicensingVerdict": "UNLICENSED" }
    })
    .to_string();
    let token = keys.mint(&play_signed_sideload);

    let from_store = verify_token(
        &token,
        &params_with_packages(&keys, PlayIntegrityMode::RelaxedAll, &packages),
    )
    .expect("relaxed_all accepts");
    assert!(!from_store);
}

#[test]
fn present_but_mismatching_fields_reject_in_every_mode() {
    let keys = TestKeys::new();
    let packages = allow_listed();
    let mismatched = serde_json::json!({
        "requestDetails": { "nonce": B64URL.encode(EXPECTED_NONCE) },
        "appIntegrity": {
            "appRecognitionVerdict": "PLAY_RECOGNIZED",
            "packageName": "io.malicious.app",
            "certificateSha256Digest": [B64URL.encode([0x77u8; 32])]
        },
        "deviceIntegrity": { "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"] },
        "accountDetails": { "appLicensingVerdict": "LICENSED" }
    })
    .to_string();
    let token = keys.mint(&mismatched);

    for mode in [
        PlayIntegrityMode::Strict,
        PlayIntegrityMode::RelaxedDevice,
        PlayIntegrityMode::RelaxedAll,
    ] {
        match verify_token(&token, &params_with_packages(&keys, mode, &packages)) {
            Err(PlayIntegrityError::Rejected(codes)) => {
                assert!(
                    codes.contains(&verdict::APK_FINGERPRINT_MISMATCH),
                    "{mode:?}"
                );
                assert!(codes.contains(&verdict::PACKAGE_NAME_MISMATCH), "{mode:?}");
            }
            other => panic!("{mode:?}: expected rejection, got {other:?}"),
        }
    }
}

#[test]
fn unknown_verdict_strings_are_treated_as_missing() {
    let keys = TestKeys::new();
    let packages = allow_listed();
    let unknown = serde_json::json!({
        "requestDetails": { "nonce": B64URL.encode(EXPECTED_NONCE) },
        "appIntegrity": {
            "appRecognitionVerdict": "TOTALLY_NEW_VERDICT",
            "packageName": PACKAGE,
            "certificateSha256Digest": [B64URL.encode(PLAYSTORE_DIGEST)]
        },
        "deviceIntegrity": { "deviceRecognitionVerdict": ["SOMETHING_ELSE"] },
        "accountDetails": { "appLicensingVerdict": "LICENSED" }
    })
    .to_string();
    let token = keys.mint(&unknown);

    match verify_token(
        &token,
        &params_with_packages(&keys, PlayIntegrityMode::Strict, &packages),
    ) {
        Err(PlayIntegrityError::Rejected(codes)) => {
            assert!(codes.contains(&verdict::APP_INTEGRITY_FAILED));
            assert!(codes.contains(&verdict::DEVICE_INTEGRITY_FAILED));
        }
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[test]
fn wrong_jose_algorithms_are_rejected() {
    let keys = TestKeys::new();
    let packages = allow_listed();
    let params = params_with_packages(&keys, PlayIntegrityMode::Strict, &packages);

    let jws = keys.sign_jws(&payload(&PLAYSTORE_DIGEST));
    let good_jwe = keys.encrypt_jwe(&jws);
    let mut parts: Vec<String> = good_jwe.split('.').map(str::to_string).collect();
    parts[0] = B64URL.encode(br#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#);
    let swapped = parts.join(".");
    assert!(matches!(
        verify_token(&swapped, &params),
        Err(PlayIntegrityError::Malformed(_))
    ));

    let header = B64URL.encode(br#"{"alg":"none"}"#);
    let body = B64URL.encode(payload(&PLAYSTORE_DIGEST).as_bytes());
    let unsigned = format!("{header}.{body}.");
    let token = keys.encrypt_jwe(&unsigned);
    assert!(matches!(
        verify_token(&token, &params),
        Err(PlayIntegrityError::Malformed(_))
    ));

    assert!(verify_token("not-a-token", &params).is_err());
}
