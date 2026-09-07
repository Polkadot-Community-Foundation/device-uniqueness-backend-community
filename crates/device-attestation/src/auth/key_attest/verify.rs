// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use base64::Engine as _;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer as _;

use super::extension::{self, KeyDescription, ANDROID_ATTESTATION_OID};
use crate::auth::x509;

pub const MAX_CHAIN_LENGTH: usize = 10;

/// Google Key Attestation root CA (RSA, serial `f92009e853b6b045`), from
/// <https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate>.
const GOOGLE_ROOT_CA_RSA_B64: &str = "\
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw\
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B\
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS\
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7\
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj\
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq\
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ\
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O\
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg\
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi\
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M\
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E\
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um\
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud\
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD\
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7\
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC\
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G\
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx\
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG\
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF\
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz\
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw\
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu\
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo\
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn\
w1IdYIg2Wxg7yHcQZemFQg==";

/// Google Key Attestation root CA (ECDSA P-384, `Key Attestation CA1`), from
/// <https://android.googleapis.com/attestation/root>.
const GOOGLE_ROOT_CA_ECDSA_B64: &str = "\
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc\
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET\
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4\
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex\
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG\
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt\
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5\
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB\
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA\
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH\
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY\
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==";

/// Decode the pinned Google attestation roots to DER (RSA + EC).
pub fn google_roots_der() -> Vec<Vec<u8>> {
    let b64 = base64::engine::general_purpose::STANDARD;
    vec![
        b64.decode(GOOGLE_ROOT_CA_RSA_B64).expect("pinned RSA root"),
        b64.decode(GOOGLE_ROOT_CA_ECDSA_B64)
            .expect("pinned EC root"),
    ]
}

/// Pinned GrapheneOS verified-boot key fingerprints (SHA-256, lowercase hex),
/// mirrored from the legacy backend / <https://grapheneos.org/attestation.json>.
/// A `SelfSigned` verified-boot state is only trusted when its boot key is in
/// this set (locked bootloader running an OS image GrapheneOS signed).
pub const GRAPHENEOS_VERIFIED_BOOT_KEYS: &[&str] = &[
    "d8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80",
    "55a2d44103e56d5ec65496399c417987ba77730e6488fc60ba058d09fc3caee3",
    "141d7fc32af7958a416f2661b37cf6f27bfb376fb5ce616aeaa27a82c7a04f74",
    "4e8ee8f717754052198ca6d2d3aaa232e2461b4293c0d6f297e519cc778de093",
    "3f7415ea26f5df5b14ea6d153256071a7a1af9ce7b0970b7311cc463c7ea02c7",
    "0508de44ee00bfb49ece32c418af1896391abde0f05b64f41bc9a2dfb589445b",
    "af4d2c6e62be0fec54f0271b9776ff061dd8392d9f51cf6ab1551d346679e24c",
    "55d3c2323db91bb91f20d38d015e85112d038f6b6b5738fe352c1a80dba57023",
    "f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86",
    "9e6a8f3e0d761a780179f93acd5721ba1ab7c8c537c7761073c0a754b0e932de",
    "096b8bd6d44527a24ac1564b308839f67e78202185cbff9cfdcb10e63250bc5e",
    "896db2d09d84e1d6bb747002b8a114950b946e5825772a9d48ba7eb01d118c1c",
    "cd7479653aa88208f9f03034810ef9b7b0af8a9d41e2000e458ac403a2acb233",
    "ee0c9dfef6f55a878538b0dbf7e78e3bc3f1a13c8c44839b095fe26dd5fe2842",
    "94df136e6c6aa08dc26580af46f36419b5f9baf46039db076f5295b91aaff230",
    "508d75dea10c5cbc3e7632260fc0b59f6055a8a49dd84e693b6d8899edbb01e4",
    "bc1c0dd95664604382bb888412026422742eb333071ea0b2d19036217d49182f",
    "3efe5392be3ac38afb894d13de639e521675e62571a8a9b3ef9fc8c44fd17fa1",
    "08c860350a9600692d10c8512f7b8e80707757468e8fbfeea2a870c0a83d6031",
    "439b76524d94c40652ce1bf0d8243773c634d2f99ba3160d8d02aa5e29ff925c",
    "f0a890375d1405e62ebfd87e8d3f475f948ef031bbf9ddd516d5f600a23677e8",
];

const BOOT_STATE_VERIFIED: u64 = 0;
const BOOT_STATE_SELF_SIGNED: u64 = 1;

/// Known-public AVB signing keys (SHA-256 of the AVB public-key blob,
/// lowercase hex): the AOSP test keys from `external/avb/test/data/`.
/// Real OEMs have shipped these as production AVB roots ("AVBTestKeyInTheWild",
/// SPICES 2025), so an affected device reports a locked bootloader and
/// `Verified` boot — with genuine, unrevoked hardware attestation — while
/// anyone can sign and boot modified firmware on it. Google's CRL does not
/// cover this, so the keys are denied outright.
const KNOWN_PUBLIC_VERIFIED_BOOT_KEYS: &[&str] = &[
    // testkey_rsa2048.pem
    "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c",
    // testkey_rsa4096.pem (the default AOSP build signing key)
    "7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6",
    // testkey_rsa8192.pem
    "e15e2365469ce672a91d02cc8d9c2f29b787481e574d3b56ac774153d7ced614",
];

/// Everything the verifier needs besides the chain itself.
pub struct VerifyParams<'a> {
    /// Challenge the client minted the keystore key with (`setAttestationChallenge`).
    pub challenge: &'a [u8],
    /// Allow-listed Android package names.
    pub package_names: &'a [String],
    /// SHA-256 digest of the Play Store signing certificate.
    pub playstore_digest: &'a [u8; 32],
    /// SHA-256 digest of the website/vanilla-APK signing certificate.
    pub website_digest: &'a [u8; 32],
    /// Trusted root certificates (DER); production passes [`google_roots_der`].
    pub trusted_roots_der: &'a [Vec<u8>],
    /// Trusted `SelfSigned` verified-boot key fingerprints (lowercase hex).
    pub trusted_verified_boot_keys: &'a [&'a str],
    /// Revoked serial numbers from the attestation CRL (lowercase hex or decimal).
    pub revoked_serials: &'a std::collections::HashSet<String>,
    /// Verification time (tests pin this; fixtures embed short-lived intermediates).
    pub now_unix: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyAttestError {
    #[error("malformed attestation chain: {0}")]
    Malformed(String),
    #[error("certificate chain rejected: {0}")]
    Chain(String),
    #[error("chain does not terminate at a trusted Google root")]
    RootNotTrusted,
    #[error("certificate serial {0} is revoked")]
    Revoked(String),
    #[error("key-description extension rejected: {0}")]
    Extension(String),
    #[error("attestation security level {attestation}/{key} is not TEE or StrongBox")]
    SecurityLevel { attestation: u64, key: u64 },
    #[error("root of trust rejected: {0}")]
    RootOfTrust(String),
    #[error("attestation challenge mismatch")]
    Challenge,
    #[error("attested package {0:?} is not allow-listed")]
    Package(String),
    #[error("signing digest rejected: {0}")]
    SigningDigest(String),
}

pub fn verify_chain(
    chain_der: &[Vec<u8>],
    params: &VerifyParams<'_>,
) -> Result<(), KeyAttestError> {
    if chain_der.len() < 2 || chain_der.len() > MAX_CHAIN_LENGTH {
        return Err(KeyAttestError::Malformed(format!(
            "chain length {} outside 2..={MAX_CHAIN_LENGTH}",
            chain_der.len()
        )));
    }

    let mut certs = Vec::with_capacity(chain_der.len());
    for (i, der) in chain_der.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| KeyAttestError::Malformed(format!("certificate {i}: {e}")))?;
        certs.push(cert);
    }

    if certs[0].subject() == certs[0].issuer() {
        certs.reverse();
    }
    for i in 0..certs.len() - 1 {
        if certs[i].issuer() != certs[i + 1].subject() {
            return Err(KeyAttestError::Chain(format!(
                "certificate {i} issuer does not match certificate {} subject",
                i + 1
            )));
        }
    }

    for (i, cert) in certs.iter().enumerate() {
        x509::check_validity(cert, params.now_unix)
            .map_err(|e| KeyAttestError::Chain(format!("certificate {i}: {e}")))?;
        check_key_usage(cert, i, certs.len()).map_err(KeyAttestError::Chain)?;
        check_revocation(cert, params.revoked_serials)?;
    }

    for i in 0..certs.len() - 1 {
        x509::verify_signed_by(&certs[i], &certs[i + 1])
            .map_err(|e| KeyAttestError::Chain(format!("certificate {i}: {e}")))?;
    }

    let chain_root = certs.last().expect("length checked");
    let root_trusted = params.trusted_roots_der.iter().any(|der| {
        X509Certificate::from_der(der)
            .ok()
            .is_some_and(|(_, root)| x509::verify_signed_by(chain_root, &root).is_ok())
    });
    if !root_trusted {
        return Err(KeyAttestError::RootNotTrusted);
    }

    for cert in certs.iter().skip(1) {
        if find_attestation_extension(cert).is_some() {
            return Err(KeyAttestError::Extension(
                "key-description extension on a non-leaf certificate".to_string(),
            ));
        }
    }
    let ext_value = find_attestation_extension(&certs[0]).ok_or_else(|| {
        KeyAttestError::Extension("leaf has no key-description extension".to_string())
    })?;
    let description = extension::parse(ext_value).map_err(KeyAttestError::Extension)?;

    check_policy(&description, params)
}

fn check_policy(
    description: &KeyDescription,
    params: &VerifyParams<'_>,
) -> Result<(), KeyAttestError> {
    // Both the attestation statement and the attested key must originate in
    // TEE (1) or StrongBox (2); Software (0) and any unknown level (3+) are
    // rejected.
    let level_ok = |level: u64| level == 1 || level == 2;
    if !level_ok(description.attestation_security_level)
        || !level_ok(description.key_security_level)
    {
        return Err(KeyAttestError::SecurityLevel {
            attestation: description.attestation_security_level,
            key: description.key_security_level,
        });
    }

    let root_of_trust = description
        .root_of_trust
        .as_ref()
        .ok_or_else(|| KeyAttestError::RootOfTrust("missing".to_string()))?;
    let key_hex = hex::encode(&root_of_trust.verified_boot_key);
    if KNOWN_PUBLIC_VERIFIED_BOOT_KEYS.contains(&key_hex.as_str()) {
        return Err(KeyAttestError::RootOfTrust(format!(
            "known-public AVB test key {key_hex}"
        )));
    }
    match root_of_trust.verified_boot_state {
        BOOT_STATE_VERIFIED => {}
        BOOT_STATE_SELF_SIGNED => {
            if !params
                .trusted_verified_boot_keys
                .contains(&key_hex.as_str())
            {
                return Err(KeyAttestError::RootOfTrust(format!(
                    "untrusted self-signed verified-boot key {key_hex}"
                )));
            }
        }
        state => {
            return Err(KeyAttestError::RootOfTrust(format!(
                "verified boot state {state} is not Verified or SelfSigned"
            )));
        }
    }
    if !root_of_trust.device_locked {
        return Err(KeyAttestError::RootOfTrust(
            "bootloader is not locked".to_string(),
        ));
    }

    if description.attestation_challenge != params.challenge {
        return Err(KeyAttestError::Challenge);
    }

    if description.package_names.is_empty() {
        return Err(KeyAttestError::Package(String::new()));
    }
    for name in &description.package_names {
        if !params.package_names.iter().any(|p| p == name) {
            return Err(KeyAttestError::Package(name.clone()));
        }
    }

    let [signing_digest] = description.signing_digests.as_slice() else {
        return Err(KeyAttestError::SigningDigest(format!(
            "expected one attested digest, got {}",
            description.signing_digests.len()
        )));
    };
    if signing_digest.as_slice() == params.playstore_digest
        || signing_digest.as_slice() == params.website_digest
    {
        Ok(())
    } else {
        Err(KeyAttestError::SigningDigest(format!(
            "unknown digest {}",
            hex::encode(signing_digest)
        )))
    }
}

fn find_attestation_extension<'a>(cert: &'a X509Certificate<'_>) -> Option<&'a [u8]> {
    cert.extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == ANDROID_ATTESTATION_OID)
        .map(|ext| ext.value)
}

fn check_key_usage(cert: &X509Certificate<'_>, index: usize, len: usize) -> Result<(), String> {
    let Ok(Some(usage)) = cert.key_usage() else {
        return Ok(());
    };
    let is_leaf = index == 0;
    let is_intermediate = index > 0 && index < len - 1;
    if is_leaf && !usage.value.digital_signature() {
        return Err(format!("leaf certificate {index} missing digitalSignature"));
    }
    if is_intermediate && !usage.value.key_cert_sign() {
        return Err(format!(
            "intermediate certificate {index} missing keyCertSign"
        ));
    }
    Ok(())
}

fn check_revocation(
    cert: &X509Certificate<'_>,
    revoked: &std::collections::HashSet<String>,
) -> Result<(), KeyAttestError> {
    let serial = &cert.tbs_certificate.serial;
    let trimmed_hex = serial.to_str_radix(16);
    let raw_hex = hex::encode(cert.tbs_certificate.raw_serial());
    let decimal = serial.to_str_radix(10);
    if [&trimmed_hex, &raw_hex, &decimal]
        .iter()
        .any(|candidate| revoked.contains(candidate.as_str()))
    {
        return Err(KeyAttestError::Revoked(trimmed_hex));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use base64::Engine as _;

    use super::*;
    use crate::auth::key_attest::{chain_from_body, extension};

    const GOOGLE_PIXEL_BODY: &str = include_str!("../../../testdata/key_attest/google-pixel.json");
    const GRAPHENEOS_BODY: &str = include_str!("../../../testdata/key_attest/grapheneos.json");

    const GOOGLE_PIXEL_CHALLENGE_B64: &str = "MoLMwO15bqX3jaB6zEbu7w==";
    const GRAPHENEOS_CHALLENGE: &[u8] = b"random_challenge";

    const DEBUG_NIGHTLY_DIGEST: &str =
        "5aa3a6d7c8f2de242cb0e97762e2e5525b0a498990afe8506355b6f4cb31275c";
    const PLAY_STORE_DIGEST: &str =
        "7b471d1bbc16f8fd811f09ace1c0541ba462e6267a2b7b6abbec3f6dfbea3061";

    fn pinned_now() -> i64 {
        time::Date::from_calendar_date(2026, time::Month::June, 10)
            .expect("valid date")
            .midnight()
            .assume_utc()
            .unix_timestamp()
    }

    fn digest(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str)
            .expect("hex digest")
            .try_into()
            .expect("32 bytes")
    }

    struct Fixture {
        chain: Vec<Vec<u8>>,
        challenge: Vec<u8>,
        packages: Vec<String>,
    }

    fn google_pixel() -> Fixture {
        Fixture {
            chain: chain_from_body(GOOGLE_PIXEL_BODY.as_bytes()).expect("fixture parses"),
            challenge: base64::engine::general_purpose::STANDARD
                .decode(GOOGLE_PIXEL_CHALLENGE_B64)
                .expect("fixture challenge"),
            packages: vec!["io.pcf.polkadotapp.debug".to_string()],
        }
    }

    fn grapheneos() -> Fixture {
        Fixture {
            chain: chain_from_body(GRAPHENEOS_BODY.as_bytes()).expect("fixture parses"),
            challenge: GRAPHENEOS_CHALLENGE.to_vec(),
            packages: vec!["io.pcf.polkadotapp.nightly".to_string()],
        }
    }

    struct ParamsInput {
        playstore: [u8; 32],
        website: [u8; 32],
        roots: Vec<Vec<u8>>,
        revoked: HashSet<String>,
        now: i64,
    }

    impl ParamsInput {
        fn new() -> Self {
            Self {
                playstore: digest(PLAY_STORE_DIGEST),
                website: digest(DEBUG_NIGHTLY_DIGEST),
                roots: google_roots_der(),
                revoked: HashSet::new(),
                now: pinned_now(),
            }
        }

        fn params<'a>(&'a self, fixture: &'a Fixture) -> VerifyParams<'a> {
            VerifyParams {
                challenge: &fixture.challenge,
                package_names: &fixture.packages,
                playstore_digest: &self.playstore,
                website_digest: &self.website,
                trusted_roots_der: &self.roots,
                trusted_verified_boot_keys: GRAPHENEOS_VERIFIED_BOOT_KEYS,
                revoked_serials: &self.revoked,
                now_unix: self.now,
            }
        }
    }

    #[test]
    fn google_pixel_capture_verifies_as_website_channel() {
        let fixture = google_pixel();
        let input = ParamsInput::new();
        verify_chain(&fixture.chain, &input.params(&fixture)).expect("valid chain");
    }

    #[test]
    fn grapheneos_capture_verifies_via_trusted_verified_boot_key() {
        let fixture = grapheneos();
        let input = ParamsInput::new();
        verify_chain(&fixture.chain, &input.params(&fixture)).expect("valid chain");
    }

    #[test]
    fn playstore_digest_is_accepted_without_claiming_store_installation() {
        // Swap the digest roles so the attested digest matches the configured
        // Play identity. Hardware attestation accepts it but cannot prove the
        // app's installation source.
        let fixture = google_pixel();
        let mut input = ParamsInput::new();
        input.playstore = digest(DEBUG_NIGHTLY_DIGEST);
        input.website = digest(PLAY_STORE_DIGEST);
        verify_chain(&fixture.chain, &input.params(&fixture)).expect("valid chain");
    }

    #[test]
    fn root_first_chain_order_is_tolerated() {
        let mut fixture = google_pixel();
        fixture.chain.reverse();
        let input = ParamsInput::new();
        assert!(verify_chain(&fixture.chain, &input.params(&fixture)).is_ok());
    }

    #[test]
    fn wrong_challenge_is_rejected() {
        let mut fixture = google_pixel();
        fixture.challenge = b"other-challenge".to_vec();
        let input = ParamsInput::new();
        assert!(matches!(
            verify_chain(&fixture.chain, &input.params(&fixture)),
            Err(KeyAttestError::Challenge)
        ));
    }

    #[test]
    fn foreign_package_is_rejected() {
        let mut fixture = google_pixel();
        fixture.packages = vec!["io.other.app".to_string()];
        let input = ParamsInput::new();
        assert!(matches!(
            verify_chain(&fixture.chain, &input.params(&fixture)),
            Err(KeyAttestError::Package(_))
        ));
    }

    #[test]
    fn unknown_signing_digest_is_rejected() {
        let fixture = google_pixel();
        let mut input = ParamsInput::new();
        input.website = [0u8; 32];
        assert!(matches!(
            verify_chain(&fixture.chain, &input.params(&fixture)),
            Err(KeyAttestError::SigningDigest(_))
        ));
    }

    #[test]
    fn revoked_serial_is_rejected() {
        let fixture = google_pixel();
        let mut input = ParamsInput::new();
        input.revoked.insert("1".to_string());
        assert!(matches!(
            verify_chain(&fixture.chain, &input.params(&fixture)),
            Err(KeyAttestError::Revoked(_))
        ));
    }

    #[test]
    fn expired_intermediates_are_rejected_outside_the_pinned_window() {
        let fixture = google_pixel();
        let mut input = ParamsInput::new();
        input.now = pinned_now() + 365 * 24 * 3600;
        assert!(matches!(
            verify_chain(&fixture.chain, &input.params(&fixture)),
            Err(KeyAttestError::Chain(_))
        ));
    }

    #[test]
    fn untrusted_roots_are_rejected() {
        let fixture = google_pixel();
        let mut input = ParamsInput::new();
        input.roots = vec![google_roots_der().remove(0)];
        assert!(matches!(
            verify_chain(&fixture.chain, &input.params(&fixture)),
            Err(KeyAttestError::RootNotTrusted)
        ));
    }

    #[test]
    fn selfsigned_boot_state_requires_a_pinned_verified_boot_key() {
        let fixture = grapheneos();
        let input = ParamsInput::new();
        let params = VerifyParams {
            trusted_verified_boot_keys: &[],
            ..input.params(&fixture)
        };
        assert!(matches!(
            verify_chain(&fixture.chain, &params),
            Err(KeyAttestError::RootOfTrust(_))
        ));
    }

    #[test]
    fn tampered_leaf_fails_signature_verification() {
        let mut fixture = google_pixel();
        let leaf = &mut fixture.chain[0];
        let position = leaf.len() / 2;
        leaf[position] ^= 0x01;
        let input = ParamsInput::new();
        let result = verify_chain(&fixture.chain, &input.params(&fixture));
        assert!(
            matches!(
                result,
                Err(KeyAttestError::Chain(_) | KeyAttestError::Malformed(_))
            ),
            "got {result:?}"
        );
    }

    #[test]
    fn parsed_extension_exposes_the_attested_fields() {
        let fixture = grapheneos();
        let (_, leaf) =
            x509_parser::certificate::X509Certificate::from_der(&fixture.chain[0]).unwrap();
        let ext = find_attestation_extension(&leaf).expect("leaf extension");
        let description = extension::parse(ext).expect("parses");

        assert_eq!(description.attestation_security_level, 1);
        assert_eq!(description.key_security_level, 1);
        assert_eq!(description.attestation_challenge, GRAPHENEOS_CHALLENGE);
        assert_eq!(
            description.package_names,
            vec!["io.pcf.polkadotapp.nightly".to_string()]
        );
        assert_eq!(
            description.signing_digests,
            vec![hex::decode(DEBUG_NIGHTLY_DIGEST).unwrap()]
        );
        let root_of_trust = description.root_of_trust.expect("root of trust");
        assert!(root_of_trust.device_locked);
        assert_eq!(root_of_trust.verified_boot_state, 1);
        assert_eq!(
            hex::encode(&root_of_trust.verified_boot_key),
            GRAPHENEOS_VERIFIED_BOOT_KEYS[0]
        );
    }

    #[test]
    fn policy_rejects_software_levels_unlocked_devices_and_bad_boot_states() {
        let make = |attestation_level: u64,
                    key_level: u64,
                    locked: bool,
                    boot_state: u64|
         -> KeyDescription {
            KeyDescription {
                attestation_security_level: attestation_level,
                key_security_level: key_level,
                attestation_challenge: b"challenge".to_vec(),
                package_names: vec!["io.pcf.polkadotapp".to_string()],
                signing_digests: vec![digest(PLAY_STORE_DIGEST).to_vec()],
                root_of_trust: Some(extension::RootOfTrust {
                    verified_boot_key: vec![0u8; 32],
                    device_locked: locked,
                    verified_boot_state: boot_state,
                }),
            }
        };
        let input = ParamsInput::new();
        let challenge = b"challenge".to_vec();
        let packages = vec!["io.pcf.polkadotapp".to_string()];
        let params = VerifyParams {
            challenge: &challenge,
            package_names: &packages,
            playstore_digest: &input.playstore,
            website_digest: &input.website,
            trusted_roots_der: &input.roots,
            trusted_verified_boot_keys: &[],
            revoked_serials: &input.revoked,
            now_unix: input.now,
        };

        assert!(matches!(
            check_policy(&make(1, 1, true, 0), &params),
            Ok(())
        ));
        let mut no_digest = make(1, 1, true, 0);
        no_digest.signing_digests.clear();
        assert!(matches!(
            check_policy(&no_digest, &params),
            Err(KeyAttestError::SigningDigest(ref reason))
                if reason == "expected one attested digest, got 0"
        ));
        let mut mixed_known = make(1, 1, true, 0);
        mixed_known.signing_digests.push(input.website.to_vec());
        assert!(matches!(
            check_policy(&mixed_known, &params),
            Err(KeyAttestError::SigningDigest(_))
        ));
        let mut mixed_unknown = make(1, 1, true, 0);
        mixed_unknown.signing_digests.push(vec![0x77; 32]);
        assert!(matches!(
            check_policy(&mixed_unknown, &params),
            Err(KeyAttestError::SigningDigest(_))
        ));
        assert!(matches!(
            check_policy(&make(0, 1, true, 0), &params),
            Err(KeyAttestError::SecurityLevel { .. })
        ));
        assert!(matches!(
            check_policy(&make(1, 0, true, 0), &params),
            Err(KeyAttestError::SecurityLevel { .. })
        ));
        assert!(matches!(
            check_policy(&make(2, 2, true, 0), &params),
            Ok(())
        ));
        assert!(matches!(
            check_policy(&make(3, 1, true, 0), &params),
            Err(KeyAttestError::SecurityLevel { .. })
        ));
        assert!(matches!(
            check_policy(&make(1, 3, true, 0), &params),
            Err(KeyAttestError::SecurityLevel { .. })
        ));
        assert!(matches!(
            check_policy(&make(1, 1, false, 0), &params),
            Err(KeyAttestError::RootOfTrust(_))
        ));
        assert!(matches!(
            check_policy(&make(1, 1, true, 2), &params),
            Err(KeyAttestError::RootOfTrust(_))
        ));
        assert!(matches!(
            check_policy(&make(1, 1, true, 3), &params),
            Err(KeyAttestError::RootOfTrust(_))
        ));
        let mut missing = make(1, 1, true, 0);
        missing.root_of_trust = None;
        assert!(matches!(
            check_policy(&missing, &params),
            Err(KeyAttestError::RootOfTrust(_))
        ));
    }

    #[test]
    fn known_public_avb_test_keys_are_denied_even_when_verified() {
        let input = ParamsInput::new();
        let challenge = b"challenge".to_vec();
        let packages = vec!["io.pcf.polkadotapp".to_string()];
        let params = VerifyParams {
            challenge: &challenge,
            package_names: &packages,
            playstore_digest: &input.playstore,
            website_digest: &input.website,
            trusted_roots_der: &input.roots,
            // Even an explicitly trusted SelfSigned entry must not resurrect a
            // denylisted key: the denylist wins over the allowlist.
            trusted_verified_boot_keys: KNOWN_PUBLIC_VERIFIED_BOOT_KEYS,
            revoked_serials: &input.revoked,
            now_unix: input.now,
        };
        for key in KNOWN_PUBLIC_VERIFIED_BOOT_KEYS {
            for boot_state in [BOOT_STATE_VERIFIED, BOOT_STATE_SELF_SIGNED] {
                let description = KeyDescription {
                    attestation_security_level: 1,
                    key_security_level: 1,
                    attestation_challenge: challenge.clone(),
                    package_names: packages.clone(),
                    signing_digests: vec![digest(PLAY_STORE_DIGEST).to_vec()],
                    root_of_trust: Some(extension::RootOfTrust {
                        verified_boot_key: hex::decode(key).expect("valid hex"),
                        device_locked: true,
                        verified_boot_state: boot_state,
                    }),
                };
                assert!(matches!(
                    check_policy(&description, &params),
                    Err(KeyAttestError::RootOfTrust(ref reason))
                        if reason.contains("known-public AVB test key")
                ));
            }
        }
    }

    #[test]
    fn extension_on_a_non_leaf_certificate_is_rejected() {
        let fixture = google_pixel();
        let mut chain = fixture.chain.clone();
        chain.insert(1, chain[0].clone());
        let input = ParamsInput::new();
        assert!(verify_chain(&chain, &input.params(&fixture)).is_err());
    }
}
