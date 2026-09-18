# Third-party notices
Device Uniqueness Backend is licensed under [GPL-3.0-only](LICENSE). It builds
against the third-party crates listed below, each under its own licence.

This file is an inventory of the **licences those crates declare** in their
`Cargo.toml`, generated from `cargo metadata` over the committed `Cargo.lock`.
It is not a substitute for the licence texts themselves: each crate's full terms
ship in its source, which `cargo vendor` will place under `vendor/<crate>/`, and
are published at the repository link beside it.

`cargo deny check licenses` gates this set against the allow list in
[`deny.toml`](deny.toml), so a dependency arriving under an unreviewed licence
fails CI rather than landing quietly. Regenerate this file whenever `Cargo.lock`
changes.

**585 third-party crates** across 33 declared licence expressions.

## Licences in use

| Licence | Crates |
| --- | ---: |
| `MIT OR Apache-2.0` | 261 |
| `MIT` | 99 |
| `Apache-2.0 OR MIT` | 59 |
| `MIT/Apache-2.0` | 40 |
| `Apache-2.0` | 29 |
| `Unicode-3.0` | 18 |
| `CC0-1.0` | 11 |
| `Apache-2.0 OR GPL-3.0` | 9 |
| `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 6 |
| `BSD-3-Clause` | 6 |
| `Zlib` | 6 |
| `CDLA-Permissive-2.0` | 4 |
| `Unlicense OR MIT` | 4 |
| `Apache-2.0 OR ISC OR MIT` | 3 |
| `Apache-2.0/MIT` | 3 |
| `GPL-3.0-or-later WITH Classpath-exception-2.0` | 3 |
| `ISC` | 3 |
| `Apache-2.0 OR BSL-1.0 OR MIT` | 2 |
| `BSD-2-Clause OR Apache-2.0 OR MIT` | 2 |
| `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | 2 |
| `MIT OR Apache-2.0 OR Zlib` | 2 |
| `Unlicense/MIT` | 2 |
| `(MIT OR Apache-2.0) AND Apache-2.0` | 1 |
| `(MIT OR Apache-2.0) AND Unicode-3.0` | 1 |
| `Apache-2.0 / MIT` | 1 |
| `Apache-2.0 AND ISC` | 1 |
| `Apache-2.0 OR BSL-1.0` | 1 |
| `BSD-2-Clause` | 1 |
| `CC0-1.0 OR MIT-0 OR Apache-2.0` | 1 |
| `MIT AND Apache-2.0` | 1 |
| `MIT AND BSD-3-Clause` | 1 |
| `MIT OR Apache-2.0 OR BSD-1-Clause` | 1 |
| `Zlib OR Apache-2.0 OR MIT` | 1 |

## Crates

| Crate | Version | Licence | Source |
| --- | --- | --- | --- |
| `aead` | 0.5.2 | `MIT OR Apache-2.0` | [github.com/RustCrypto/traits](https://github.com/RustCrypto/traits) |
| `aes` | 0.8.4 | `MIT OR Apache-2.0` | [github.com/RustCrypto/block-ciphers](https://github.com/RustCrypto/block-ciphers) |
| `aes-gcm` | 0.10.3 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/AEADs](https://github.com/RustCrypto/AEADs) |
| `aes-kw` | 0.2.1 | `MIT OR Apache-2.0` | [github.com/RustCrypto/key-wraps/tree/aes-kw](https://github.com/RustCrypto/key-wraps/tree/aes-kw) |
| `ahash` | 0.8.12 | `MIT OR Apache-2.0` | [github.com/tkaitchuck/ahash](https://github.com/tkaitchuck/ahash) |
| `aho-corasick` | 1.1.4 | `Unlicense OR MIT` | [github.com/BurntSushi/aho-corasick](https://github.com/BurntSushi/aho-corasick) |
| `allocator-api2` | 0.2.21 | `MIT OR Apache-2.0` | [github.com/zakarumych/allocator-api2](https://github.com/zakarumych/allocator-api2) |
| `anyhow` | 1.0.103 | `MIT OR Apache-2.0` | [github.com/dtolnay/anyhow](https://github.com/dtolnay/anyhow) |
| `ark-bls12-381` | 0.5.0 | `MIT OR Apache-2.0` | [github.com/arkworks-rs/algebra](https://github.com/arkworks-rs/algebra) |
| `ark-ec` | 0.5.0 | `MIT OR Apache-2.0` | [github.com/arkworks-rs/algebra](https://github.com/arkworks-rs/algebra) |
| `ark-ed-on-bls12-381-bandersnatch` | 0.5.0 | `MIT OR Apache-2.0` | [github.com/arkworks-rs/algebra](https://github.com/arkworks-rs/algebra) |
| `ark-ff` | 0.5.0 | `MIT OR Apache-2.0` | [github.com/arkworks-rs/algebra](https://github.com/arkworks-rs/algebra) |
| `ark-ff-asm` | 0.5.0 | `MIT OR Apache-2.0` | [github.com/arkworks-rs/algebra](https://github.com/arkworks-rs/algebra) |
| `ark-ff-macros` | 0.5.0 | `MIT OR Apache-2.0` | [github.com/arkworks-rs/algebra](https://github.com/arkworks-rs/algebra) |
| `ark-poly` | 0.5.0 | `MIT OR Apache-2.0` | [github.com/arkworks-rs/algebra](https://github.com/arkworks-rs/algebra) |
| `ark-scale` | 0.0.13 | `MIT/Apache-2.0` | [github.com/w3f/ark-scale](https://github.com/w3f/ark-scale) |
| `ark-serialize` | 0.5.0 | `MIT OR Apache-2.0` | [github.com/arkworks-rs/algebra](https://github.com/arkworks-rs/algebra) |
| `ark-serialize-derive` | 0.5.0 | `MIT OR Apache-2.0` | [github.com/arkworks-rs/algebra](https://github.com/arkworks-rs/algebra) |
| `ark-std` | 0.5.0 | `MIT/Apache-2.0` | [github.com/arkworks-rs/std](https://github.com/arkworks-rs/std) |
| `ark-transcript` | 0.0.3 | `MIT/Apache-2.0` | [github.com/w3f/ark-transcript](https://github.com/w3f/ark-transcript) |
| `ark-vrf` | 0.5.1 | `MIT` | [github.com/davxy/ark-vrf](https://github.com/davxy/ark-vrf) |
| `arrayref` | 0.3.9 | `BSD-2-Clause` | [github.com/droundy/arrayref](https://github.com/droundy/arrayref) |
| `arrayvec` | 0.4.12 | `MIT/Apache-2.0` | [github.com/bluss/arrayvec](https://github.com/bluss/arrayvec) |
| `arrayvec` | 0.7.8 | `MIT OR Apache-2.0` | [github.com/bluss/arrayvec](https://github.com/bluss/arrayvec) |
| `asn1-rs` | 0.7.2 | `MIT OR Apache-2.0` | [github.com/rusticata/asn1-rs.git](https://github.com/rusticata/asn1-rs.git) |
| `asn1-rs-derive` | 0.6.0 | `MIT OR Apache-2.0` | [github.com/rusticata/asn1-rs.git](https://github.com/rusticata/asn1-rs.git) |
| `asn1-rs-impl` | 0.2.0 | `MIT/Apache-2.0` | [github.com/rusticata/asn1-rs.git](https://github.com/rusticata/asn1-rs.git) |
| `async-channel` | 2.5.0 | `Apache-2.0 OR MIT` | [github.com/smol-rs/async-channel](https://github.com/smol-rs/async-channel) |
| `async-executor` | 1.14.0 | `Apache-2.0 OR MIT` | [github.com/smol-rs/async-executor](https://github.com/smol-rs/async-executor) |
| `async-fs` | 2.2.0 | `Apache-2.0 OR MIT` | [github.com/smol-rs/async-fs](https://github.com/smol-rs/async-fs) |
| `async-io` | 2.6.0 | `Apache-2.0 OR MIT` | [github.com/smol-rs/async-io](https://github.com/smol-rs/async-io) |
| `async-lock` | 3.4.2 | `Apache-2.0 OR MIT` | [github.com/smol-rs/async-lock](https://github.com/smol-rs/async-lock) |
| `async-net` | 2.0.0 | `Apache-2.0 OR MIT` | [github.com/smol-rs/async-net](https://github.com/smol-rs/async-net) |
| `async-process` | 2.5.0 | `Apache-2.0 OR MIT` | [github.com/smol-rs/async-process](https://github.com/smol-rs/async-process) |
| `async-signal` | 0.2.14 | `Apache-2.0 OR MIT` | [github.com/smol-rs/async-signal](https://github.com/smol-rs/async-signal) |
| `async-task` | 4.7.1 | `Apache-2.0 OR MIT` | [github.com/smol-rs/async-task](https://github.com/smol-rs/async-task) |
| `async-trait` | 0.1.89 | `MIT OR Apache-2.0` | [github.com/dtolnay/async-trait](https://github.com/dtolnay/async-trait) |
| `atoi` | 2.0.0 | `MIT` | [github.com/pacman82/atoi-rs](https://github.com/pacman82/atoi-rs) |
| `atomic-take` | 1.1.0 | `MIT` | [github.com/Darksonn/atomic-take](https://github.com/Darksonn/atomic-take) |
| `atomic-waker` | 1.1.2 | `Apache-2.0 OR MIT` | [github.com/smol-rs/atomic-waker](https://github.com/smol-rs/atomic-waker) |
| `autocfg` | 1.5.1 | `Apache-2.0 OR MIT` | [github.com/cuviper/autocfg](https://github.com/cuviper/autocfg) |
| `axum` | 0.8.9 | `MIT` | [github.com/tokio-rs/axum](https://github.com/tokio-rs/axum) |
| `axum-core` | 0.5.6 | `MIT` | [github.com/tokio-rs/axum](https://github.com/tokio-rs/axum) |
| `base16ct` | 0.2.0 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/formats/tree/master/base16ct](https://github.com/RustCrypto/formats/tree/master/base16ct) |
| `base32` | 0.5.1 | `MIT OR Apache-2.0` | [github.com/andreasots/base32](https://github.com/andreasots/base32) |
| `base58` | 0.2.0 | `MIT` | [github.com/debris/base58](https://github.com/debris/base58) |
| `base64` | 0.22.1 | `MIT OR Apache-2.0` | [github.com/marshallpierce/rust-base64](https://github.com/marshallpierce/rust-base64) |
| `base64ct` | 1.8.3 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/formats](https://github.com/RustCrypto/formats) |
| `bip39` | 2.2.2 | `CC0-1.0` | [github.com/rust-bitcoin/rust-bip39](https://github.com/rust-bitcoin/rust-bip39/) |
| `bitcoin-consensus-encoding` | 1.0.0 | `CC0-1.0` | [github.com/rust-bitcoin/rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin/) |
| `bitcoin-internals` | 0.5.0 | `CC0-1.0` | [github.com/rust-bitcoin/rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin/) |
| `bitcoin-io` | 0.1.101 | `CC0-1.0` | [github.com/rust-bitcoin/rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) |
| `bitcoin_hashes` | 0.14.101 | `CC0-1.0` | [github.com/rust-bitcoin/rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) |
| `bitflags` | 2.13.0 | `MIT OR Apache-2.0` | [github.com/bitflags/bitflags](https://github.com/bitflags/bitflags) |
| `bitvec` | 1.1.1 | `MIT` | [github.com/bitvecto-rs/bitvec](https://github.com/bitvecto-rs/bitvec) |
| `blake2` | 0.10.6 | `MIT OR Apache-2.0` | [github.com/RustCrypto/hashes](https://github.com/RustCrypto/hashes) |
| `blake2-rfc` | 0.2.18 | `MIT OR Apache-2.0` | [github.com/cesarb/blake2-rfc](https://github.com/cesarb/blake2-rfc) |
| `blake2b_simd` | 1.0.4 | `MIT` | [github.com/oconnor663/blake2_simd](https://github.com/oconnor663/blake2_simd) |
| `block-buffer` | 0.10.4 | `MIT OR Apache-2.0` | [github.com/RustCrypto/utils](https://github.com/RustCrypto/utils) |
| `block-buffer` | 0.9.0 | `MIT OR Apache-2.0` | [github.com/RustCrypto/utils](https://github.com/RustCrypto/utils) |
| `blocking` | 1.6.2 | `Apache-2.0 OR MIT` | [github.com/smol-rs/blocking](https://github.com/smol-rs/blocking) |
| `bounded-collections` | 0.3.2 | `MIT OR Apache-2.0` | [github.com/paritytech/parity-common](https://github.com/paritytech/parity-common) |
| `bs58` | 0.5.1 | `MIT/Apache-2.0` | [github.com/Nullus157/bs58-rs](https://github.com/Nullus157/bs58-rs) |
| `bumpalo` | 3.20.3 | `MIT OR Apache-2.0` | [github.com/fitzgen/bumpalo](https://github.com/fitzgen/bumpalo) |
| `byte-slice-cast` | 1.2.3 | `MIT` | [github.com/sdroege/bytes-num-slice-cast](https://github.com/sdroege/bytes-num-slice-cast) |
| `byteorder` | 1.5.0 | `Unlicense OR MIT` | [github.com/BurntSushi/byteorder](https://github.com/BurntSushi/byteorder) |
| `bytes` | 1.12.0 | `MIT` | [github.com/tokio-rs/bytes](https://github.com/tokio-rs/bytes) |
| `cc` | 1.2.65 | `MIT OR Apache-2.0` | [github.com/rust-lang/cc-rs](https://github.com/rust-lang/cc-rs) |
| `cesu8` | 1.1.0 | `Apache-2.0/MIT` | [github.com/emk/cesu8-rs](https://github.com/emk/cesu8-rs) |
| `cfg-if` | 1.0.4 | `MIT OR Apache-2.0` | [github.com/rust-lang/cfg-if](https://github.com/rust-lang/cfg-if) |
| `cfg_aliases` | 0.2.1 | `MIT` | [github.com/katharostech/cfg_aliases](https://github.com/katharostech/cfg_aliases) |
| `chacha20` | 0.10.1 | `MIT OR Apache-2.0` | [github.com/RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers) |
| `chacha20` | 0.9.1 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers) |
| `ciborium` | 0.2.2 | `Apache-2.0` | [github.com/enarx/ciborium](https://github.com/enarx/ciborium) |
| `ciborium-io` | 0.2.2 | `Apache-2.0` | [github.com/enarx/ciborium](https://github.com/enarx/ciborium) |
| `ciborium-ll` | 0.2.2 | `Apache-2.0` | [github.com/enarx/ciborium](https://github.com/enarx/ciborium) |
| `cipher` | 0.4.4 | `MIT OR Apache-2.0` | [github.com/RustCrypto/traits](https://github.com/RustCrypto/traits) |
| `client-ip` | 0.2.1 | `MIT` | [github.com/imbolc/client-ip](https://github.com/imbolc/client-ip) |
| `combine` | 4.6.7 | `MIT` | [github.com/Marwes/combine](https://github.com/Marwes/combine) |
| `concurrent-queue` | 2.5.0 | `Apache-2.0 OR MIT` | [github.com/smol-rs/concurrent-queue](https://github.com/smol-rs/concurrent-queue) |
| `const-oid` | 0.9.6 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/formats/tree/master/const-oid](https://github.com/RustCrypto/formats/tree/master/const-oid) |
| `const_format` | 0.2.36 | `Zlib` | [github.com/rodrimati1992/const_format_crates](https://github.com/rodrimati1992/const_format_crates/) |
| `const_format_proc_macros` | 0.2.34 | `Zlib` | [github.com/rodrimati1992/const_format_crates](https://github.com/rodrimati1992/const_format_crates/) |
| `constant_time_eq` | 0.1.5 | `CC0-1.0` | [github.com/cesarb/constant_time_eq](https://github.com/cesarb/constant_time_eq) |
| `constant_time_eq` | 0.4.2 | `CC0-1.0 OR MIT-0 OR Apache-2.0` | [github.com/cesarb/constant_time_eq](https://github.com/cesarb/constant_time_eq) |
| `convert_case` | 0.10.0 | `MIT` | [github.com/rutrum/convert-case](https://github.com/rutrum/convert-case) |
| `core-foundation` | 0.10.1 | `MIT OR Apache-2.0` | [github.com/servo/core-foundation-rs](https://github.com/servo/core-foundation-rs) |
| `core-foundation-sys` | 0.8.7 | `MIT OR Apache-2.0` | [github.com/servo/core-foundation-rs](https://github.com/servo/core-foundation-rs) |
| `cpufeatures` | 0.2.17 | `MIT OR Apache-2.0` | [github.com/RustCrypto/utils](https://github.com/RustCrypto/utils) |
| `cpufeatures` | 0.3.0 | `MIT OR Apache-2.0` | [github.com/RustCrypto/utils](https://github.com/RustCrypto/utils) |
| `crc` | 3.4.0 | `MIT OR Apache-2.0` | [github.com/mrhooray/crc-rs.git](https://github.com/mrhooray/crc-rs.git) |
| `crc-catalog` | 2.5.0 | `MIT OR Apache-2.0` | [github.com/akhilles/crc-catalog.git](https://github.com/akhilles/crc-catalog.git) |
| `crossbeam-channel` | 0.5.16 | `MIT OR Apache-2.0` | [github.com/crossbeam-rs/crossbeam](https://github.com/crossbeam-rs/crossbeam) |
| `crossbeam-deque` | 0.8.7 | `MIT OR Apache-2.0` | [github.com/crossbeam-rs/crossbeam](https://github.com/crossbeam-rs/crossbeam) |
| `crossbeam-epoch` | 0.9.20 | `MIT OR Apache-2.0` | [github.com/crossbeam-rs/crossbeam](https://github.com/crossbeam-rs/crossbeam) |
| `crossbeam-queue` | 0.3.12 | `MIT OR Apache-2.0` | [github.com/crossbeam-rs/crossbeam](https://github.com/crossbeam-rs/crossbeam) |
| `crossbeam-utils` | 0.8.21 | `MIT OR Apache-2.0` | [github.com/crossbeam-rs/crossbeam](https://github.com/crossbeam-rs/crossbeam) |
| `crunchy` | 0.2.4 | `MIT` | [github.com/eira-fransham/crunchy](https://github.com/eira-fransham/crunchy) |
| `crypto-bigint` | 0.5.5 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/crypto-bigint](https://github.com/RustCrypto/crypto-bigint) |
| `crypto-common` | 0.1.7 | `MIT OR Apache-2.0` | [github.com/RustCrypto/traits](https://github.com/RustCrypto/traits) |
| `crypto-mac` | 0.8.0 | `MIT OR Apache-2.0` | [github.com/RustCrypto/traits](https://github.com/RustCrypto/traits) |
| `crypto_secretbox` | 0.1.1 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/nacl-compat/tree/master/crypto_secretbox](https://github.com/RustCrypto/nacl-compat/tree/master/crypto_secretbox) |
| `ctr` | 0.9.2 | `MIT OR Apache-2.0` | [github.com/RustCrypto/block-modes](https://github.com/RustCrypto/block-modes) |
| `curve25519-dalek` | 4.1.3 | `BSD-3-Clause` | [github.com/dalek-cryptography/curve25519-dalek/tree/main/curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/curve25519-dalek) |
| `curve25519-dalek-derive` | 0.1.1 | `MIT/Apache-2.0` | [github.com/dalek-cryptography/curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) |
| `darling` | 0.20.11 | `MIT` | [github.com/TedDriggs/darling](https://github.com/TedDriggs/darling) |
| `darling_core` | 0.20.11 | `MIT` | [github.com/TedDriggs/darling](https://github.com/TedDriggs/darling) |
| `darling_macro` | 0.20.11 | `MIT` | [github.com/TedDriggs/darling](https://github.com/TedDriggs/darling) |
| `dashmap` | 6.2.1 | `MIT` | [github.com/xacrimon/dashmap](https://github.com/xacrimon/dashmap) |
| `data-encoding` | 2.11.0 | `MIT` | [github.com/ia0/data-encoding](https://github.com/ia0/data-encoding) |
| `der` | 0.7.10 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/formats/tree/master/der](https://github.com/RustCrypto/formats/tree/master/der) |
| `der-parser` | 10.0.0 | `MIT OR Apache-2.0` | [github.com/rusticata/der-parser.git](https://github.com/rusticata/der-parser.git) |
| `deranged` | 0.5.8 | `MIT OR Apache-2.0` | [github.com/jhpratt/deranged](https://github.com/jhpratt/deranged) |
| `derive-where` | 1.6.1 | `MIT OR Apache-2.0` | [github.com/ModProg/derive-where](https://github.com/ModProg/derive-where) |
| `derive_more` | 1.0.0 | `MIT` | [github.com/JelteF/derive_more](https://github.com/JelteF/derive_more) |
| `derive_more` | 2.1.1 | `MIT` | [github.com/JelteF/derive_more](https://github.com/JelteF/derive_more) |
| `derive_more-impl` | 1.0.0 | `MIT` | [github.com/JelteF/derive_more](https://github.com/JelteF/derive_more) |
| `derive_more-impl` | 2.1.1 | `MIT` | [github.com/JelteF/derive_more](https://github.com/JelteF/derive_more) |
| `digest` | 0.10.7 | `MIT OR Apache-2.0` | [github.com/RustCrypto/traits](https://github.com/RustCrypto/traits) |
| `digest` | 0.9.0 | `MIT OR Apache-2.0` | [github.com/RustCrypto/traits](https://github.com/RustCrypto/traits) |
| `displaydoc` | 0.2.6 | `MIT OR Apache-2.0` | [github.com/yaahc/displaydoc](https://github.com/yaahc/displaydoc) |
| `dotenvy` | 0.15.7 | `MIT` | [github.com/allan2/dotenvy](https://github.com/allan2/dotenvy) |
| `downcast-rs` | 1.2.1 | `MIT/Apache-2.0` | [github.com/marcianx/downcast-rs](https://github.com/marcianx/downcast-rs) |
| `ecdsa` | 0.16.9 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/signatures/tree/master/ecdsa](https://github.com/RustCrypto/signatures/tree/master/ecdsa) |
| `ed25519` | 2.2.3 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/signatures/tree/master/ed25519](https://github.com/RustCrypto/signatures/tree/master/ed25519) |
| `ed25519-dalek` | 2.2.0 | `BSD-3-Clause` | [github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek) |
| `ed25519-zebra` | 4.2.0 | `MIT OR Apache-2.0` | [github.com/ZcashFoundation/ed25519-zebra](https://github.com/ZcashFoundation/ed25519-zebra) |
| `educe` | 0.6.0 | `MIT` | [github.com/magiclen/educe](https://github.com/magiclen/educe) |
| `either` | 1.16.0 | `MIT OR Apache-2.0` | [github.com/rayon-rs/either](https://github.com/rayon-rs/either) |
| `elliptic-curve` | 0.13.8 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/traits/tree/master/elliptic-curve](https://github.com/RustCrypto/traits/tree/master/elliptic-curve) |
| `enum-ordinalize` | 4.4.2 | `MIT` | [github.com/magiclen/enum-ordinalize](https://github.com/magiclen/enum-ordinalize) |
| `enum-ordinalize-derive` | 4.4.2 | `MIT` | [github.com/magiclen/enum-ordinalize](https://github.com/magiclen/enum-ordinalize) |
| `equivalent` | 1.0.2 | `Apache-2.0 OR MIT` | [github.com/indexmap-rs/equivalent](https://github.com/indexmap-rs/equivalent) |
| `errno` | 0.3.14 | `MIT OR Apache-2.0` | [github.com/lambda-fairy/rust-errno](https://github.com/lambda-fairy/rust-errno) |
| `etcetera` | 0.8.0 | `MIT OR Apache-2.0` | [github.com/lunacookies/etcetera](https://github.com/lunacookies/etcetera) |
| `event-listener` | 5.4.1 | `Apache-2.0 OR MIT` | [github.com/smol-rs/event-listener](https://github.com/smol-rs/event-listener) |
| `event-listener-strategy` | 0.5.4 | `Apache-2.0 OR MIT` | [github.com/smol-rs/event-listener-strategy](https://github.com/smol-rs/event-listener-strategy) |
| `evmap` | 11.0.0 | `MIT OR Apache-2.0` | [github.com/jonhoo/evmap.git](https://github.com/jonhoo/evmap.git) |
| `fastbloom` | 0.17.0 | `MIT OR Apache-2.0` | [github.com/tomtomwombat/fastbloom](https://github.com/tomtomwombat/fastbloom/) |
| `fastrand` | 2.4.1 | `Apache-2.0 OR MIT` | [github.com/smol-rs/fastrand](https://github.com/smol-rs/fastrand) |
| `ff` | 0.13.1 | `MIT/Apache-2.0` | [github.com/zkcrypto/ff](https://github.com/zkcrypto/ff) |
| `fiat-crypto` | 0.2.9 | `MIT OR Apache-2.0 OR BSD-1-Clause` | [github.com/mit-plv/fiat-crypto](https://github.com/mit-plv/fiat-crypto) |
| `find-msvc-tools` | 0.1.9 | `MIT OR Apache-2.0` | [github.com/rust-lang/cc-rs](https://github.com/rust-lang/cc-rs) |
| `finito` | 0.1.0 | `MIT` | [github.com/niklasad1/finito](https://github.com/niklasad1/finito) |
| `fixed-hash` | 0.8.0 | `MIT OR Apache-2.0` | [github.com/paritytech/parity-common](https://github.com/paritytech/parity-common) |
| `flume` | 0.11.1 | `Apache-2.0/MIT` | [github.com/zesterer/flume](https://github.com/zesterer/flume) |
| `fnv` | 1.0.7 | `Apache-2.0 / MIT` | [github.com/servo/rust-fnv](https://github.com/servo/rust-fnv) |
| `foldhash` | 0.1.5 | `Zlib` | [github.com/orlp/foldhash](https://github.com/orlp/foldhash) |
| `foldhash` | 0.2.0 | `Zlib` | [github.com/orlp/foldhash](https://github.com/orlp/foldhash) |
| `form_urlencoded` | 1.2.2 | `MIT OR Apache-2.0` | [github.com/servo/rust-url](https://github.com/servo/rust-url) |
| `frame-decode` | 0.18.1 | `Apache-2.0` | [github.com/paritytech/frame-decode](https://github.com/paritytech/frame-decode) |
| `frame-metadata` | 23.0.1 | `Apache-2.0` | [github.com/paritytech/frame-metadata](https://github.com/paritytech/frame-metadata/) |
| `funty` | 2.0.0 | `MIT` | [github.com/myrrlyn/funty](https://github.com/myrrlyn/funty) |
| `futures` | 0.3.32 | `MIT OR Apache-2.0` | [github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) |
| `futures-channel` | 0.3.32 | `MIT OR Apache-2.0` | [github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) |
| `futures-core` | 0.3.32 | `MIT OR Apache-2.0` | [github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) |
| `futures-executor` | 0.3.32 | `MIT OR Apache-2.0` | [github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) |
| `futures-intrusive` | 0.5.0 | `MIT OR Apache-2.0` | [github.com/Matthias247/futures-intrusive](https://github.com/Matthias247/futures-intrusive) |
| `futures-io` | 0.3.32 | `MIT OR Apache-2.0` | [github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) |
| `futures-lite` | 2.6.1 | `Apache-2.0 OR MIT` | [github.com/smol-rs/futures-lite](https://github.com/smol-rs/futures-lite) |
| `futures-macro` | 0.3.32 | `MIT OR Apache-2.0` | [github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) |
| `futures-sink` | 0.3.32 | `MIT OR Apache-2.0` | [github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) |
| `futures-task` | 0.3.32 | `MIT OR Apache-2.0` | [github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) |
| `futures-timer` | 3.0.4 | `MIT/Apache-2.0` | [github.com/async-rs/futures-timer](https://github.com/async-rs/futures-timer) |
| `futures-util` | 0.3.32 | `MIT OR Apache-2.0` | [github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) |
| `generator` | 0.8.9 | `MIT/Apache-2.0` | [github.com/Xudong-Huang/generator-rs.git](https://github.com/Xudong-Huang/generator-rs.git) |
| `generic-array` | 0.14.7 | `MIT` | [github.com/fizyk20/generic-array.git](https://github.com/fizyk20/generic-array.git) |
| `getrandom` | 0.2.17 | `MIT OR Apache-2.0` | [github.com/rust-random/getrandom](https://github.com/rust-random/getrandom) |
| `getrandom` | 0.3.4 | `MIT OR Apache-2.0` | [github.com/rust-random/getrandom](https://github.com/rust-random/getrandom) |
| `getrandom` | 0.4.3 | `MIT OR Apache-2.0` | [github.com/rust-random/getrandom](https://github.com/rust-random/getrandom) |
| `getrandom_or_panic` | 0.0.3 | `BSD-3-Clause` | [github.com/burdges/getrandom_or_panic](https://github.com/burdges/getrandom_or_panic) |
| `ghash` | 0.5.1 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/universal-hashes](https://github.com/RustCrypto/universal-hashes) |
| `governor` | 0.10.4 | `MIT` | [github.com/boinkor-net/governor.git](https://github.com/boinkor-net/governor.git) |
| `group` | 0.13.0 | `MIT/Apache-2.0` | [github.com/zkcrypto/group](https://github.com/zkcrypto/group) |
| `h2` | 0.4.19 | `MIT` | [github.com/hyperium/h2](https://github.com/hyperium/h2) |
| `half` | 2.7.1 | `MIT OR Apache-2.0` | [github.com/VoidStarKat/half-rs](https://github.com/VoidStarKat/half-rs) |
| `hashbag` | 0.1.13 | `MIT OR Apache-2.0` | [github.com/jonhoo/hashbag.git](https://github.com/jonhoo/hashbag.git) |
| `hashbrown` | 0.14.5 | `MIT OR Apache-2.0` | [github.com/rust-lang/hashbrown](https://github.com/rust-lang/hashbrown) |
| `hashbrown` | 0.15.5 | `MIT OR Apache-2.0` | [github.com/rust-lang/hashbrown](https://github.com/rust-lang/hashbrown) |
| `hashbrown` | 0.16.1 | `MIT OR Apache-2.0` | [github.com/rust-lang/hashbrown](https://github.com/rust-lang/hashbrown) |
| `hashbrown` | 0.17.1 | `MIT OR Apache-2.0` | [github.com/rust-lang/hashbrown](https://github.com/rust-lang/hashbrown) |
| `hashlink` | 0.10.0 | `MIT OR Apache-2.0` | [github.com/kyren/hashlink](https://github.com/kyren/hashlink) |
| `heck` | 0.5.0 | `MIT OR Apache-2.0` | [github.com/withoutboats/heck](https://github.com/withoutboats/heck) |
| `hermit-abi` | 0.5.2 | `MIT OR Apache-2.0` | [github.com/hermit-os/hermit-rs](https://github.com/hermit-os/hermit-rs) |
| `hex` | 0.4.3 | `MIT OR Apache-2.0` | [github.com/KokaKiwi/rust-hex](https://github.com/KokaKiwi/rust-hex) |
| `hex-conservative` | 0.2.2 | `CC0-1.0` | [github.com/rust-bitcoin/hex-conservative](https://github.com/rust-bitcoin/hex-conservative) |
| `hex-conservative` | 0.3.2 | `CC0-1.0` | [github.com/rust-bitcoin/hex-conservative](https://github.com/rust-bitcoin/hex-conservative) |
| `hkdf` | 0.12.4 | `MIT OR Apache-2.0` | [github.com/RustCrypto/KDFs](https://github.com/RustCrypto/KDFs/) |
| `hmac` | 0.12.1 | `MIT OR Apache-2.0` | [github.com/RustCrypto/MACs](https://github.com/RustCrypto/MACs) |
| `hmac` | 0.8.1 | `MIT OR Apache-2.0` | [github.com/RustCrypto/MACs](https://github.com/RustCrypto/MACs) |
| `hmac-drbg` | 0.3.0 | `Apache-2.0` | — |
| `home` | 0.5.12 | `MIT OR Apache-2.0` | [github.com/rust-lang/cargo](https://github.com/rust-lang/cargo) |
| `http` | 1.4.2 | `MIT OR Apache-2.0` | [github.com/hyperium/http](https://github.com/hyperium/http) |
| `http-body` | 1.0.1 | `MIT` | [github.com/hyperium/http-body](https://github.com/hyperium/http-body) |
| `http-body-util` | 0.1.3 | `MIT` | [github.com/hyperium/http-body](https://github.com/hyperium/http-body) |
| `http-range-header` | 0.4.2 | `MIT` | [github.com/MarcusGrass/parse-range-headers](https://github.com/MarcusGrass/parse-range-headers) |
| `httparse` | 1.10.1 | `MIT OR Apache-2.0` | [github.com/seanmonstar/httparse](https://github.com/seanmonstar/httparse) |
| `httpdate` | 1.0.3 | `MIT OR Apache-2.0` | [github.com/pyfisch/httpdate](https://github.com/pyfisch/httpdate) |
| `hyper` | 1.10.1 | `MIT` | [github.com/hyperium/hyper](https://github.com/hyperium/hyper) |
| `hyper-rustls` | 0.27.9 | `Apache-2.0 OR ISC OR MIT` | [github.com/rustls/hyper-rustls](https://github.com/rustls/hyper-rustls) |
| `hyper-util` | 0.1.20 | `MIT` | [github.com/hyperium/hyper-util](https://github.com/hyperium/hyper-util) |
| `icu_collections` | 2.2.0 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `icu_locale_core` | 2.2.0 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `icu_normalizer` | 2.2.0 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `icu_normalizer_data` | 2.2.0 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `icu_properties` | 2.2.0 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `icu_properties_data` | 2.2.0 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `icu_provider` | 2.2.0 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `ident_case` | 1.0.1 | `MIT/Apache-2.0` | [github.com/TedDriggs/ident_case](https://github.com/TedDriggs/ident_case) |
| `idna` | 1.1.0 | `MIT OR Apache-2.0` | [github.com/servo/rust-url](https://github.com/servo/rust-url/) |
| `idna_adapter` | 1.2.2 | `Apache-2.0 OR MIT` | [github.com/hsivonen/idna_adapter](https://github.com/hsivonen/idna_adapter) |
| `impl-codec` | 0.7.1 | `MIT OR Apache-2.0` | — |
| `impl-serde` | 0.5.0 | `MIT OR Apache-2.0` | — |
| `impl-trait-for-tuples` | 0.2.3 | `Apache-2.0/MIT` | [github.com/bkchr/impl-trait-for-tuples](https://github.com/bkchr/impl-trait-for-tuples) |
| `indexmap` | 2.14.0 | `Apache-2.0 OR MIT` | [github.com/indexmap-rs/indexmap](https://github.com/indexmap-rs/indexmap) |
| `inout` | 0.1.4 | `MIT OR Apache-2.0` | [github.com/RustCrypto/utils](https://github.com/RustCrypto/utils) |
| `ipnet` | 2.12.0 | `MIT OR Apache-2.0` | [github.com/krisprice/ipnet](https://github.com/krisprice/ipnet) |
| `itertools` | 0.13.0 | `MIT OR Apache-2.0` | [github.com/rust-itertools/itertools](https://github.com/rust-itertools/itertools) |
| `itertools` | 0.14.0 | `MIT OR Apache-2.0` | [github.com/rust-itertools/itertools](https://github.com/rust-itertools/itertools) |
| `itoa` | 1.0.18 | `MIT OR Apache-2.0` | [github.com/dtolnay/itoa](https://github.com/dtolnay/itoa) |
| `jam-codec` | 0.1.1 | `Apache-2.0` | [github.com/paritytech/jam-codec](https://github.com/paritytech/jam-codec) |
| `jam-codec-derive` | 0.1.1 | `Apache-2.0` | [github.com/paritytech/jam-codec](https://github.com/paritytech/jam-codec) |
| `jni` | 0.21.1 | `MIT/Apache-2.0` | [github.com/jni-rs/jni-rs](https://github.com/jni-rs/jni-rs) |
| `jni-sys` | 0.3.1 | `MIT OR Apache-2.0` | [github.com/jni-rs/jni-sys](https://github.com/jni-rs/jni-sys) |
| `jni-sys` | 0.4.1 | `MIT OR Apache-2.0` | [github.com/jni-rs/jni-sys](https://github.com/jni-rs/jni-sys) |
| `jni-sys-macros` | 0.4.1 | `MIT OR Apache-2.0` | [github.com/jni-rs/jni-sys](https://github.com/jni-rs/jni-sys) |
| `js-sys` | 0.3.103 | `MIT OR Apache-2.0` | [github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys) |
| `jsonrpsee` | 0.24.11 | `MIT` | [github.com/paritytech/jsonrpsee](https://github.com/paritytech/jsonrpsee) |
| `jsonrpsee-client-transport` | 0.24.11 | `MIT` | [github.com/paritytech/jsonrpsee](https://github.com/paritytech/jsonrpsee) |
| `jsonrpsee-core` | 0.24.11 | `MIT` | [github.com/paritytech/jsonrpsee](https://github.com/paritytech/jsonrpsee) |
| `jsonrpsee-server` | 0.24.11 | `MIT` | [github.com/paritytech/jsonrpsee](https://github.com/paritytech/jsonrpsee) |
| `jsonrpsee-types` | 0.24.11 | `MIT` | [github.com/paritytech/jsonrpsee](https://github.com/paritytech/jsonrpsee) |
| `jsonrpsee-ws-client` | 0.24.11 | `MIT` | [github.com/paritytech/jsonrpsee](https://github.com/paritytech/jsonrpsee) |
| `jsonwebtoken` | 9.3.1 | `MIT` | [github.com/Keats/jsonwebtoken](https://github.com/Keats/jsonwebtoken) |
| `keccak` | 0.1.6 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/sponges/tree/master/keccak](https://github.com/RustCrypto/sponges/tree/master/keccak) |
| `keccak-hash` | 0.11.0 | `MIT OR Apache-2.0` | [github.com/paritytech/parity-common](https://github.com/paritytech/parity-common) |
| `konst` | 0.2.20 | `Zlib` | [github.com/rodrimati1992/konst](https://github.com/rodrimati1992/konst/) |
| `konst_macro_rules` | 0.2.19 | `Zlib` | [github.com/rodrimati1992/konst](https://github.com/rodrimati1992/konst/) |
| `lazy_static` | 1.5.0 | `MIT OR Apache-2.0` | [github.com/rust-lang-nursery/lazy-static.rs](https://github.com/rust-lang-nursery/lazy-static.rs) |
| `left-right` | 0.11.8 | `MIT OR Apache-2.0` | [github.com/jonhoo/left-right.git](https://github.com/jonhoo/left-right.git) |
| `libc` | 0.2.186 | `MIT OR Apache-2.0` | [github.com/rust-lang/libc](https://github.com/rust-lang/libc) |
| `libm` | 0.2.16 | `MIT` | [github.com/rust-lang/compiler-builtins](https://github.com/rust-lang/compiler-builtins) |
| `libredox` | 0.1.18 | `MIT` | [gitlab.redox-os.org/redox-os/libredox.git](https://gitlab.redox-os.org/redox-os/libredox.git) |
| `libsecp256k1` | 0.7.2 | `Apache-2.0` | [github.com/paritytech/libsecp256k1](https://github.com/paritytech/libsecp256k1) |
| `libsecp256k1-core` | 0.3.0 | `Apache-2.0` | [github.com/paritytech/libsecp256k1](https://github.com/paritytech/libsecp256k1) |
| `libsecp256k1-gen-ecmult` | 0.3.0 | `Apache-2.0` | [github.com/paritytech/libsecp256k1](https://github.com/paritytech/libsecp256k1) |
| `libsecp256k1-gen-genmult` | 0.3.0 | `Apache-2.0` | [github.com/paritytech/libsecp256k1](https://github.com/paritytech/libsecp256k1) |
| `libsqlite3-sys` | 0.30.1 | `MIT` | [github.com/rusqlite/rusqlite](https://github.com/rusqlite/rusqlite) |
| `linux-raw-sys` | 0.12.1 | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [github.com/sunfishcode/linux-raw-sys](https://github.com/sunfishcode/linux-raw-sys) |
| `litemap` | 0.8.2 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `lock_api` | 0.4.14 | `MIT OR Apache-2.0` | [github.com/Amanieu/parking_lot](https://github.com/Amanieu/parking_lot) |
| `log` | 0.4.33 | `MIT OR Apache-2.0` | [github.com/rust-lang/log](https://github.com/rust-lang/log) |
| `loom` | 0.7.2 | `MIT` | [github.com/tokio-rs/loom](https://github.com/tokio-rs/loom) |
| `lru` | 0.16.4 | `MIT` | [github.com/jeromefroe/lru-rs.git](https://github.com/jeromefroe/lru-rs.git) |
| `lru-slab` | 0.1.2 | `MIT OR Apache-2.0 OR Zlib` | [github.com/Ralith/lru-slab](https://github.com/Ralith/lru-slab) |
| `matchers` | 0.2.0 | `MIT` | [github.com/hawkw/matchers](https://github.com/hawkw/matchers) |
| `matchit` | 0.8.4 | `MIT AND BSD-3-Clause` | [github.com/ibraheemdev/matchit](https://github.com/ibraheemdev/matchit) |
| `md-5` | 0.10.6 | `MIT OR Apache-2.0` | [github.com/RustCrypto/hashes](https://github.com/RustCrypto/hashes) |
| `memchr` | 2.8.2 | `Unlicense OR MIT` | [github.com/BurntSushi/memchr](https://github.com/BurntSushi/memchr) |
| `merlin` | 3.0.0 | `MIT` | [github.com/zkcrypto/merlin](https://github.com/zkcrypto/merlin) |
| `metrics` | 0.24.6 | `MIT` | [github.com/metrics-rs/metrics](https://github.com/metrics-rs/metrics) |
| `metrics-exporter-prometheus` | 0.18.3 | `MIT AND Apache-2.0` | [github.com/metrics-rs/metrics](https://github.com/metrics-rs/metrics) |
| `metrics-util` | 0.20.4 | `MIT` | [github.com/metrics-rs/metrics](https://github.com/metrics-rs/metrics) |
| `mime` | 0.3.17 | `MIT OR Apache-2.0` | [github.com/hyperium/mime](https://github.com/hyperium/mime) |
| `mime_guess` | 2.0.5 | `MIT` | [github.com/abonander/mime_guess](https://github.com/abonander/mime_guess) |
| `minimal-lexical` | 0.2.1 | `MIT/Apache-2.0` | [github.com/Alexhuszagh/minimal-lexical](https://github.com/Alexhuszagh/minimal-lexical) |
| `mio` | 1.2.1 | `MIT` | [github.com/tokio-rs/mio](https://github.com/tokio-rs/mio) |
| `moka` | 0.12.16 | `(MIT OR Apache-2.0) AND Apache-2.0` | [github.com/moka-rs/moka](https://github.com/moka-rs/moka) |
| `multi-stash` | 0.2.0 | `MIT/Apache-2.0` | [github.com/robbepop/multi-stash](https://github.com/robbepop/multi-stash) |
| `nodrop` | 0.1.14 | `MIT/Apache-2.0` | [github.com/bluss/arrayvec](https://github.com/bluss/arrayvec) |
| `nom` | 7.1.3 | `MIT` | [github.com/Geal/nom](https://github.com/Geal/nom) |
| `nom` | 8.0.0 | `MIT` | [github.com/rust-bakery/nom](https://github.com/rust-bakery/nom) |
| `nonzero_ext` | 0.3.0 | `Apache-2.0` | [github.com/antifuchs/nonzero_ext](https://github.com/antifuchs/nonzero_ext) |
| `nu-ansi-term` | 0.50.3 | `MIT` | [github.com/nushell/nu-ansi-term](https://github.com/nushell/nu-ansi-term) |
| `num-bigint` | 0.4.8 | `MIT OR Apache-2.0` | [github.com/rust-num/num-bigint](https://github.com/rust-num/num-bigint) |
| `num-bigint-dig` | 0.8.6 | `MIT/Apache-2.0` | [github.com/dignifiedquire/num-bigint](https://github.com/dignifiedquire/num-bigint) |
| `num-conv` | 0.2.2 | `MIT OR Apache-2.0` | [github.com/jhpratt/num-conv](https://github.com/jhpratt/num-conv) |
| `num-integer` | 0.1.46 | `MIT OR Apache-2.0` | [github.com/rust-num/num-integer](https://github.com/rust-num/num-integer) |
| `num-iter` | 0.1.45 | `MIT OR Apache-2.0` | [github.com/rust-num/num-iter](https://github.com/rust-num/num-iter) |
| `num-rational` | 0.4.2 | `MIT OR Apache-2.0` | [github.com/rust-num/num-rational](https://github.com/rust-num/num-rational) |
| `num-traits` | 0.2.19 | `MIT OR Apache-2.0` | [github.com/rust-num/num-traits](https://github.com/rust-num/num-traits) |
| `oid-registry` | 0.8.1 | `MIT OR Apache-2.0` | [github.com/rusticata/oid-registry.git](https://github.com/rusticata/oid-registry.git) |
| `once_cell` | 1.21.4 | `MIT OR Apache-2.0` | [github.com/matklad/once_cell](https://github.com/matklad/once_cell) |
| `opaque-debug` | 0.3.1 | `MIT OR Apache-2.0` | [github.com/RustCrypto/utils](https://github.com/RustCrypto/utils) |
| `openssl-probe` | 0.2.1 | `MIT OR Apache-2.0` | [github.com/rustls/openssl-probe](https://github.com/rustls/openssl-probe) |
| `p256` | 0.13.2 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/elliptic-curves/tree/master/p256](https://github.com/RustCrypto/elliptic-curves/tree/master/p256) |
| `p384` | 0.13.1 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/elliptic-curves/tree/master/p384](https://github.com/RustCrypto/elliptic-curves/tree/master/p384) |
| `parity-scale-codec` | 3.7.5 | `Apache-2.0` | [github.com/paritytech/parity-scale-codec](https://github.com/paritytech/parity-scale-codec) |
| `parity-scale-codec-derive` | 3.7.5 | `Apache-2.0` | [github.com/paritytech/parity-scale-codec](https://github.com/paritytech/parity-scale-codec) |
| `parking` | 2.2.1 | `Apache-2.0 OR MIT` | [github.com/smol-rs/parking](https://github.com/smol-rs/parking) |
| `parking_lot` | 0.12.5 | `MIT OR Apache-2.0` | [github.com/Amanieu/parking_lot](https://github.com/Amanieu/parking_lot) |
| `parking_lot_core` | 0.9.12 | `MIT OR Apache-2.0` | [github.com/Amanieu/parking_lot](https://github.com/Amanieu/parking_lot) |
| `password-hash` | 0.5.0 | `MIT OR Apache-2.0` | [github.com/RustCrypto/traits/tree/master/password-hash](https://github.com/RustCrypto/traits/tree/master/password-hash) |
| `paste` | 1.0.15 | `MIT OR Apache-2.0` | [github.com/dtolnay/paste](https://github.com/dtolnay/paste) |
| `pbkdf2` | 0.12.2 | `MIT OR Apache-2.0` | [github.com/RustCrypto/password-hashes/tree/master/pbkdf2](https://github.com/RustCrypto/password-hashes/tree/master/pbkdf2) |
| `pem` | 3.0.6 | `MIT` | [github.com/jcreekmore/pem-rs.git](https://github.com/jcreekmore/pem-rs.git) |
| `pem-rfc7468` | 0.7.0 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/formats/tree/master/pem-rfc7468](https://github.com/RustCrypto/formats/tree/master/pem-rfc7468) |
| `percent-encoding` | 2.3.2 | `MIT OR Apache-2.0` | [github.com/servo/rust-url](https://github.com/servo/rust-url/) |
| `pin-project` | 1.1.13 | `Apache-2.0 OR MIT` | [github.com/taiki-e/pin-project](https://github.com/taiki-e/pin-project) |
| `pin-project-internal` | 1.1.13 | `Apache-2.0 OR MIT` | [github.com/taiki-e/pin-project](https://github.com/taiki-e/pin-project) |
| `pin-project-lite` | 0.2.17 | `Apache-2.0 OR MIT` | [github.com/taiki-e/pin-project-lite](https://github.com/taiki-e/pin-project-lite) |
| `piper` | 0.2.5 | `MIT OR Apache-2.0` | [github.com/smol-rs/piper](https://github.com/smol-rs/piper) |
| `pkcs1` | 0.7.5 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/formats/tree/master/pkcs1](https://github.com/RustCrypto/formats/tree/master/pkcs1) |
| `pkcs8` | 0.10.2 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/formats/tree/master/pkcs8](https://github.com/RustCrypto/formats/tree/master/pkcs8) |
| `pkg-config` | 0.3.33 | `MIT OR Apache-2.0` | [github.com/rust-lang/pkg-config-rs](https://github.com/rust-lang/pkg-config-rs) |
| `plain` | 0.2.3 | `MIT/Apache-2.0` | [github.com/randomites/plain](https://github.com/randomites/plain) |
| `polling` | 3.11.0 | `Apache-2.0 OR MIT` | [github.com/smol-rs/polling](https://github.com/smol-rs/polling) |
| `poly1305` | 0.8.0 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/universal-hashes](https://github.com/RustCrypto/universal-hashes) |
| `polyval` | 0.6.2 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/universal-hashes](https://github.com/RustCrypto/universal-hashes) |
| `portable-atomic` | 1.13.1 | `Apache-2.0 OR MIT` | [github.com/taiki-e/portable-atomic](https://github.com/taiki-e/portable-atomic) |
| `potential_utf` | 0.1.5 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `powerfmt` | 0.2.0 | `MIT OR Apache-2.0` | [github.com/jhpratt/powerfmt](https://github.com/jhpratt/powerfmt) |
| `ppv-lite86` | 0.2.21 | `MIT OR Apache-2.0` | [github.com/cryptocorrosion/cryptocorrosion](https://github.com/cryptocorrosion/cryptocorrosion) |
| `primeorder` | 0.13.6 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/elliptic-curves/tree/master/primeorder](https://github.com/RustCrypto/elliptic-curves/tree/master/primeorder) |
| `primitive-types` | 0.13.1 | `MIT OR Apache-2.0` | [github.com/paritytech/parity-common](https://github.com/paritytech/parity-common) |
| `proc-macro-crate` | 3.5.0 | `MIT OR Apache-2.0` | [github.com/bkchr/proc-macro-crate](https://github.com/bkchr/proc-macro-crate) |
| `proc-macro-error-attr2` | 2.0.0 | `MIT OR Apache-2.0` | [github.com/GnomedDev/proc-macro-error-2](https://github.com/GnomedDev/proc-macro-error-2) |
| `proc-macro-error2` | 2.0.1 | `MIT OR Apache-2.0` | [github.com/GnomedDev/proc-macro-error-2](https://github.com/GnomedDev/proc-macro-error-2) |
| `proc-macro2` | 1.0.106 | `MIT OR Apache-2.0` | [github.com/dtolnay/proc-macro2](https://github.com/dtolnay/proc-macro2) |
| `quanta` | 0.12.6 | `MIT` | [github.com/metrics-rs/quanta](https://github.com/metrics-rs/quanta) |
| `quinn` | 0.11.11 | `MIT OR Apache-2.0` | [github.com/quinn-rs/quinn](https://github.com/quinn-rs/quinn) |
| `quinn-proto` | 0.11.16 | `MIT OR Apache-2.0` | [github.com/quinn-rs/quinn](https://github.com/quinn-rs/quinn) |
| `quinn-udp` | 0.5.15 | `MIT OR Apache-2.0` | [github.com/quinn-rs/quinn](https://github.com/quinn-rs/quinn) |
| `quote` | 1.0.46 | `MIT OR Apache-2.0` | [github.com/dtolnay/quote](https://github.com/dtolnay/quote) |
| `r-efi` | 5.3.0 | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | [github.com/r-efi/r-efi](https://github.com/r-efi/r-efi) |
| `r-efi` | 6.0.0 | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | [github.com/r-efi/r-efi](https://github.com/r-efi/r-efi) |
| `radium` | 0.7.0 | `MIT` | [github.com/bitvecto-rs/radium](https://github.com/bitvecto-rs/radium) |
| `rand` | 0.10.2 | `MIT OR Apache-2.0` | [github.com/rust-random/rand](https://github.com/rust-random/rand) |
| `rand` | 0.8.6 | `MIT OR Apache-2.0` | [github.com/rust-random/rand](https://github.com/rust-random/rand) |
| `rand` | 0.9.5 | `MIT OR Apache-2.0` | [github.com/rust-random/rand](https://github.com/rust-random/rand) |
| `rand_chacha` | 0.3.1 | `MIT OR Apache-2.0` | [github.com/rust-random/rand](https://github.com/rust-random/rand) |
| `rand_chacha` | 0.9.0 | `MIT OR Apache-2.0` | [github.com/rust-random/rand](https://github.com/rust-random/rand) |
| `rand_core` | 0.10.1 | `MIT OR Apache-2.0` | [github.com/rust-random/rand_core](https://github.com/rust-random/rand_core) |
| `rand_core` | 0.6.4 | `MIT OR Apache-2.0` | [github.com/rust-random/rand](https://github.com/rust-random/rand) |
| `rand_core` | 0.9.5 | `MIT OR Apache-2.0` | [github.com/rust-random/rand](https://github.com/rust-random/rand) |
| `rand_pcg` | 0.10.2 | `MIT OR Apache-2.0` | [github.com/rust-random/rngs](https://github.com/rust-random/rngs) |
| `rand_xoshiro` | 0.7.0 | `MIT OR Apache-2.0` | [github.com/rust-random/rngs](https://github.com/rust-random/rngs) |
| `rapidhash` | 4.5.1 | `MIT OR Apache-2.0` | [github.com/hoxxep/rapidhash](https://github.com/hoxxep/rapidhash) |
| `raw-cpuid` | 11.6.0 | `MIT` | [github.com/gz/rust-cpuid](https://github.com/gz/rust-cpuid) |
| `rayon` | 1.12.0 | `MIT OR Apache-2.0` | [github.com/rayon-rs/rayon](https://github.com/rayon-rs/rayon) |
| `rayon-core` | 1.13.0 | `MIT OR Apache-2.0` | [github.com/rayon-rs/rayon](https://github.com/rayon-rs/rayon) |
| `rcgen` | 0.13.2 | `MIT OR Apache-2.0` | [github.com/rustls/rcgen](https://github.com/rustls/rcgen) |
| `redox_syscall` | 0.5.18 | `MIT` | [gitlab.redox-os.org/redox-os/syscall](https://gitlab.redox-os.org/redox-os/syscall) |
| `redox_syscall` | 0.9.0 | `MIT` | [gitlab.redox-os.org/redox-os/syscall](https://gitlab.redox-os.org/redox-os/syscall) |
| `regex` | 1.12.4 | `MIT OR Apache-2.0` | [github.com/rust-lang/regex](https://github.com/rust-lang/regex) |
| `regex-automata` | 0.4.14 | `MIT OR Apache-2.0` | [github.com/rust-lang/regex](https://github.com/rust-lang/regex) |
| `regex-syntax` | 0.8.11 | `MIT OR Apache-2.0` | [github.com/rust-lang/regex](https://github.com/rust-lang/regex) |
| `reqwest` | 0.12.28 | `MIT OR Apache-2.0` | [github.com/seanmonstar/reqwest](https://github.com/seanmonstar/reqwest) |
| `rfc6979` | 0.4.0 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/signatures/tree/master/rfc6979](https://github.com/RustCrypto/signatures/tree/master/rfc6979) |
| `ring` | 0.17.14 | `Apache-2.0 AND ISC` | [github.com/briansmith/ring](https://github.com/briansmith/ring) |
| `route-recognizer` | 0.3.1 | `MIT` | [github.com/rustasync/route-recognizer](https://github.com/rustasync/route-recognizer) |
| `rsa` | 0.9.10 | `MIT OR Apache-2.0` | [github.com/RustCrypto/RSA](https://github.com/RustCrypto/RSA) |
| `rustc-hash` | 2.1.3 | `Apache-2.0 OR MIT` | [github.com/rust-lang/rustc-hash](https://github.com/rust-lang/rustc-hash) |
| `rustc-hex` | 2.1.0 | `MIT/Apache-2.0` | [github.com/debris/rustc-hex](https://github.com/debris/rustc-hex) |
| `rustc_version` | 0.4.1 | `MIT OR Apache-2.0` | [github.com/djc/rustc-version-rs](https://github.com/djc/rustc-version-rs) |
| `rusticata-macros` | 4.1.0 | `MIT/Apache-2.0` | [github.com/rusticata/rusticata-macros.git](https://github.com/rusticata/rusticata-macros.git) |
| `rustix` | 1.1.4 | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [github.com/bytecodealliance/rustix](https://github.com/bytecodealliance/rustix) |
| `rustls` | 0.23.45 | `Apache-2.0 OR ISC OR MIT` | [github.com/rustls/rustls](https://github.com/rustls/rustls) |
| `rustls-native-certs` | 0.8.4 | `Apache-2.0 OR ISC OR MIT` | [github.com/rustls/rustls-native-certs](https://github.com/rustls/rustls-native-certs) |
| `rustls-pki-types` | 1.15.0 | `MIT OR Apache-2.0` | [github.com/rustls/pki-types](https://github.com/rustls/pki-types) |
| `rustls-platform-verifier` | 0.5.3 | `MIT OR Apache-2.0` | [github.com/rustls/rustls-platform-verifier](https://github.com/rustls/rustls-platform-verifier) |
| `rustls-platform-verifier-android` | 0.1.1 | `MIT OR Apache-2.0` | [github.com/rustls/rustls-platform-verifier](https://github.com/rustls/rustls-platform-verifier) |
| `rustls-webpki` | 0.103.15 | `ISC` | [github.com/rustls/webpki](https://github.com/rustls/webpki) |
| `rustversion` | 1.0.22 | `MIT OR Apache-2.0` | [github.com/dtolnay/rustversion](https://github.com/dtolnay/rustversion) |
| `ruzstd` | 0.8.3 | `MIT` | [github.com/KillingSpark/zstd-rs](https://github.com/KillingSpark/zstd-rs) |
| `ryu` | 1.0.23 | `Apache-2.0 OR BSL-1.0` | [github.com/dtolnay/ryu](https://github.com/dtolnay/ryu) |
| `salsa20` | 0.10.2 | `MIT OR Apache-2.0` | [github.com/RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers) |
| `same-file` | 1.0.6 | `Unlicense/MIT` | [github.com/BurntSushi/same-file](https://github.com/BurntSushi/same-file) |
| `scale-bits` | 0.7.0 | `Apache-2.0` | [github.com/paritytech/scale-bits](https://github.com/paritytech/scale-bits) |
| `scale-decode` | 0.16.2 | `Apache-2.0` | [github.com/paritytech/scale-decode](https://github.com/paritytech/scale-decode) |
| `scale-decode-derive` | 0.16.2 | `Apache-2.0` | [github.com/paritytech/scale-decode](https://github.com/paritytech/scale-decode) |
| `scale-encode` | 0.10.1 | `Apache-2.0` | [github.com/paritytech/scale-encode](https://github.com/paritytech/scale-encode) |
| `scale-encode-derive` | 0.10.1 | `Apache-2.0` | [github.com/paritytech/scale-encode](https://github.com/paritytech/scale-encode) |
| `scale-info` | 2.11.6 | `Apache-2.0` | [github.com/paritytech/scale-info](https://github.com/paritytech/scale-info) |
| `scale-info-derive` | 2.11.6 | `Apache-2.0` | [github.com/paritytech/scale-info](https://github.com/paritytech/scale-info) |
| `scale-info-legacy` | 0.4.2 | `Apache-2.0` | [github.com/paritytech/scale-info-legacy](https://github.com/paritytech/scale-info-legacy) |
| `scale-type-resolver` | 0.2.0 | `Apache-2.0` | [github.com/paritytech/scale-type-resolver](https://github.com/paritytech/scale-type-resolver) |
| `scale-typegen` | 0.12.0 | `Apache-2.0` | [github.com/paritytech/scale-typegen](https://github.com/paritytech/scale-typegen) |
| `scale-value` | 0.18.2 | `Apache-2.0` | [github.com/paritytech/scale-value](https://github.com/paritytech/scale-value) |
| `schannel` | 0.1.29 | `MIT` | [github.com/steffengy/schannel-rs](https://github.com/steffengy/schannel-rs) |
| `schnorrkel` | 0.11.5 | `BSD-3-Clause` | [github.com/w3f/schnorrkel](https://github.com/w3f/schnorrkel) |
| `scoped-tls` | 1.0.1 | `MIT/Apache-2.0` | [github.com/alexcrichton/scoped-tls](https://github.com/alexcrichton/scoped-tls) |
| `scopeguard` | 1.2.0 | `MIT OR Apache-2.0` | [github.com/bluss/scopeguard](https://github.com/bluss/scopeguard) |
| `scrypt` | 0.11.0 | `MIT OR Apache-2.0` | [github.com/RustCrypto/password-hashes/tree/master/scrypt](https://github.com/RustCrypto/password-hashes/tree/master/scrypt) |
| `sec1` | 0.7.3 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/formats/tree/master/sec1](https://github.com/RustCrypto/formats/tree/master/sec1) |
| `secp256k1` | 0.30.0 | `CC0-1.0` | [github.com/rust-bitcoin/rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1/) |
| `secp256k1-sys` | 0.10.1 | `CC0-1.0` | [github.com/rust-bitcoin/rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1/) |
| `secrecy` | 0.10.3 | `Apache-2.0 OR MIT` | [github.com/iqlusioninc/crates/tree/main/secrecy](https://github.com/iqlusioninc/crates/tree/main/secrecy) |
| `security-framework` | 3.7.0 | `MIT OR Apache-2.0` | [github.com/kornelski/rust-security-framework](https://github.com/kornelski/rust-security-framework) |
| `security-framework-sys` | 2.17.0 | `MIT OR Apache-2.0` | [github.com/kornelski/rust-security-framework](https://github.com/kornelski/rust-security-framework) |
| `semver` | 1.0.28 | `MIT OR Apache-2.0` | [github.com/dtolnay/semver](https://github.com/dtolnay/semver) |
| `serde` | 1.0.228 | `MIT OR Apache-2.0` | [github.com/serde-rs/serde](https://github.com/serde-rs/serde) |
| `serde_bytes` | 0.11.19 | `MIT OR Apache-2.0` | [github.com/serde-rs/bytes](https://github.com/serde-rs/bytes) |
| `serde_core` | 1.0.228 | `MIT OR Apache-2.0` | [github.com/serde-rs/serde](https://github.com/serde-rs/serde) |
| `serde_derive` | 1.0.228 | `MIT OR Apache-2.0` | [github.com/serde-rs/serde](https://github.com/serde-rs/serde) |
| `serde_json` | 1.0.150 | `MIT OR Apache-2.0` | [github.com/serde-rs/json](https://github.com/serde-rs/json) |
| `serde_path_to_error` | 0.1.20 | `MIT OR Apache-2.0` | [github.com/dtolnay/path-to-error](https://github.com/dtolnay/path-to-error) |
| `serde_urlencoded` | 0.7.1 | `MIT/Apache-2.0` | [github.com/nox/serde_urlencoded](https://github.com/nox/serde_urlencoded) |
| `serde_yaml` | 0.9.34+deprecated | `MIT OR Apache-2.0` | [github.com/dtolnay/serde-yaml](https://github.com/dtolnay/serde-yaml) |
| `sha1` | 0.10.6 | `MIT OR Apache-2.0` | [github.com/RustCrypto/hashes](https://github.com/RustCrypto/hashes) |
| `sha2` | 0.10.9 | `MIT OR Apache-2.0` | [github.com/RustCrypto/hashes](https://github.com/RustCrypto/hashes) |
| `sha2` | 0.9.9 | `MIT OR Apache-2.0` | [github.com/RustCrypto/hashes](https://github.com/RustCrypto/hashes) |
| `sha3` | 0.10.9 | `MIT OR Apache-2.0` | [github.com/RustCrypto/hashes](https://github.com/RustCrypto/hashes) |
| `sharded-slab` | 0.1.7 | `MIT` | [github.com/hawkw/sharded-slab](https://github.com/hawkw/sharded-slab) |
| `shlex` | 2.0.1 | `MIT OR Apache-2.0` | [github.com/comex/rust-shlex](https://github.com/comex/rust-shlex) |
| `signal-hook-registry` | 1.4.8 | `MIT OR Apache-2.0` | [github.com/vorner/signal-hook](https://github.com/vorner/signal-hook) |
| `signature` | 2.2.0 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/traits/tree/master/signature](https://github.com/RustCrypto/traits/tree/master/signature) |
| `simple_asn1` | 0.6.4 | `ISC` | [github.com/acw/simple_asn1](https://github.com/acw/simple_asn1) |
| `siphasher` | 1.0.3 | `MIT/Apache-2.0` | [github.com/jedisct1/rust-siphash](https://github.com/jedisct1/rust-siphash) |
| `sketches-ddsketch` | 0.3.1 | `Apache-2.0` | [github.com/mheffner/rust-sketches-ddsketch](https://github.com/mheffner/rust-sketches-ddsketch) |
| `slab` | 0.4.12 | `MIT` | [github.com/tokio-rs/slab](https://github.com/tokio-rs/slab) |
| `smallstr` | 0.3.1 | `MIT OR Apache-2.0` | [github.com/murarth/smallstr](https://github.com/murarth/smallstr) |
| `smallvec` | 1.15.2 | `MIT OR Apache-2.0` | [github.com/servo/rust-smallvec](https://github.com/servo/rust-smallvec) |
| `smol` | 2.0.2 | `Apache-2.0 OR MIT` | [github.com/smol-rs/smol](https://github.com/smol-rs/smol) |
| `smoldot` | 2.1.0 | `GPL-3.0-or-later WITH Classpath-exception-2.0` | [github.com/paritytech/smoldot](https://github.com/paritytech/smoldot) |
| `smoldot-light` | 1.3.1 | `GPL-3.0-or-later WITH Classpath-exception-2.0` | [github.com/paritytech/smoldot](https://github.com/paritytech/smoldot) |
| `socket2` | 0.6.4 | `MIT OR Apache-2.0` | [github.com/rust-lang/socket2](https://github.com/rust-lang/socket2) |
| `soketto` | 0.8.1 | `Apache-2.0 OR MIT` | [github.com/paritytech/soketto](https://github.com/paritytech/soketto) |
| `sp-crypto-hashing` | 0.1.0 | `Apache-2.0` | [github.com/paritytech/polkadot-sdk.git](https://github.com/paritytech/polkadot-sdk.git) |
| `spin` | 0.9.9 | `MIT` | [github.com/mvdnes/spin-rs.git](https://github.com/mvdnes/spin-rs.git) |
| `spinning_top` | 0.3.0 | `MIT/Apache-2.0` | [github.com/rust-osdev/spinning_top](https://github.com/rust-osdev/spinning_top) |
| `spki` | 0.7.3 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/formats/tree/master/spki](https://github.com/RustCrypto/formats/tree/master/spki) |
| `sqlx` | 0.8.6 | `MIT OR Apache-2.0` | [github.com/launchbadge/sqlx](https://github.com/launchbadge/sqlx) |
| `sqlx-core` | 0.8.6 | `MIT OR Apache-2.0` | [github.com/launchbadge/sqlx](https://github.com/launchbadge/sqlx) |
| `sqlx-macros` | 0.8.6 | `MIT OR Apache-2.0` | [github.com/launchbadge/sqlx](https://github.com/launchbadge/sqlx) |
| `sqlx-macros-core` | 0.8.6 | `MIT OR Apache-2.0` | [github.com/launchbadge/sqlx](https://github.com/launchbadge/sqlx) |
| `sqlx-mysql` | 0.8.6 | `MIT OR Apache-2.0` | [github.com/launchbadge/sqlx](https://github.com/launchbadge/sqlx) |
| `sqlx-postgres` | 0.8.6 | `MIT OR Apache-2.0` | [github.com/launchbadge/sqlx](https://github.com/launchbadge/sqlx) |
| `sqlx-sqlite` | 0.8.6 | `MIT OR Apache-2.0` | [github.com/launchbadge/sqlx](https://github.com/launchbadge/sqlx) |
| `stable_deref_trait` | 1.2.1 | `MIT OR Apache-2.0` | [github.com/storyyeller/stable_deref_trait](https://github.com/storyyeller/stable_deref_trait) |
| `static_assertions` | 1.1.0 | `MIT OR Apache-2.0` | [github.com/nvzqz/static-assertions-rs](https://github.com/nvzqz/static-assertions-rs) |
| `stringprep` | 0.1.5 | `MIT/Apache-2.0` | [github.com/sfackler/rust-stringprep](https://github.com/sfackler/rust-stringprep) |
| `strsim` | 0.11.1 | `MIT` | [github.com/rapidfuzz/strsim-rs](https://github.com/rapidfuzz/strsim-rs) |
| `subtle` | 2.6.1 | `BSD-3-Clause` | [github.com/dalek-cryptography/subtle](https://github.com/dalek-cryptography/subtle) |
| `subxt` | 0.50.3 | `Apache-2.0 OR GPL-3.0` | [github.com/paritytech/subxt](https://github.com/paritytech/subxt) |
| `subxt-codegen` | 0.50.3 | `Apache-2.0 OR GPL-3.0` | [github.com/paritytech/subxt](https://github.com/paritytech/subxt) |
| `subxt-lightclient` | 0.50.3 | `Apache-2.0 OR GPL-3.0` | [github.com/paritytech/subxt](https://github.com/paritytech/subxt) |
| `subxt-macro` | 0.50.3 | `Apache-2.0 OR GPL-3.0` | [github.com/paritytech/subxt](https://github.com/paritytech/subxt) |
| `subxt-metadata` | 0.50.3 | `Apache-2.0 OR GPL-3.0` | [github.com/paritytech/subxt](https://github.com/paritytech/subxt) |
| `subxt-rpcs` | 0.50.3 | `Apache-2.0 OR GPL-3.0` | [github.com/paritytech/subxt](https://github.com/paritytech/subxt) |
| `subxt-signer` | 0.50.3 | `Apache-2.0 OR GPL-3.0` | [github.com/paritytech/subxt](https://github.com/paritytech/subxt) |
| `subxt-utils-accountid32` | 0.50.3 | `Apache-2.0 OR GPL-3.0` | [github.com/paritytech/subxt](https://github.com/paritytech/subxt) |
| `subxt-utils-fetchmetadata` | 0.50.3 | `Apache-2.0 OR GPL-3.0` | [github.com/paritytech/subxt](https://github.com/paritytech/subxt) |
| `syn` | 2.0.118 | `MIT OR Apache-2.0` | [github.com/dtolnay/syn](https://github.com/dtolnay/syn) |
| `syn` | 3.0.3 | `MIT OR Apache-2.0` | [github.com/dtolnay/syn](https://github.com/dtolnay/syn) |
| `sync_wrapper` | 1.0.2 | `Apache-2.0` | [github.com/Actyx/sync_wrapper](https://github.com/Actyx/sync_wrapper) |
| `synstructure` | 0.13.2 | `MIT` | [github.com/mystor/synstructure](https://github.com/mystor/synstructure) |
| `tagptr` | 0.2.0 | `MIT/Apache-2.0` | [github.com/oliver-giersch/tagptr.git](https://github.com/oliver-giersch/tagptr.git) |
| `tap` | 1.0.1 | `MIT` | [github.com/myrrlyn/tap](https://github.com/myrrlyn/tap) |
| `thiserror` | 1.0.69 | `MIT OR Apache-2.0` | [github.com/dtolnay/thiserror](https://github.com/dtolnay/thiserror) |
| `thiserror` | 2.0.18 | `MIT OR Apache-2.0` | [github.com/dtolnay/thiserror](https://github.com/dtolnay/thiserror) |
| `thiserror-impl` | 1.0.69 | `MIT OR Apache-2.0` | [github.com/dtolnay/thiserror](https://github.com/dtolnay/thiserror) |
| `thiserror-impl` | 2.0.18 | `MIT OR Apache-2.0` | [github.com/dtolnay/thiserror](https://github.com/dtolnay/thiserror) |
| `thread_local` | 1.1.9 | `MIT OR Apache-2.0` | [github.com/Amanieu/thread_local-rs](https://github.com/Amanieu/thread_local-rs) |
| `time` | 0.3.53 | `MIT OR Apache-2.0` | [github.com/time-rs/time](https://github.com/time-rs/time) |
| `time-core` | 0.1.9 | `MIT OR Apache-2.0` | [github.com/time-rs/time](https://github.com/time-rs/time) |
| `time-macros` | 0.2.31 | `MIT OR Apache-2.0` | [github.com/time-rs/time](https://github.com/time-rs/time) |
| `tiny-keccak` | 2.0.2 | `CC0-1.0` | — |
| `tinystr` | 0.8.3 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `tinyvec` | 1.11.0 | `Zlib OR Apache-2.0 OR MIT` | [github.com/Lokathor/tinyvec](https://github.com/Lokathor/tinyvec) |
| `tinyvec_macros` | 0.1.1 | `MIT OR Apache-2.0 OR Zlib` | [github.com/Soveu/tinyvec_macros](https://github.com/Soveu/tinyvec_macros) |
| `tokio` | 1.52.3 | `MIT` | [github.com/tokio-rs/tokio](https://github.com/tokio-rs/tokio) |
| `tokio-macros` | 2.7.0 | `MIT` | [github.com/tokio-rs/tokio](https://github.com/tokio-rs/tokio) |
| `tokio-rustls` | 0.26.4 | `MIT OR Apache-2.0` | [github.com/rustls/tokio-rustls](https://github.com/rustls/tokio-rustls) |
| `tokio-stream` | 0.1.18 | `MIT` | [github.com/tokio-rs/tokio](https://github.com/tokio-rs/tokio) |
| `tokio-util` | 0.7.18 | `MIT` | [github.com/tokio-rs/tokio](https://github.com/tokio-rs/tokio) |
| `toml_datetime` | 1.1.1+spec-1.1.0 | `MIT OR Apache-2.0` | [github.com/toml-rs/toml](https://github.com/toml-rs/toml) |
| `toml_edit` | 0.25.12+spec-1.1.0 | `MIT OR Apache-2.0` | [github.com/toml-rs/toml](https://github.com/toml-rs/toml) |
| `toml_parser` | 1.1.2+spec-1.1.0 | `MIT OR Apache-2.0` | [github.com/toml-rs/toml](https://github.com/toml-rs/toml) |
| `tower` | 0.4.13 | `MIT` | [github.com/tower-rs/tower](https://github.com/tower-rs/tower) |
| `tower` | 0.5.3 | `MIT` | [github.com/tower-rs/tower](https://github.com/tower-rs/tower) |
| `tower-http` | 0.6.11 | `MIT` | [github.com/tower-rs/tower-http](https://github.com/tower-rs/tower-http) |
| `tower-layer` | 0.3.3 | `MIT` | [github.com/tower-rs/tower](https://github.com/tower-rs/tower) |
| `tower-service` | 0.3.3 | `MIT` | [github.com/tower-rs/tower](https://github.com/tower-rs/tower) |
| `tracing` | 0.1.44 | `MIT` | [github.com/tokio-rs/tracing](https://github.com/tokio-rs/tracing) |
| `tracing-attributes` | 0.1.31 | `MIT` | [github.com/tokio-rs/tracing](https://github.com/tokio-rs/tracing) |
| `tracing-core` | 0.1.36 | `MIT` | [github.com/tokio-rs/tracing](https://github.com/tokio-rs/tracing) |
| `tracing-log` | 0.2.0 | `MIT` | [github.com/tokio-rs/tracing](https://github.com/tokio-rs/tracing) |
| `tracing-serde` | 0.2.0 | `MIT` | [github.com/tokio-rs/tracing](https://github.com/tokio-rs/tracing) |
| `tracing-subscriber` | 0.3.23 | `MIT` | [github.com/tokio-rs/tracing](https://github.com/tokio-rs/tracing) |
| `try-lock` | 0.2.5 | `MIT` | [github.com/seanmonstar/try-lock](https://github.com/seanmonstar/try-lock) |
| `twox-hash` | 1.6.3 | `MIT` | [github.com/shepmaster/twox-hash](https://github.com/shepmaster/twox-hash) |
| `twox-hash` | 2.1.2 | `MIT` | [github.com/shepmaster/twox-hash](https://github.com/shepmaster/twox-hash) |
| `typenum` | 1.20.1 | `MIT OR Apache-2.0` | [github.com/paholg/typenum](https://github.com/paholg/typenum) |
| `uint` | 0.10.0 | `MIT OR Apache-2.0` | [github.com/paritytech/parity-common](https://github.com/paritytech/parity-common) |
| `unicase` | 2.9.0 | `MIT OR Apache-2.0` | [github.com/seanmonstar/unicase](https://github.com/seanmonstar/unicase) |
| `unicode-bidi` | 0.3.18 | `MIT OR Apache-2.0` | [github.com/servo/unicode-bidi](https://github.com/servo/unicode-bidi) |
| `unicode-ident` | 1.0.24 | `(MIT OR Apache-2.0) AND Unicode-3.0` | [github.com/dtolnay/unicode-ident](https://github.com/dtolnay/unicode-ident) |
| `unicode-normalization` | 0.1.25 | `MIT OR Apache-2.0` | [github.com/unicode-rs/unicode-normalization](https://github.com/unicode-rs/unicode-normalization) |
| `unicode-properties` | 0.1.4 | `MIT/Apache-2.0` | [github.com/unicode-rs/unicode-properties](https://github.com/unicode-rs/unicode-properties) |
| `unicode-segmentation` | 1.13.3 | `MIT OR Apache-2.0` | [github.com/unicode-rs/unicode-segmentation](https://github.com/unicode-rs/unicode-segmentation) |
| `unicode-xid` | 0.2.6 | `MIT OR Apache-2.0` | [github.com/unicode-rs/unicode-xid](https://github.com/unicode-rs/unicode-xid) |
| `universal-hash` | 0.5.1 | `MIT OR Apache-2.0` | [github.com/RustCrypto/traits](https://github.com/RustCrypto/traits) |
| `unsafe-libyaml` | 0.2.11 | `MIT` | [github.com/dtolnay/unsafe-libyaml](https://github.com/dtolnay/unsafe-libyaml) |
| `untrusted` | 0.9.0 | `ISC` | [github.com/briansmith/untrusted](https://github.com/briansmith/untrusted) |
| `url` | 2.5.8 | `MIT OR Apache-2.0` | [github.com/servo/rust-url](https://github.com/servo/rust-url) |
| `utf8_iter` | 1.0.4 | `Apache-2.0 OR MIT` | [github.com/hsivonen/utf8_iter](https://github.com/hsivonen/utf8_iter) |
| `utoipa` | 5.5.0 | `MIT OR Apache-2.0` | [github.com/juhaku/utoipa](https://github.com/juhaku/utoipa) |
| `utoipa-gen` | 5.5.0 | `MIT OR Apache-2.0` | [github.com/juhaku/utoipa](https://github.com/juhaku/utoipa) |
| `uuid` | 1.23.4 | `Apache-2.0 OR MIT` | [github.com/uuid-rs/uuid](https://github.com/uuid-rs/uuid) |
| `valuable` | 0.1.1 | `MIT` | [github.com/tokio-rs/valuable](https://github.com/tokio-rs/valuable) |
| `vcpkg` | 0.2.15 | `MIT/Apache-2.0` | [github.com/mcgoo/vcpkg-rs](https://github.com/mcgoo/vcpkg-rs) |
| `verifiable` | 0.5.0 | `GPL-3.0-or-later WITH Classpath-exception-2.0` | [github.com/paritytech/verifiable.git](https://github.com/paritytech/verifiable.git) |
| `version_check` | 0.9.5 | `MIT/Apache-2.0` | [github.com/SergioBenitez/version_check](https://github.com/SergioBenitez/version_check) |
| `w3f-pcs` | 0.0.5 | `MIT/Apache-2.0` | [github.com/w3f/fflonk](https://github.com/w3f/fflonk) |
| `w3f-plonk-common` | 0.0.7 | `MIT/Apache-2.0` | [github.com/w3f/ring-proof](https://github.com/w3f/ring-proof) |
| `w3f-ring-proof` | 0.0.8 | `MIT/Apache-2.0` | [github.com/w3f/ring-proof](https://github.com/w3f/ring-proof) |
| `walkdir` | 2.5.0 | `Unlicense/MIT` | [github.com/BurntSushi/walkdir](https://github.com/BurntSushi/walkdir) |
| `want` | 0.3.1 | `MIT` | [github.com/seanmonstar/want](https://github.com/seanmonstar/want) |
| `wasi` | 0.11.1+wasi-snapshot-preview1 | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [github.com/bytecodealliance/wasi](https://github.com/bytecodealliance/wasi) |
| `wasip2` | 1.0.4+wasi-0.2.12 | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [github.com/bytecodealliance/wasi-rs](https://github.com/bytecodealliance/wasi-rs) |
| `wasite` | 0.1.0 | `Apache-2.0 OR BSL-1.0 OR MIT` | [github.com/ardaku/wasite](https://github.com/ardaku/wasite) |
| `wasm-bindgen` | 0.2.126 | `MIT OR Apache-2.0` | [github.com/wasm-bindgen/wasm-bindgen](https://github.com/wasm-bindgen/wasm-bindgen) |
| `wasm-bindgen-futures` | 0.4.76 | `MIT OR Apache-2.0` | [github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/futures](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/futures) |
| `wasm-bindgen-macro` | 0.2.126 | `MIT OR Apache-2.0` | [github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro) |
| `wasm-bindgen-macro-support` | 0.2.126 | `MIT OR Apache-2.0` | [github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro-support](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro-support) |
| `wasm-bindgen-shared` | 0.2.126 | `MIT OR Apache-2.0` | [github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/shared](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/shared) |
| `wasmi` | 0.40.0 | `MIT/Apache-2.0` | [github.com/wasmi-labs/wasmi](https://github.com/wasmi-labs/wasmi) |
| `wasmi_collections` | 0.40.0 | `MIT/Apache-2.0` | [github.com/wasmi-labs/wasmi](https://github.com/wasmi-labs/wasmi) |
| `wasmi_core` | 0.40.0 | `MIT/Apache-2.0` | [github.com/wasmi-labs/wasmi](https://github.com/wasmi-labs/wasmi) |
| `wasmi_ir` | 0.40.0 | `MIT/Apache-2.0` | [github.com/wasmi-labs/wasmi](https://github.com/wasmi-labs/wasmi) |
| `wasmparser` | 0.221.3 | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [github.com/bytecodealliance/wasm-tools/tree/main/crates/wasmparser](https://github.com/bytecodealliance/wasm-tools/tree/main/crates/wasmparser) |
| `web-sys` | 0.3.103 | `MIT OR Apache-2.0` | [github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/web-sys](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/web-sys) |
| `web-time` | 1.1.0 | `MIT OR Apache-2.0` | [github.com/daxpedda/web-time](https://github.com/daxpedda/web-time) |
| `webpki-root-certs` | 0.26.11 | `CDLA-Permissive-2.0` | [github.com/rustls/webpki-roots](https://github.com/rustls/webpki-roots) |
| `webpki-root-certs` | 1.0.8 | `CDLA-Permissive-2.0` | [github.com/rustls/webpki-roots](https://github.com/rustls/webpki-roots) |
| `webpki-roots` | 0.26.11 | `CDLA-Permissive-2.0` | [github.com/rustls/webpki-roots](https://github.com/rustls/webpki-roots) |
| `webpki-roots` | 1.0.8 | `CDLA-Permissive-2.0` | [github.com/rustls/webpki-roots](https://github.com/rustls/webpki-roots) |
| `whoami` | 1.6.1 | `Apache-2.0 OR BSL-1.0 OR MIT` | [github.com/ardaku/whoami](https://github.com/ardaku/whoami) |
| `winapi` | 0.3.9 | `MIT/Apache-2.0` | [github.com/retep998/winapi-rs](https://github.com/retep998/winapi-rs) |
| `winapi-i686-pc-windows-gnu` | 0.4.0 | `MIT/Apache-2.0` | [github.com/retep998/winapi-rs](https://github.com/retep998/winapi-rs) |
| `winapi-util` | 0.1.11 | `Unlicense OR MIT` | [github.com/BurntSushi/winapi-util](https://github.com/BurntSushi/winapi-util) |
| `winapi-x86_64-pc-windows-gnu` | 0.4.0 | `MIT/Apache-2.0` | [github.com/retep998/winapi-rs](https://github.com/retep998/winapi-rs) |
| `windows-link` | 0.2.1 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows-result` | 0.4.1 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows-sys` | 0.45.0 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows-sys` | 0.48.0 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows-sys` | 0.52.0 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows-sys` | 0.59.0 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows-sys` | 0.61.2 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows-targets` | 0.42.2 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows-targets` | 0.48.5 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows-targets` | 0.52.6 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_aarch64_gnullvm` | 0.42.2 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_aarch64_gnullvm` | 0.48.5 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_aarch64_gnullvm` | 0.52.6 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_aarch64_msvc` | 0.42.2 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_aarch64_msvc` | 0.48.5 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_aarch64_msvc` | 0.52.6 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_i686_gnu` | 0.42.2 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_i686_gnu` | 0.48.5 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_i686_gnu` | 0.52.6 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_i686_gnullvm` | 0.52.6 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_i686_msvc` | 0.42.2 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_i686_msvc` | 0.48.5 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_i686_msvc` | 0.52.6 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_gnu` | 0.42.2 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_gnu` | 0.48.5 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_gnu` | 0.52.6 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_gnullvm` | 0.42.2 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_gnullvm` | 0.48.5 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_gnullvm` | 0.52.6 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_msvc` | 0.42.2 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_msvc` | 0.48.5 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `windows_x86_64_msvc` | 0.52.6 | `MIT OR Apache-2.0` | [github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs) |
| `winnow` | 1.0.3 | `MIT` | [github.com/winnow-rs/winnow](https://github.com/winnow-rs/winnow) |
| `wit-bindgen` | 0.57.1 | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | [github.com/bytecodealliance/wit-bindgen](https://github.com/bytecodealliance/wit-bindgen) |
| `writeable` | 0.6.3 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `wyz` | 0.5.1 | `MIT` | [github.com/myrrlyn/wyz](https://github.com/myrrlyn/wyz) |
| `x25519-dalek` | 2.0.1 | `BSD-3-Clause` | [github.com/dalek-cryptography/curve25519-dalek/tree/main/x25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/x25519-dalek) |
| `x509-parser` | 0.17.0 | `MIT OR Apache-2.0` | [github.com/rusticata/x509-parser.git](https://github.com/rusticata/x509-parser.git) |
| `yap` | 0.12.0 | `MIT` | [github.com/jsdw/yap](https://github.com/jsdw/yap) |
| `yasna` | 0.5.2 | `MIT OR Apache-2.0` | [github.com/qnighy/yasna.rs](https://github.com/qnighy/yasna.rs) |
| `yoke` | 0.8.3 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `yoke-derive` | 0.8.2 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `zerocopy` | 0.8.53 | `BSD-2-Clause OR Apache-2.0 OR MIT` | [github.com/google/zerocopy](https://github.com/google/zerocopy) |
| `zerocopy-derive` | 0.8.53 | `BSD-2-Clause OR Apache-2.0 OR MIT` | [github.com/google/zerocopy](https://github.com/google/zerocopy) |
| `zerofrom` | 0.1.8 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `zerofrom-derive` | 0.1.7 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `zeroize` | 1.9.0 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/utils](https://github.com/RustCrypto/utils) |
| `zeroize_derive` | 1.5.0 | `Apache-2.0 OR MIT` | [github.com/RustCrypto/utils](https://github.com/RustCrypto/utils) |
| `zerotrie` | 0.2.4 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `zerovec` | 0.11.6 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `zerovec-derive` | 0.11.3 | `Unicode-3.0` | [github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) |
| `zmij` | 1.0.21 | `MIT` | [github.com/dtolnay/zmij](https://github.com/dtolnay/zmij) |
