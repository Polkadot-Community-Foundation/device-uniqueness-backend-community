// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::net::SocketAddr;

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_STORAGE_PAGE_SIZE: &str = "1000";
const MAX_STORAGE_PAGE_SIZE: u32 = 1_000;
const DEFAULT_SYNC_INTERVAL_SECS: &str = "30";
const MAX_SYNC_INTERVAL_SECS: u32 = 86_400;
const DEFAULT_SEARCH_RATE_LIMIT: &str = "60";
const DEFAULT_SEARCH_RATE_LIMIT_WINDOW_SECS: &str = "60";
const DEFAULT_POC_DIFFICULTY_BITS: &str = "16";
const MIN_POC_HMAC_SECRET_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub bind_addr: SocketAddr,
    /// Service-owned Postgres connection string.
    pub database_url: String,
    /// People Chain WebSocket RPC endpoint.
    pub people_rpc_url: String,
    /// Maximum number of storage entries requested and written per page.
    pub storage_page_size: u32,
    /// Longest the sync loop waits without a best-block header, in seconds,
    /// before forcing a pass anyway. Not a poll interval — the timer resets on
    /// every header, so on a healthy subscription it never fires.
    pub sync_interval_secs: u32,
    /// Requests per window per client IP on the public search route.
    pub search_rate_limit: u32,
    /// Rate-limit window, in seconds, for the public search route.
    pub search_rate_limit_window_secs: u32,
    /// Required leading zero bits in a puzzle solution (1–32).
    pub poc_difficulty_bits: u8,
    pub speculative_indexing: bool,
    /// Input keying material for the puzzle HMAC.
    ///
    /// `Some` exactly when `POC_ENABLED=true`, which is what mounts the gate and
    /// its issuance route; `None` (the default) leaves the service behaving as
    /// it did before the gate existed.
    pub poc_hmac_secret: Option<String>,
}

pub use http_common::config::ConfigError;

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_getter(|key| std::env::var(key).ok())
    }

    /// Read configuration through a caller-provided lookup function.
    pub fn from_getter<F>(get: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let database_url = required(&get, "INDEXER_DATABASE_URL")?;
        let people_rpc_url = required(&get, "PEOPLE_RPC_URL")?;
        let bind_addr = parse(
            "BIND_ADDR",
            get("BIND_ADDR").as_deref().unwrap_or(DEFAULT_BIND_ADDR),
        )?;
        let storage_page_size = parse(
            "STORAGE_PAGE_SIZE",
            get("STORAGE_PAGE_SIZE")
                .as_deref()
                .unwrap_or(DEFAULT_STORAGE_PAGE_SIZE),
        )?;
        if !(1..=MAX_STORAGE_PAGE_SIZE).contains(&storage_page_size) {
            return Err(ConfigError::Invalid {
                key: "STORAGE_PAGE_SIZE",
                reason: format!("must be between 1 and {MAX_STORAGE_PAGE_SIZE}"),
            });
        }
        let sync_interval_secs = parse(
            "SYNC_INTERVAL_SECS",
            get("SYNC_INTERVAL_SECS")
                .as_deref()
                .unwrap_or(DEFAULT_SYNC_INTERVAL_SECS),
        )?;
        if !(1..=MAX_SYNC_INTERVAL_SECS).contains(&sync_interval_secs) {
            return Err(ConfigError::Invalid {
                key: "SYNC_INTERVAL_SECS",
                reason: format!("must be between 1 and {MAX_SYNC_INTERVAL_SECS}"),
            });
        }
        let search_rate_limit = parse(
            "SEARCH_RATE_LIMIT",
            get("SEARCH_RATE_LIMIT")
                .as_deref()
                .unwrap_or(DEFAULT_SEARCH_RATE_LIMIT),
        )?;
        if search_rate_limit == 0 {
            return Err(ConfigError::Invalid {
                key: "SEARCH_RATE_LIMIT",
                reason: "must be at least 1".to_string(),
            });
        }
        let search_rate_limit_window_secs = parse(
            "SEARCH_RATE_LIMIT_WINDOW_SECS",
            get("SEARCH_RATE_LIMIT_WINDOW_SECS")
                .as_deref()
                .unwrap_or(DEFAULT_SEARCH_RATE_LIMIT_WINDOW_SECS),
        )?;
        if search_rate_limit_window_secs == 0 {
            return Err(ConfigError::Invalid {
                key: "SEARCH_RATE_LIMIT_WINDOW_SECS",
                reason: "must be at least 1".to_string(),
            });
        }

        let speculative_indexing = parse_bool(&get, "SPECULATIVE_INDEXING_ENABLED", true)?;

        let poc_enabled = parse_bool(&get, "POC_ENABLED", false)?;
        let poc_difficulty_bits = parse(
            "POC_DIFFICULTY_BITS",
            get("POC_DIFFICULTY_BITS")
                .as_deref()
                .unwrap_or(DEFAULT_POC_DIFFICULTY_BITS),
        )?;
        if !(1..=32).contains(&poc_difficulty_bits) {
            return Err(ConfigError::Invalid {
                key: "POC_DIFFICULTY_BITS",
                reason: "must be between 1 and 32".to_string(),
            });
        }
        // Required only with the gate on, so existing deployments keep booting
        // untouched while `POC_ENABLED` stays false.
        let poc_hmac_secret = if poc_enabled {
            let secret = required(&get, "POC_HMAC_SECRET")?;
            // HKDF spreads the input over the key but adds no entropy, and every
            // issued puzzle hands out a known message/HMAC pair — so a short
            // secret is recoverable offline, after which anyone can mint
            // `difficulty = 1` puzzles. Require real key material.
            if secret.len() < MIN_POC_HMAC_SECRET_LEN {
                return Err(ConfigError::Invalid {
                    key: "POC_HMAC_SECRET",
                    reason: format!(
                        "must be at least {MIN_POC_HMAC_SECRET_LEN} characters of random material"
                    ),
                });
            }
            Some(secret)
        } else {
            None
        };

        Ok(Self {
            bind_addr,
            database_url,
            people_rpc_url,
            storage_page_size,
            sync_interval_secs,
            search_rate_limit,
            search_rate_limit_window_secs,
            speculative_indexing,
            poc_difficulty_bits,
            poc_hmac_secret,
        })
    }
}

/// Parse a boolean env var strictly: only `true`/`false` (any case) are
/// accepted, so a typo can never silently disable a security gate.
fn parse_bool<F>(get: &F, key: &'static str, default: bool) -> Result<bool, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    match get(key) {
        // Only an *absent* variable takes the default. An explicitly empty value
        // is a deployment mistake, and defaulting it would fail open on a
        // security gate.
        None => Ok(default),
        Some(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(ConfigError::Invalid {
                key,
                reason: format!("expected `true` or `false`, got `{other}`"),
            }),
        },
    }
}

fn required<F>(get: &F, key: &'static str) -> Result<String, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    get(key)
        .filter(|value| !value.trim().is_empty())
        .ok_or(ConfigError::Missing(key))
}

fn parse<T>(key: &'static str, raw: &str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    raw.parse().map_err(|error: T::Err| ConfigError::Invalid {
        key,
        reason: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{Config, ConfigError};

    const POC_SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn config(values: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let values = values
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect::<HashMap<_, _>>();
        Config::from_getter(|key| values.get(key).cloned())
    }

    #[test]
    fn requires_database_and_people_rpc_urls() {
        assert!(matches!(
            config(&[]),
            Err(ConfigError::Missing("INDEXER_DATABASE_URL"))
        ));
        assert!(matches!(
            config(&[("INDEXER_DATABASE_URL", "postgres://localhost/read")]),
            Err(ConfigError::Missing("PEOPLE_RPC_URL"))
        ));
    }

    #[test]
    fn applies_defaults_and_accepts_overrides() {
        let defaults = config(&[
            ("INDEXER_DATABASE_URL", "postgres://localhost/read"),
            ("PEOPLE_RPC_URL", "ws://localhost:9944"),
        ])
        .expect("valid defaults");
        assert_eq!(defaults.bind_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(defaults.storage_page_size, 1000);
        assert_eq!(defaults.sync_interval_secs, 30);
        assert_eq!(defaults.search_rate_limit, 60);
        assert_eq!(defaults.search_rate_limit_window_secs, 60);
        assert_eq!(defaults.poc_difficulty_bits, 16);
        assert_eq!(defaults.poc_hmac_secret, None);

        let overridden = config(&[
            ("INDEXER_DATABASE_URL", "postgres://localhost/read"),
            ("PEOPLE_RPC_URL", "ws://localhost:9944"),
            ("BIND_ADDR", "127.0.0.1:9000"),
            ("STORAGE_PAGE_SIZE", "250"),
            ("SYNC_INTERVAL_SECS", "5"),
            ("SEARCH_RATE_LIMIT", "10"),
            ("SEARCH_RATE_LIMIT_WINDOW_SECS", "15"),
        ])
        .expect("valid overrides");
        assert_eq!(overridden.bind_addr.to_string(), "127.0.0.1:9000");
        assert_eq!(overridden.storage_page_size, 250);
        assert_eq!(overridden.sync_interval_secs, 5);
        assert_eq!(overridden.search_rate_limit, 10);
        assert_eq!(overridden.search_rate_limit_window_secs, 15);
    }

    #[test]
    fn rejects_zero_and_excessive_page_sizes() {
        for value in ["0", "1001"] {
            let error = config(&[
                ("INDEXER_DATABASE_URL", "postgres://localhost/read"),
                ("PEOPLE_RPC_URL", "ws://localhost:9944"),
                ("STORAGE_PAGE_SIZE", value),
            ])
            .expect_err("invalid page size");
            assert!(matches!(
                error,
                ConfigError::Invalid {
                    key: "STORAGE_PAGE_SIZE",
                    ..
                }
            ));
        }
    }

    #[test]
    fn rejects_zero_and_excessive_sync_intervals() {
        for value in ["0", "86401"] {
            let error = config(&[
                ("INDEXER_DATABASE_URL", "postgres://localhost/read"),
                ("PEOPLE_RPC_URL", "ws://localhost:9944"),
                ("SYNC_INTERVAL_SECS", value),
            ])
            .expect_err("invalid sync interval");
            assert!(matches!(
                error,
                ConfigError::Invalid {
                    key: "SYNC_INTERVAL_SECS",
                    ..
                }
            ));
        }
    }

    #[test]
    fn rejects_zero_search_rate_limit() {
        let error = config(&[
            ("INDEXER_DATABASE_URL", "postgres://localhost/read"),
            ("PEOPLE_RPC_URL", "ws://localhost:9944"),
            ("SEARCH_RATE_LIMIT", "0"),
        ])
        .expect_err("invalid search rate limit");
        assert!(matches!(
            error,
            ConfigError::Invalid {
                key: "SEARCH_RATE_LIMIT",
                ..
            }
        ));
    }

    #[test]
    fn poc_secret_is_required_only_when_the_gate_is_enabled() {
        let base = [
            ("INDEXER_DATABASE_URL", "postgres://localhost/read"),
            ("PEOPLE_RPC_URL", "ws://localhost:9944"),
        ];
        let enabled_without_secret = config(&[base[0], base[1], ("POC_ENABLED", "true")])
            .expect_err("secret is required with the gate on");
        assert!(matches!(
            enabled_without_secret,
            ConfigError::Missing("POC_HMAC_SECRET")
        ));

        let enabled = config(&[
            base[0],
            base[1],
            ("POC_ENABLED", "true"),
            ("POC_HMAC_SECRET", POC_SECRET),
            ("POC_DIFFICULTY_BITS", "8"),
        ])
        .expect("valid gate config");
        assert_eq!(enabled.poc_hmac_secret.as_deref(), Some(POC_SECRET));
        assert_eq!(enabled.poc_difficulty_bits, 8);
    }

    #[test]
    fn rejects_short_or_empty_poc_secret() {
        let base = [
            ("INDEXER_DATABASE_URL", "postgres://localhost/read"),
            ("PEOPLE_RPC_URL", "ws://localhost:9944"),
        ];
        assert!(matches!(
            config(&[
                base[0],
                base[1],
                ("POC_ENABLED", "true"),
                ("POC_HMAC_SECRET", "too-short"),
            ]),
            Err(ConfigError::Invalid {
                key: "POC_HMAC_SECRET",
                ..
            })
        ));
        assert!(matches!(
            config(&[
                base[0],
                base[1],
                ("POC_ENABLED", "true"),
                ("POC_HMAC_SECRET", "   "),
            ]),
            Err(ConfigError::Missing("POC_HMAC_SECRET"))
        ));
    }

    #[test]
    fn an_explicitly_empty_poc_flag_is_rejected_not_defaulted() {
        assert!(matches!(
            config(&[
                ("INDEXER_DATABASE_URL", "postgres://localhost/read"),
                ("PEOPLE_RPC_URL", "ws://localhost:9944"),
                ("POC_ENABLED", ""),
            ]),
            Err(ConfigError::Invalid {
                key: "POC_ENABLED",
                ..
            })
        ));
    }

    #[test]
    fn rejects_malformed_poc_flag_and_difficulty() {
        let base = [
            ("INDEXER_DATABASE_URL", "postgres://localhost/read"),
            ("PEOPLE_RPC_URL", "ws://localhost:9944"),
        ];
        assert!(matches!(
            config(&[base[0], base[1], ("POC_ENABLED", "treu")]),
            Err(ConfigError::Invalid {
                key: "POC_ENABLED",
                ..
            })
        ));
        for value in ["0", "33"] {
            assert!(matches!(
                config(&[base[0], base[1], ("POC_DIFFICULTY_BITS", value)]),
                Err(ConfigError::Invalid {
                    key: "POC_DIFFICULTY_BITS",
                    ..
                })
            ));
        }
    }
}
