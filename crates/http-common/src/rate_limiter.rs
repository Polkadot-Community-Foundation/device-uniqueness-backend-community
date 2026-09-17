use axum::extract::Request;
pub use config::Config;
use governor::{
    clock::{self, Clock, QuantaClock},
    NotUntil, Quota,
};
use state_store::MokaStateStore;
use std::{num::NonZeroU32, sync::Arc, time::Duration};
mod config;
mod state_store;

#[derive(Clone)]
pub struct RateLimiter {
    limiter: Arc<governor::RateLimiter<String, MokaStateStore, clock::QuantaClock>>,
}

impl RateLimiter {
    pub fn new(config: Config) -> Result<Self, anyhow::Error> {
        let Ok(_) = tokio::runtime::Handle::try_current() else {
            anyhow::bail!("Failed to construct the rate-limiter, no Tokio runtime detected")
        };
        if config.max_burst == 0 {
            anyhow::bail!("Failed to construct the rate-limiter, max-burst must be non-zero")
        };
        Ok({
            let quota = {
                let replenish_interval_ns =
                    Duration::from_secs(config.window_secs).as_nanos() / (config.max_burst as u128);
                Quota::with_period(Duration::from_nanos(replenish_interval_ns as u64))
                    .expect("rate limiter expects a valid period")
                    .allow_burst(
                        NonZeroU32::new(config.max_burst)
                            .expect("can't use 0 as rate limiter's max_burst_size"),
                    )
            };
            let state = MokaStateStore::new(config.entry_limit, config.tti_secs);
            let clock = QuantaClock::default();
            let state = governor::RateLimiter::new(quota, state, clock);
            Self {
                limiter: Arc::new(state),
            }
        })
    }
}
impl RateLimiter {
    /// Checks the limit for a given key
    /// If the rate limit is reached, check_key returns information about the earliest time that a cell might be allowed through again under that key.
    pub async fn allow(&self, key: String) -> Result<(), NotUntil<clock::QuantaInstant>> {
        self.limiter.check_key(&key)
    }

    /// returns current time offset on the clock
    pub fn current_time(&self) -> clock::QuantaInstant {
        self.limiter.clock().now()
    }

    /// extracts IP from request
    pub fn client_ip(&self, req: &Request) -> String {
        let headers = req.headers();
        if let Ok(addr) = client_ip::rightmost_x_forwarded_for(headers) {
            return addr.to_string();
        };

        if let Ok(addr) = client_ip::cf_connecting_ip(headers) {
            return addr.to_string();
        };

        if let Ok(addr) = client_ip::true_client_ip(headers) {
            return addr.to_string();
        };

        "unknown".to_owned()
    }
}

#[cfg(test)]
mod test {
    use crate::{rate_limiter::Config, RateLimiter};

    #[tokio::test]
    async fn retry_after() {
        let limit =
            RateLimiter::new(Config::default().set_window_secs(10).set_max_burst(1)).unwrap();

        limit.allow("test".to_owned()).await.unwrap();
        let timeout = limit
            .allow("test".to_owned())
            .await
            .unwrap_err()
            .wait_time_from(limit.current_time())
            .as_secs();
        assert!(timeout > 0);
    }
}
