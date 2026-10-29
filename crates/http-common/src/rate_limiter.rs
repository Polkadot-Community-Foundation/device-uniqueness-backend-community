use axum::extract::Request;
pub use config::Config;
use governor::{
    clock::{self, Clock, QuantaClock},
    NotUntil, Quota,
};
use state_store::MokaStateStore;
use std::{
    num::NonZeroU32,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
mod config;
mod state_store;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Paid {
    Quota,
    Credit,
}

#[derive(Clone)]
pub struct RateLimiter {
    limiter: Arc<governor::RateLimiter<String, MokaStateStore, clock::QuantaClock>>,
    credits: moka::sync::Cache<String, Arc<AtomicU32>>,
    max_burst: u32,
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
            let credits = moka::sync::Cache::builder()
                .max_capacity(config.entry_limit)
                .time_to_idle(Duration::from_secs(config.tti_secs))
                .build();
            Self {
                limiter: Arc::new(state),
                credits,
                max_burst: config.max_burst,
            }
        })
    }
}
impl RateLimiter {
    /// Checks the limit for a given key
    /// If the rate limit is reached, check_key returns information about the earliest time that a cell might be allowed through again under that key.
    pub async fn allow(&self, key: String) -> Result<Paid, NotUntil<clock::QuantaInstant>> {
        if self.spend_credit(&key) {
            return Ok(Paid::Credit);
        }
        self.limiter.check_key(&key).map(|()| Paid::Quota)
    }

    pub fn refund(&self, key: String, paid: Paid) {
        if paid != Paid::Quota {
            return;
        }
        let banked = self.credits.get_with(key, || Arc::new(AtomicU32::new(0)));
        let _ = banked.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
            (held < self.max_burst).then_some(held + 1)
        });
    }

    /// Spend one banked credit for `key`, if it has any.
    fn spend_credit(&self, key: &str) -> bool {
        let Some(banked) = self.credits.get(key) else {
            return false;
        };
        banked
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                held.checked_sub(1)
            })
            .is_ok()
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
    use crate::{
        rate_limiter::{Config, Paid},
        RateLimiter,
    };

    #[tokio::test]
    async fn a_refund_returns_exactly_one_request_to_the_key() {
        let limit =
            RateLimiter::new(Config::default().set_window_secs(10).set_max_burst(1)).unwrap();

        let paid = limit.allow("test".to_owned()).await.unwrap();
        assert_eq!(paid, Paid::Quota);
        assert!(limit.allow("test".to_owned()).await.is_err());

        limit.refund("test".to_owned(), paid);
        assert_eq!(limit.allow("test".to_owned()).await.unwrap(), Paid::Credit);
        // One refund, one request: the credit is not reusable.
        assert!(limit.allow("test".to_owned()).await.is_err());
        // And it is the refunded key alone that got it back.
        limit.refund("test".to_owned(), Paid::Quota);
        let _ = limit.allow("other".to_owned()).await.unwrap();
        assert!(limit.allow("other".to_owned()).await.is_err());
    }

    #[tokio::test]
    async fn banked_credits_stop_at_the_burst_ceiling() {
        let limit =
            RateLimiter::new(Config::default().set_window_secs(600).set_max_burst(2)).unwrap();

        for _ in 0..10 {
            limit.refund("test".to_owned(), Paid::Quota);
        }
        for _ in 0..2 {
            let _ = limit.allow("test".to_owned()).await.unwrap();
        }
        // The two banked credits, then the quota's own two.
        for _ in 0..2 {
            let _ = limit.allow("test".to_owned()).await.unwrap();
        }
        assert!(limit.allow("test".to_owned()).await.is_err());
    }

    #[tokio::test]
    async fn a_credit_paid_request_cannot_refund_itself() {
        let limit =
            RateLimiter::new(Config::default().set_window_secs(600).set_max_burst(1)).unwrap();

        let paid = limit.allow("test".to_owned()).await.unwrap();
        assert_eq!(paid, Paid::Quota);
        limit.refund("test".to_owned(), paid);

        let paid = limit.allow("test".to_owned()).await.unwrap();
        assert_eq!(paid, Paid::Credit);
        limit.refund("test".to_owned(), paid);
        assert!(limit.allow("test".to_owned()).await.is_err());
    }

    #[tokio::test]
    async fn retry_after() {
        let limit =
            RateLimiter::new(Config::default().set_window_secs(10).set_max_burst(1)).unwrap();

        let _ = limit.allow("test".to_owned()).await.unwrap();
        let timeout = limit
            .allow("test".to_owned())
            .await
            .unwrap_err()
            .wait_time_from(limit.current_time())
            .as_secs();
        assert!(timeout > 0);
    }
}
