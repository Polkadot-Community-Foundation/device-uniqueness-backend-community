#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Rate limiter config
pub struct Config {
    /// Window duration per rate-limited key
    /// Default: 60 secs
    pub(super) window_secs: u64,
    /// Max amount of requests during rate-limiter window
    /// Default: 30
    pub(super) max_burst: u32,
    /// Max amount of keys that the rate-limiter can hold
    /// Should be described as power of 2 to better align with table growth and resizing
    /// Default: 8192
    pub(super) entry_limit: u64,
    /// Time-To-Idle expiration
    /// Default: 60 mins
    pub(super) tti_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            window_secs: 60,
            max_burst: 30,
            entry_limit: 8192,
            tti_secs: 60 * 60,
        }
    }
}

impl Config {
    pub fn set_window_secs(mut self, window_secs: u64) -> Self {
        self.window_secs = window_secs;
        self
    }

    pub fn set_max_burst(mut self, max_burst: u32) -> Self {
        self.max_burst = max_burst;
        self
    }

    pub fn set_entry_limit(mut self, entry_limit: u64) -> Self {
        self.entry_limit = entry_limit;
        self
    }

    pub fn set_tti_secs(mut self, tti_secs: u64) -> Self {
        self.tti_secs = tti_secs;
        self
    }
}
