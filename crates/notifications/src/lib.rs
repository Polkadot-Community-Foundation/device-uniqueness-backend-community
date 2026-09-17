// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub mod config;
pub mod http;
pub mod notify;
pub mod openapi;
pub mod platform;
pub mod provider;

pub use config::{Config, ConfigError};
pub use http::{routes, AppState};
pub use http_common::{rate_limiter::Config as RateLimiterConfig, RateLimiter};
pub use jwt_verify::{JwtError, VerifiedClaims, Verifier};
pub use notify::{NotifyResponse, PushError};
pub use platform::Platform;
pub use provider::apns::{ApnsConfig, ApnsEnvironment, ApnsProvider};
pub use provider::fcm::{FcmConfig, FcmProvider};
pub use provider::{
    ProviderError, PushOutcome, PushProvider, PushRequest, RecordingProvider, UnconfiguredProvider,
};
