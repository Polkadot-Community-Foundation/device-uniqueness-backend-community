// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub(crate) mod client;

pub use client::Client;

/// The two-bit state Apple stores per device, as returned by
/// `query_two_bits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitState {
    /// First bit (unused by the legacy encoding; kept for fidelity).
    pub bit0: bool,
    /// Second bit: set when the device has claimed its free registration.
    pub bit1: bool,
}

impl BitState {
    /// Whether this state marks a device that already claimed its free
    /// registration (legacy encoding: `!bit0 && bit1`).
    pub fn is_registered(self) -> bool {
        !self.bit0 && self.bit1
    }
}

/// What the DeviceCheck lookup said about this request's device.
#[derive(Debug)]
pub enum Verdict {
    /// Token present and the device has not claimed a free registration.
    Available,
    /// Token present and the device already claimed a free registration.
    AlreadyUsed,
    /// Apple could not be consulted (API failure/outage).
    Failed(String),
    /// No usable device token on the request.
    Inactive,
}

/// The claim-route decision derived from a verdict + enforcement posture.
/// A straight port of the legacy `gate.workflow.ts` table.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Proceed and mark the device as used (hard mode, fresh device).
    Register,
    /// Proceed without blocking; `available` is advisory (soft mode / no
    /// verdict). `None` = DeviceCheck said nothing (failed/inactive).
    Proceed { available: Option<bool> },
    /// Device already used its free registration (hard mode) — the caller
    /// maps this to the 200 ineligible outcome, not an error.
    Blocked,
    /// Hard mode requires a device token and none was usable.
    TokenRequired,
    /// Hard mode and Apple was unavailable — the caller surfaces a
    /// DeviceCheck-unavailable failure rather than deciding blindly.
    Unavailable(String),
}

/// Map a DeviceCheck verdict onto the claim decision for the given posture.
pub fn decide_gate(verdict: Verdict, enforced: bool) -> Decision {
    match (verdict, enforced) {
        (Verdict::Available, true) => Decision::Register,
        (Verdict::Available, false) => Decision::Proceed {
            available: Some(true),
        },
        (Verdict::AlreadyUsed, true) => Decision::Blocked,
        (Verdict::AlreadyUsed, false) => Decision::Proceed {
            available: Some(false),
        },
        (Verdict::Failed(cause), true) => Decision::Unavailable(cause),
        (Verdict::Failed(_), false) => Decision::Proceed { available: None },
        (Verdict::Inactive, true) => Decision::TokenRequired,
        (Verdict::Inactive, false) => Decision::Proceed { available: None },
    }
}

/// Query Apple for this request's device token and classify it. Mirrors the
/// legacy device-check middleware: no token → [`Verdict::Inactive`]; a query
/// failure → [`Verdict::Failed`]; otherwise [`Verdict::AlreadyUsed`] /
/// [`Verdict::Available`].
pub async fn evaluate(client: &Client, device_token: Option<&[u8]>) -> Verdict {
    let Some(token) = device_token else {
        return Verdict::Inactive;
    };
    match client.already_used(token).await {
        Ok(true) => Verdict::AlreadyUsed,
        Ok(false) => Verdict::Available,
        Err(err) => Verdict::Failed(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_state_encodes_the_legacy_used_marker() {
        assert!(BitState {
            bit0: false,
            bit1: true
        }
        .is_registered());
        for (bit0, bit1) in [(false, false), (true, false), (true, true)] {
            assert!(!BitState { bit0, bit1 }.is_registered());
        }
    }

    #[test]
    fn gate_decision_table_matches_legacy() {
        assert_eq!(decide_gate(Verdict::Available, true), Decision::Register);
        assert_eq!(
            decide_gate(Verdict::Available, false),
            Decision::Proceed {
                available: Some(true)
            }
        );
        assert_eq!(decide_gate(Verdict::AlreadyUsed, true), Decision::Blocked);
        assert_eq!(
            decide_gate(Verdict::AlreadyUsed, false),
            Decision::Proceed {
                available: Some(false)
            }
        );
        assert!(matches!(
            decide_gate(Verdict::Failed("outage".into()), true),
            Decision::Unavailable(_)
        ));
        assert_eq!(
            decide_gate(Verdict::Failed("outage".into()), false),
            Decision::Proceed { available: None }
        );
        assert_eq!(
            decide_gate(Verdict::Inactive, true),
            Decision::TokenRequired
        );
        assert_eq!(
            decide_gate(Verdict::Inactive, false),
            Decision::Proceed { available: None }
        );
    }
}
