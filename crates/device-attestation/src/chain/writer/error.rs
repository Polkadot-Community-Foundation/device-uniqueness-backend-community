// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Recording a row as landed on chain.
    Landing,
    /// Recording a terminal failure.
    Failing,
    /// Recording a reservation signature that aged out.
    Expiring,
    /// Scheduling one row's own retry.
    Retrying,
    /// Backing a row off without spending its attempt.
    Parking,
    /// Re-queueing a whole batch at an unchanged attempt.
    Deferring,
    /// Marking rows `SUBMITTING` before broadcast.
    Submitting,
    /// Claiming and draining a set.
    Draining,
    /// Awaiting finalization of a submitted extrinsic.
    Finalizing,
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            Op::Landing => "recording a row as landed",
            Op::Failing => "failing a row",
            Op::Expiring => "expiring a reservation",
            Op::Retrying => "scheduling a retry",
            Op::Parking => "parking a row",
            Op::Deferring => "re-queueing a batch",
            Op::Submitting => "marking rows submitting",
            Op::Draining => "draining",
            Op::Finalizing => "awaiting finalization",
        };
        f.write_str(what)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WriterError {
    /// A second writer took the lease, so this one must stop writing at once.
    #[error("lost the writer lease while {0}")]
    LeaseLost(Op),

    /// The outbox database.
    #[error(transparent)]
    Db(#[from] sqlx::Error),

    /// Anything the chain did, or that happened while talking to it.
    #[error(transparent)]
    Chain(#[from] anyhow::Error),
}

impl WriterError {
    /// Whether this is the routine "somebody else holds the lease now" case.
    pub fn is_lease_lost(&self) -> bool {
        matches!(self, WriterError::LeaseLost(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chain_error_renders_without_a_prefix() {
        let reason = "Invalid transaction: Inability to pay some fees";
        let wrapped = WriterError::Chain(anyhow::anyhow!(reason));
        assert_eq!(wrapped.to_string(), reason);
        assert!(!wrapped.is_lease_lost());
    }

    #[test]
    fn a_lost_lease_names_what_it_interrupted() {
        let error = WriterError::LeaseLost(Op::Landing);
        assert_eq!(
            error.to_string(),
            "lost the writer lease while recording a row as landed"
        );
        assert!(error.is_lease_lost());
    }

    #[test]
    fn no_lease_lost_message_reads_as_a_chain_refusal() {
        use super::super::engine::{classify_submit_failure, SubmitFailureAction};

        for op in [
            Op::Landing,
            Op::Failing,
            Op::Expiring,
            Op::Retrying,
            Op::Parking,
            Op::Deferring,
            Op::Submitting,
            Op::Draining,
            Op::Finalizing,
        ] {
            let rendered = WriterError::LeaseLost(op).to_string();
            assert_eq!(
                classify_submit_failure(&rendered, None, [7; 32], 1, 8),
                SubmitFailureAction::Retry,
                "{op} must not classify as anything special: {rendered}"
            );
        }
    }
}
