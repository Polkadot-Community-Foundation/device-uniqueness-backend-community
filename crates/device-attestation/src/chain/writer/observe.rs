// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use sqlx::PgPool;
use subxt::{utils::AccountId32, OnlineClient};

use super::{hex_account, WriterConfig};
use crate::chain::outbox;

pub(super) fn record_writer_info(config: &WriterConfig, signer: &AccountId32) {
    metrics::gauge!(
        "dub_writer_info",
        "signer" => hex_account(&signer.0),
        "attester" => hex_account(&config.attester),
        "dotns_lane" => if config.dotns_gateway_enabled { "enabled" } else { "disabled" }
    )
    .set(1.0);
}

pub(super) async fn record_spec_version<C: subxt::Config>(
    chain: &'static str,
    client: &OnlineClient<C>,
) {
    match client.at_current_block().await {
        Ok(at) => {
            metrics::gauge!("dub_chain_spec_version", "chain" => chain)
                .set(at.spec_version() as f64);
            metrics::gauge!("dub_chain_transaction_version", "chain" => chain)
                .set(at.transaction_version() as f64);
        }
        Err(error) => {
            tracing::warn!(chain, %error, "reading the runtime version failed");
        }
    }
}

const SUBMIT_LANES: [&str; 2] = ["people", "dotns"];
const SUBMIT_OUTCOMES: [&str; 3] = ["ok", "retry", "terminal"];

pub(super) fn zero_init_submit_outcomes() {
    for lane in SUBMIT_LANES {
        for outcome in SUBMIT_OUTCOMES {
            metrics::counter!("dub_chain_submit_total", "lane" => lane, "outcome" => outcome)
                .absolute(0);
        }
        metrics::counter!("dub_chain_batch_failed_total", "lane" => lane).absolute(0);
        metrics::counter!("dub_chain_batch_item_failed_total", "lane" => lane).absolute(0);
    }
}

pub(super) fn record_submit_outcome(lane: &'static str, outcome: &'static str) {
    metrics::counter!("dub_chain_submit_total", "lane" => lane, "outcome" => outcome).increment(1);
}

pub(super) async fn record_outbox_gauges(pool: &PgPool) -> Result<(), sqlx::Error> {
    for (status, depth) in outbox::depth_by_status(pool).await? {
        let status = status.as_str();
        metrics::gauge!("dub_outbox_depth", "status" => status).set(depth.depth as f64);
        metrics::gauge!("dub_outbox_oldest_age_seconds", "status" => status)
            .set(depth.oldest_age_secs.unwrap_or(0.0));
    }
    for (status, depth) in outbox::dotns_depth_by_status(pool).await? {
        let status = status.as_str();
        metrics::gauge!("dub_dotns_outbox_depth", "status" => status).set(depth.depth as f64);
        metrics::gauge!("dub_dotns_outbox_oldest_age_seconds", "status" => status)
            .set(depth.oldest_age_secs.unwrap_or(0.0));
    }
    Ok(())
}
