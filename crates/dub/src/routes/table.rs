// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

/// How a row matches, in terms both edges can render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// A path prefix that does **not** require a trailing slash:
    /// `/api/v1/notify` also owns `/api/v1/notifyfoo`.
    Prefix(&'static str),
    /// A path prefix that requires the separator: `/api/v1/turn/` owns
    /// `/api/v1/turn/issue` but not `/api/v1/turning`.
    PrefixSlash(&'static str),
    CatchAll,
}

#[derive(Debug, Clone, Copy)]
pub struct Row {
    /// Stable identifier, used as the Traefik route name and the Caddy comment.
    pub name: &'static str,
    /// The owning role — the same string as the compose service and `--role`.
    pub owner: &'static str,
    /// Positional index into the Caddy snippet's arguments. The snippet takes
    /// upstreams positionally, so this is what binds a row to a site block's
    /// upstream list.
    pub caddy_arg: usize,
    pub matches: Match,
    /// Traefik router priority; higher wins. Caddy needs none — its `handle`
    /// blocks are first-match-wins in file order, which is why `TABLE` order is
    /// itself meaningful.
    pub priority: u16,
    /// The prefix is stripped before the upstream sees the request.
    pub strip_prefix: bool,
    /// One instance serves every environment, so a multi-environment deployment
    /// keeps the route live even where the service is not deployed.
    pub shared: bool,
    /// Why this row exists. Rendered into both artifacts, because a route table
    /// without its reasons is the thing people edit wrongly.
    pub why: &'static [&'static str],
}

/// The ownership map, in **Caddy's evaluation order**: first match wins, so the
/// catch-all is last and the carve-outs come before what they carve out of.
pub const TABLE: &[Row] = &[
    Row {
        name: "docs",
        owner: "api-docs",
        caddy_arg: usize::MAX, // served in-process, not proxied to an upstream
        matches: Match::Prefix("/docs"),
        priority: 110,
        strip_prefix: true,
        shared: false,
        why: &[
            "The committed API reference. Caddy file-serves it; a deployment that serves it from a",
            "static server instead is still in the ownership map, and must strip the same way. The",
            "prefix is STRIPPED before the server sees it — without that the static server is handed",
            "/docs/openapi.json, looks for it under its document root and 404s, while its readiness",
            "probe stays green. Ownership parity is not path parity.",
        ],
    },
    Row {
        name: "username-search",
        owner: "username-indexer",
        caddy_arg: 1,
        matches: Match::Prefix("/api/v1/usernames/search"),
        priority: 100,
        strip_prefix: false,
        shared: false,
        why: &[
            "Username search is the indexer's only route under /api/v1/usernames; the rest of that",
            "prefix (the claim and availability writes, their CORS preflight) falls through to",
            "device-attestation-api.",
        ],
    },
    // Kept on every network: the edge config is shared, and a build without
    // invite-tickets serves the catch-all 404 here. A deployment that runs no
    // invite-tickets-api points this upstream at its device-attestation-api.
    Row {
        name: "invite-tickets",
        owner: "invite-tickets-api",
        caddy_arg: 2,
        matches: Match::PrefixSlash("/api/v1/invitation-ticket/"),
        priority: 90,
        strip_prefix: false,
        shared: false,
        why: &["The synchronous invitation-credential claim route."],
    },
    Row {
        name: "turn",
        owner: "turn-api",
        caddy_arg: 3,
        matches: Match::PrefixSlash("/api/v1/turn/"),
        priority: 90,
        strip_prefix: false,
        shared: false,
        why: &[
            "Each environment runs its own issuer because proof verification pins one People Chain",
            "RPC and genesis hash; routing to another environment would verify against the wrong ring.",
        ],
    },
    Row {
        name: "notify",
        owner: "notify-relay",
        caddy_arg: 4,
        matches: Match::Prefix("/api/v1/notify"),
        priority: 90,
        strip_prefix: false,
        shared: true,
        why: &[
            "Shared across environments. NOTE: this service answers an EMPTY 404 for an unmatched path and",
            "405 for a wrong method, where every sibling answers the JSON 404 body. The",
            "whole prefix is routed here, so that is the live contract — see routes::fallback.",
        ],
    },
    Row {
        name: "proof-of-compute",
        owner: "username-indexer",
        caddy_arg: 1,
        matches: Match::Prefix("/api/v1/poc"),
        priority: 90,
        strip_prefix: false,
        shared: false,
        why: &[
            "Proof-of-compute gates the indexer's own public search, so it is the indexer's route.",
            "Off by default, in which case the service answers its plain-text 404.",
        ],
    },
    Row {
        name: "default",
        owner: "device-attestation-api",
        caddy_arg: 0,
        matches: Match::CatchAll,
        priority: 1,
        strip_prefix: false,
        shared: false,
        why: &["Everything else: auth, attester, username writes, JWKS, root health."],
    },
];

/// Marker opening a generated region in a committed artifact.
pub const BEGIN: &str = "generated:route-table";
pub const END: &str = "/generated:route-table";

/// Render the Caddy `(routes)` snippet body.
///
/// Positional upstreams, in `TABLE`'s order, because Caddy's `handle` blocks are
/// first-match-wins in file order — the order here IS the precedence.
pub fn caddy_snippet() -> String {
    let mut out = String::new();
    for row in TABLE {
        for line in row.why {
            out.push_str(&format!("\t# {line}\n"));
        }
        match row.matches {
            Match::Prefix(prefix) if row.strip_prefix => {
                // handle_path strips; the docs root is the same variable the
                // all-in-one role reads.
                out.push_str(&format!("\thandle_path {prefix}* {{\n"));
                out.push_str("\t\troot * {$GATEWAY_DOCS_ROOT:/srv/docs}\n");
                out.push_str("\t\tfile_server\n\t}\n");
            }
            Match::Prefix(prefix) => {
                out.push_str(&format!("\thandle {prefix}* {{\n"));
                out.push_str(&format!(
                    "\t\treverse_proxy {{args[{}]}}\n\t}}\n",
                    row.caddy_arg
                ));
            }
            Match::PrefixSlash(prefix) => {
                out.push_str(&format!("\thandle {prefix}* {{\n"));
                out.push_str(&format!(
                    "\t\treverse_proxy {{args[{}]}}\n\t}}\n",
                    row.caddy_arg
                ));
            }
            Match::CatchAll => {
                out.push_str("\thandle {\n");
                out.push_str(&format!(
                    "\t\treverse_proxy {{args[{}]}}\n\t}}\n",
                    row.caddy_arg
                ));
            }
        }
        out.push('\n');
    }
    out.pop();
    out
}

/// Render a Traefik `routes:` list — rule expressions with explicit priorities,
/// since Traefik's routers are unordered. Not a committed artifact: it is here
/// for deployments that front the services with Traefik rather than Caddy.
pub fn chart_routes() -> String {
    let mut out = String::new();
    for row in TABLE {
        for line in row.why {
            out.push_str(&format!("  # {line}\n"));
        }
        out.push_str(&format!("  - name: {}\n", row.name));
        out.push_str(&format!("    match: {}\n", traefik_rule(row)));
        out.push_str(&format!("    service: {}\n", row.owner));
        if row.shared {
            out.push_str("    shared: true\n");
        }
        out.push_str(&format!("    priority: {}\n", row.priority));
        if row.strip_prefix {
            if let Match::Prefix(prefix) = row.matches {
                out.push_str(&format!("    stripPrefix: {prefix}\n"));
            }
        }
    }
    out.pop();
    out
}

fn traefik_rule(row: &Row) -> String {
    match row.matches {
        Match::Prefix(prefix) | Match::PrefixSlash(prefix) => format!("PathPrefix(`{prefix}`)"),
        Match::CatchAll => "PathPrefix(`/`)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catch_all_is_last_and_lowest() {
        let last = TABLE.last().expect("non-empty");
        assert!(matches!(last.matches, Match::CatchAll));
        let lowest = TABLE.iter().map(|r| r.priority).min().unwrap();
        assert_eq!(last.priority, lowest);
        assert_eq!(
            TABLE
                .iter()
                .filter(|r| matches!(r.matches, Match::CatchAll))
                .count(),
            1
        );
    }

    #[test]
    fn username_search_outranks_the_catch_all_in_both_orderings() {
        let search = TABLE
            .iter()
            .position(|r| r.name == "username-search")
            .unwrap();
        let default = TABLE.iter().position(|r| r.name == "default").unwrap();
        assert!(search < default, "Caddy order: first match wins");
        assert!(
            TABLE[search].priority > TABLE[default].priority,
            "Traefik order"
        );
    }

    #[test]
    fn every_owner_is_a_real_target() {
        for row in TABLE {
            assert!(
                crate::roles::ROLES.contains(&row.owner)
                    || crate::roles::INVITE_TICKETS_ROLES.contains(&row.owner)
                    || row.owner == "api-docs",
                "route {} names unknown owner {}",
                row.name,
                row.owner
            );
        }
    }

    #[test]
    fn only_search_under_usernames_reaches_the_indexer() {
        let snippet = caddy_snippet();
        assert!(
            snippet.contains("handle /api/v1/usernames/search* {"),
            "{snippet}"
        );
        assert!(
            !snippet.contains("path /api/v1/usernames /api/v1/usernames/*")
                && !snippet.contains("handle /api/v1/usernames* {"),
            "the claim root must fall through to device-attestation-api: {snippet}"
        );
    }
}
