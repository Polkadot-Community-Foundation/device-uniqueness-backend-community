// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

mod healthcheck;

use dub::roles;

use anyhow::{bail, Context as _};

enum Command {
    Run(String),
    /// Print the STANDARD topology's roles, one per line — the source the
    /// deployment gate compares compose services and chart workloads against,
    /// so it can never drift from what this binary actually accepts.
    ListRoles,
    /// Print the SMALL topology's merged roles. Separate from `--list-roles`
    /// because the two topologies are mutually exclusive, and the gate needs to
    /// tell them apart to reject a mix.
    ListMergedRoles,
    /// Probe a `/readyz` and exit 0/1. Defaults to this process's own bind
    /// port on loopback.
    Healthcheck(Option<String>),
}

fn parse_args() -> anyhow::Result<Command> {
    let mut role: Option<String> = None;
    let mut healthcheck = false;
    let mut url: Option<String> = None;

    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let mut value = |name: &str| {
            iter.next()
                .with_context(|| format!("{name} requires a value"))
        };
        match flag.as_str() {
            "--role" => role = Some(value("--role")?),
            "--url" => url = Some(value("--url")?),
            "--healthcheck" => healthcheck = true,
            "--list-roles" => return Ok(Command::ListRoles),
            "--list-merged-roles" => return Ok(Command::ListMergedRoles),
            "--help" | "-h" => {
                eprintln!("{}", usage());
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}\n\n{}", usage()),
        }
    }

    if healthcheck {
        return Ok(Command::Healthcheck(url));
    }
    if url.is_some() {
        bail!("--url is only meaningful with --healthcheck");
    }

    let Some(role) = role else {
        bail!("no --role given\n\n{}", usage());
    };
    if !roles::accepts(&role) {
        bail!("unknown role: {role}\n\n{}", usage());
    }
    Ok(Command::Run(role))
}

fn usage() -> String {
    format!(
        "usage: dub --role <ROLE>\n       dub --list-roles | --list-merged-roles\n       dub --healthcheck [--url URL]\n\nstandard topology (six workloads):\n  {}\n\nsmall topology (this, plus the two workers above; holds every secret in one\nprocess — see docs/architecture.md, Deployment topologies):\n  {}",
        roles::ROLES.join("\n  "),
        roles::MERGED_ROLES.join("\n  ")
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match parse_args()? {
        Command::ListRoles => {
            for role in roles::ROLES {
                println!("{role}");
            }
            Ok(())
        }
        Command::ListMergedRoles => {
            for role in roles::MERGED_ROLES {
                println!("{role}");
            }
            Ok(())
        }
        Command::Healthcheck(url) => healthcheck::run(url).await,
        Command::Run(role) => roles::run(&role).await,
    }
}
