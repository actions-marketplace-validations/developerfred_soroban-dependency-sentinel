//! Minimal crates.io API client — repository URL + owner-based pony proxy.

use anyhow::{Context, Result};
use serde::Deserialize;

const BASE: &str = "https://crates.io/api/v1/crates";
const USER_AGENT: &str =
    "soroban-dependency-sentinel (github.com/scf-public-goods/soroban-dependency-sentinel)";

#[derive(Debug, Deserialize)]
struct CrateResponse {
    #[serde(rename = "crate")]
    krate: CrateInfo,
}

#[derive(Debug, Deserialize)]
struct CrateInfo {
    repository: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OwnersResponse {
    users: Vec<Owner>,
}

#[derive(Debug, Deserialize)]
struct Owner {
    login: String,
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .user_agent(USER_AGENT)
        .build()?)
}

/// Real repository URL from crates.io (used only in `--deep-pony` mode).
pub async fn fetch_repository_url(name: &str) -> Result<Option<String>> {
    let url = format!("{BASE}/{name}");
    let resp = client()?.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let body: CrateResponse = resp
        .json()
        .await
        .with_context(|| format!("invalid crates.io response for {name}"))?;
    Ok(body.krate.repository)
}

/// Estimates pony factor from the number of owners on crates.io.
///
/// Fast proxy (no clone). Returns `None` if the crate has zero owners or
/// the request failed.
pub async fn estimate_pony_factor_from_owners(name: &str) -> Result<Option<u32>> {
    let url = format!("{BASE}/{name}/owners");
    let resp = client()?.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let body: OwnersResponse = resp
        .json()
        .await
        .with_context(|| format!("invalid owners response for {name}"))?;

    // Log owner logins at debug level so the field is genuinely used and
    // operators can inspect who maintains a crate when troubleshooting.
    let logins: Vec<&str> = body.users.iter().map(|u| u.login.as_str()).collect();
    tracing::debug!(crate_name = name, owners = ?logins, "crates.io owners");

    let n = body.users.len() as u32;
    Ok(if n == 0 { None } else { Some(n) })
}
