//! PG Atlas API client (pony factor + criticality).

use anyhow::{Context, Result};
use serde::Deserialize;

const BASE: &str = "https://api.pgatlas.xyz";

#[derive(Debug, Deserialize)]
pub struct ProjectMetrics {
    pub display_name: String,
    pub pony_factor: Option<u32>,
    pub criticality_score: Option<f64>,
}

pub async fn fetch_project(canonical_id: &str) -> Result<ProjectMetrics> {
    let url = format!("{BASE}/projects/{canonical_id}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let metrics = client
        .get(&url)
        .send()
        .await
        .context("PG Atlas request failed")?
        .error_for_status()?
        .json()
        .await?;
    Ok(metrics)
}
