//! Soroban Dependency Sentinel — supply-chain security for Soroban projects.

pub mod analyzer;
pub mod baseline;
pub mod cache;
pub mod cli;
pub mod config;
pub mod crates_io;
pub mod markdown;
pub mod pg_atlas;
pub mod planner;
pub mod reporter;
pub mod scanner;
pub mod scorer;
pub mod wizard;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyReport {
    pub crate_name: String,
    pub version: String,
    pub vulnerabilities: Vec<scanner::Vulnerability>,
    pub pony_factor: Option<u32>,
    pub pony_source: PonySource,
    pub risk_score: f32,
    pub classification: scorer::Classification,
    pub mitigation: Option<planner::MitigationPlan>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PonySource {
    PgAtlas,
    CratesIoOwners,
    LocalFallback,
    Unknown,
}
