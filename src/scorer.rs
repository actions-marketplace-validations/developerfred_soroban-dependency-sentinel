//! Unified risk score = 0.6 * CVE weight + 0.4 * pony weight.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Safe,
    Watch,
    High,
    Critical,
}

pub fn cve_weight(severity: &str) -> f32 {
    let s = severity.to_ascii_uppercase();
    if s.contains("CRITICAL") {
        4.0
    } else if s.contains("HIGH") {
        3.0
    } else if s.contains("MEDIUM") {
        2.0
    } else if s.contains("LOW") {
        1.0
    } else {
        0.0
    }
}

pub fn pony_weight(pony: Option<u32>) -> f32 {
    match pony {
        Some(1) => 3.0,
        Some(2) => 2.0,
        Some(3..=5) => 1.0,
        Some(_) => 0.0,
        None => 0.0,
    }
}

pub fn score(cve: &str, pony: Option<u32>) -> (f32, Classification) {
    let s = 0.6 * cve_weight(cve) + 0.4 * pony_weight(pony);
    let class = if s >= 3.0 {
        Classification::Critical
    } else if s >= 2.0 {
        Classification::High
    } else if s >= 1.0 {
        Classification::Watch
    } else {
        Classification::Safe
    };
    (s, class)
}
