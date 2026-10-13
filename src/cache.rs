//! Tiny file-based cache for OSV.dev responses (24h TTL).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    fetched_at: u64,
    payload: serde_json::Value,
}

fn cache_dir() -> Result<PathBuf> {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .context("cannot determine cache dir (HOME/XDG_CACHE_HOME unset)")?;
    let dir = base.join("soroban-dependency-sentinel");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn key_path(key: &str) -> Result<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let hash = hex::encode(hasher.finalize());
    Ok(cache_dir()?.join(format!("{hash}.json")))
}

/// Retrieve a cached value if it is younger than the TTL.
pub fn get(key: &str) -> Option<serde_json::Value> {
    let path = key_path(key).ok()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    let entry: Entry = serde_json::from_str(&raw).ok()?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();
    if now.saturating_sub(entry.fetched_at) < TTL.as_secs() {
        Some(entry.payload)
    } else {
        None
    }
}

/// Store a value in the cache.
pub fn put(key: &str, payload: serde_json::Value) -> Result<()> {
    let path = key_path(key)?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let entry = Entry {
        fetched_at: now,
        payload,
    };
    std::fs::write(&path, serde_json::to_vec(&entry)?)?;
    Ok(())
}
