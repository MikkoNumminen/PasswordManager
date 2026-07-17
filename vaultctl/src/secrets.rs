//! Loading and checking the out-of-repo secrets that the Google gate needs.
//! Values are read but never printed.

use anyhow::{Context, Result};
use std::path::Path;

/// Parse `KEY=VALUE` lines from the oauth2 env file, skipping comments.
pub fn load_env(path: &Path) -> Result<Vec<(String, String)>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(out)
}

/// True when the file exists and holds no leftover placeholder.
pub fn filled(path: &Path) -> bool {
    match std::fs::read_to_string(path) {
        Ok(text) => !text.contains("REPLACE_") && text.trim().chars().any(|c| !c.is_whitespace()),
        Err(_) => false,
    }
}
