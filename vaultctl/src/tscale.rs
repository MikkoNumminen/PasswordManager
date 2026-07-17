//! Thin wrappers over the Tailscale CLI. Reads node identity and funnel
//! state, and scopes every funnel change to a single port. It never runs
//! `tailscale funnel reset`, which would wipe every service on this node,
//! including the RAGs.

use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;
use std::process::Command;

use crate::config::Config;

fn json(cfg: &Config, args: &[&str]) -> Result<Value> {
    let out = Command::new(cfg.tailscale())
        .args(args)
        .output()
        .with_context(|| format!("running tailscale {}", args.join(" ")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim().is_empty() {
        return Ok(Value::Object(Default::default()));
    }
    Ok(serde_json::from_str(&text).unwrap_or(Value::Object(Default::default())))
}

/// `Self.DNSName` without the trailing dot, e.g. `paskamyrsky.tail6ed53b.ts.net`.
pub fn dns_name(cfg: &Config) -> Result<String> {
    let v = json(cfg, &["status", "--json"])?;
    let name = v["Self"]["DNSName"]
        .as_str()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_string();
    anyhow::ensure!(!name.is_empty(), "no Tailscale DNS name; is Tailscale up?");
    Ok(name)
}

/// Is the Tailscale backend running (logged in and connected)?
pub fn backend_running(cfg: &Config) -> bool {
    json(cfg, &["status", "--json"])
        .ok()
        .and_then(|v| v["BackendState"].as_str().map(|s| s == "Running"))
        .unwrap_or(false)
}

pub fn tailnet_ip(cfg: &Config) -> Result<String> {
    let out = Command::new(cfg.tailscale())
        .args(["ip", "-4"])
        .output()
        .context("running tailscale ip -4")?;
    let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
    anyhow::ensure!(
        !ip.is_empty(),
        "no Tailscale IPv4 address; is Tailscale up?"
    );
    Ok(ip)
}

pub struct PortState {
    pub on: bool,
    pub target: Option<String>,
}

/// Funnel state for one port, read from `tailscale serve status --json`.
pub fn funnel_state(cfg: &Config, port: u16) -> Result<PortState> {
    let dns = dns_name(cfg)?;
    let v = json(cfg, &["serve", "status", "--json"])?;
    let key = format!("{dns}:{port}");
    let on = v["AllowFunnel"][&key].as_bool().unwrap_or(false);
    let target = v["Web"][&key]["Handlers"]["/"]["Proxy"]
        .as_str()
        .map(|s| s.to_string());
    Ok(PortState { on, target })
}

/// Save the whole serve/funnel config before a change, so a mistake is
/// recoverable without a reset.
pub fn backup(cfg: &Config) -> Result<std::path::PathBuf> {
    let dir = cfg.backups_dir();
    std::fs::create_dir_all(&dir).ok();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = dir.join(format!("serve-{stamp}.json"));
    let out = Command::new(cfg.tailscale())
        .args(["serve", "status", "--json"])
        .output()
        .context("reading serve config for backup")?;
    std::fs::write(&path, out.stdout).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Turn the funnel on for `port`, proxying to `target`. Backs up first.
pub fn funnel_on(cfg: &Config, port: u16, target: &str) -> Result<()> {
    let b = backup(cfg)?;
    println!("  (serve config backed up to {})", short(&b));
    let status = Command::new(cfg.tailscale())
        .args(["funnel", "--bg", &format!("--https={port}"), target])
        .status()
        .context("running tailscale funnel")?;
    anyhow::ensure!(status.success(), "tailscale funnel exited with {status}");
    Ok(())
}

/// Turn the funnel off for a single port. Never a reset.
pub fn funnel_off(cfg: &Config, port: u16) -> Result<()> {
    let b = backup(cfg)?;
    println!("  (serve config backed up to {})", short(&b));
    let status = Command::new(cfg.tailscale())
        .args(["funnel", &format!("--https={port}"), "off"])
        .status()
        .context("running tailscale funnel off")?;
    anyhow::ensure!(
        status.success(),
        "tailscale funnel off exited with {status}"
    );
    Ok(())
}

fn short(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}
