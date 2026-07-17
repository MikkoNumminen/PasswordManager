//! Process and port helpers. Spawns detached background processes, tracks
//! their PIDs, stops them, and answers "who is listening on this port".

use anyhow::{Context, Result};
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Fully detach a spawned child so it becomes a standalone background daemon:
/// no console, and its own process group, so a shell that started vaultctl
/// does not wait on (or signal) the daemon. Output already goes to a log
/// file, so it needs no console. No-op off Windows.
#[cfg(windows)]
fn detach(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
}
#[cfg(not(windows))]
fn detach(_cmd: &mut Command) {}

/// Start a background process, appending its output to `log`, and return its
/// PID. The child outlives this tool.
pub fn spawn_detached(
    bin: &Path,
    args: &[String],
    envs: &[(String, String)],
    log: &Path,
) -> Result<u32> {
    if let Some(parent) = log.parent() {
        fs::create_dir_all(parent).ok();
    }
    let out = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .with_context(|| format!("opening log {}", log.display()))?;
    let err = out.try_clone()?;
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .envs(envs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    detach(&mut cmd);
    let child = cmd
        .spawn()
        .with_context(|| format!("starting {}", bin.display()))?;
    Ok(child.id())
}

pub fn write_pid(path: &Path, pid: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(path, pid.to_string()).with_context(|| format!("writing {}", path.display()))
}

pub fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub fn remove_pid(path: &Path) {
    let _ = fs::remove_file(path);
}

/// Is a TCP server listening on 127.0.0.1:port right now?
pub fn port_listening(port: u16) -> bool {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(400)).is_ok()
}

/// Wait up to `secs` for something to start listening on the port.
pub fn wait_listening(port: u16, secs: u64) -> bool {
    for _ in 0..(secs * 5) {
        if port_listening(port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// PID of the process listening on `port`, via `netstat -ano` (Windows).
pub fn port_owner(port: u16) -> Option<u32> {
    let out = Command::new("netstat")
        .args(["-ano", "-p", "tcp"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let needle = format!(":{port}");
    for line in text.lines() {
        if !line.contains("LISTENING") {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Proto  Local  Foreign  State  PID
        if cols.len() >= 5 && cols[1].ends_with(&needle) {
            if let Ok(pid) = cols[4].parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

/// Force-kill a process tree by PID (Windows taskkill).
pub fn kill(pid: u32) -> Result<()> {
    let status = Command::new("taskkill")
        .args(["/F", "/T", "/PID", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("running taskkill")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("taskkill exited with {status}")
    }
}

/// Last `n` lines of a file, or empty if it does not exist.
pub fn tail(path: &Path, n: usize) -> String {
    let Ok(text) = fs::read_to_string(path) else {
        return String::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}
