//! vaultctl: lifecycle control for the PasswordManager vault, in the shape of
//! the sibling RAG tools (ragctl, feedctl). It owns the vault's processes and
//! its funnel port (8443) and shows the RAGs read-only. It scopes every
//! Tailscale change to its own port and never runs a funnel reset, so it
//! cannot knock the RAGs off port 443.

#![forbid(unsafe_code)]

mod config;
mod secrets;
mod sys;
mod tscale;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use std::process::Command;

use config::{Config, FUNNEL_PORT, GATE_PORT, VAULT_PORT};

#[derive(Parser)]
#[command(
    name = "vaultctl",
    version,
    about = "Run and expose the PasswordManager vault"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Public path: vault (localhost) + Google gate + funnel on 8443.
    Up,
    /// Private path: vault on the tailnet IP only, no gate, no funnel.
    Tailnet,
    /// Stop the funnel, the gate, and the vault.
    Down,
    /// Show what is running and what is exposed.
    Status,
    /// Toggle only the vault's funnel (leaves the processes alone).
    Funnel {
        #[command(subcommand)]
        action: FunnelAction,
    },
    /// Rotate the server API token into the secrets file (never prints it).
    Token,
    /// Check that everything needed to go public is in place.
    Doctor,
    /// Print the tail of a process log.
    Logs {
        #[arg(value_enum, default_value_t = Which::Vault)]
        which: Which,
    },
}

#[derive(Subcommand)]
enum FunnelAction {
    On,
    Off,
}

#[derive(Copy, Clone, ValueEnum)]
enum Which {
    Vault,
    Gate,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load()?;
    match cli.command {
        // No subcommand (e.g. the desktop shortcut): the interactive menu.
        None => run_menu(&cfg),
        Some(Cmd::Up) => cmd_up(&cfg),
        Some(Cmd::Tailnet) => cmd_tailnet(&cfg),
        Some(Cmd::Down) => cmd_down(&cfg),
        Some(Cmd::Status) => cmd_status(&cfg),
        Some(Cmd::Funnel { action }) => cmd_funnel(&cfg, action),
        Some(Cmd::Token) => cmd_token(&cfg),
        Some(Cmd::Doctor) => {
            cmd_doctor(&cfg);
            Ok(())
        }
        Some(Cmd::Logs { which }) => cmd_logs(&cfg, which),
    }
}

// ---- interactive menu ------------------------------------------------------

/// A numbered menu, looping until quit. This is what the desktop shortcut
/// opens: pick an action by number, no commands to remember.
fn run_menu(cfg: &Config) -> Result<()> {
    loop {
        println!();
        let _ = cmd_status(cfg);
        println!();
        println!("  what do you want to do?");
        println!("    1) refresh status");
        println!("    2) go public   (Google gate + funnel 8443)");
        println!("    3) tailnet only (private, no gate)");
        println!("    4) stop everything");
        println!("    5) funnel on");
        println!("    6) funnel off");
        println!("    7) rotate API token");
        println!("    8) doctor (check setup)");
        println!("    9) view logs");
        println!("    q) quit");
        let choice = prompt("  choose: ");
        let result = match choice.as_str() {
            "1" | "" => Ok(()),
            "2" => cmd_up(cfg),
            "3" => cmd_tailnet(cfg),
            "4" => cmd_down(cfg),
            "5" => cmd_funnel(cfg, FunnelAction::On),
            "6" => cmd_funnel(cfg, FunnelAction::Off),
            "7" => cmd_token(cfg),
            "8" => {
                cmd_doctor(cfg);
                Ok(())
            }
            "9" => {
                let w = prompt("  which log (vault/gate)? ");
                let which = if w.starts_with('g') { Which::Gate } else { Which::Vault };
                cmd_logs(cfg, which)
            }
            "q" | "Q" => return Ok(()),
            other => {
                println!("  '{other}'? pick a number, or q to quit.");
                Ok(())
            }
        };
        if let Err(e) = result {
            println!("  error: {e:#}");
        }
        prompt("  [enter to continue] ");
    }
}

/// Print a prompt and read one trimmed line from stdin.
fn prompt(msg: &str) -> String {
    use std::io::Write;
    print!("{msg}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim().to_string()
}

// ---- resource registry (read-only view of the shared node) ----------------

#[derive(Deserialize)]
struct Resources {
    resources: Vec<Res>,
}

#[derive(Deserialize)]
struct Res {
    label: String,
    #[serde(default)]
    owned: bool,
    funnel_port: u16,
    #[serde(default)]
    local: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    tool: Option<String>,
}

fn load_resources(cfg: &Config) -> Vec<Res> {
    std::fs::read_to_string(cfg.resources_file())
        .ok()
        .and_then(|t| serde_json::from_str::<Resources>(&t).ok())
        .map(|r| r.resources)
        .unwrap_or_default()
}

// ---- process lifecycle -----------------------------------------------------

fn start_vault(cfg: &Config, bind: &str) -> Result<()> {
    if sys::port_listening(VAULT_PORT) {
        bail!("something is already listening on port {VAULT_PORT}; run `vaultctl down` first");
    }
    let db = cfg.server_db();
    let args = vec![
        "--db".into(),
        db.to_string_lossy().into_owned(),
        "serve".into(),
        "--bind".into(),
        bind.to_string(),
        "--web-dir".into(),
        cfg.web_dir().to_string_lossy().into_owned(),
    ];
    let pid = sys::spawn_detached(&cfg.server_bin(), &args, &[], &cfg.log_file("vault"))?;
    sys::write_pid(&cfg.pid_file("vault"), pid)?;
    if !sys::wait_listening(VAULT_PORT, 6) {
        bail!("vault did not come up on {VAULT_PORT}; see `vaultctl logs vault`");
    }
    println!("  vault up on {bind} (pid {pid})");
    Ok(())
}

fn start_gate(cfg: &Config) -> Result<()> {
    if sys::port_listening(GATE_PORT) {
        bail!("something is already listening on port {GATE_PORT}; run `vaultctl down` first");
    }
    let envs = secrets::load_env(&cfg.oauth_env())?;
    let args = vec![
        "--config".into(),
        cfg.proxy_cfg().to_string_lossy().into_owned(),
        "--authenticated-emails-file".into(),
        cfg.emails_file().to_string_lossy().into_owned(),
    ];
    let pid = sys::spawn_detached(&cfg.proxy_bin(), &args, &envs, &cfg.log_file("gate"))?;
    sys::write_pid(&cfg.pid_file("gate"), pid)?;
    if !sys::wait_listening(GATE_PORT, 8) {
        bail!("gate did not come up on {GATE_PORT}; see `vaultctl logs gate`");
    }
    println!("  gate up on {GATE_PORT} (pid {pid})");
    Ok(())
}

fn stop_service(cfg: &Config, name: &str, port: u16) {
    let pid = sys::read_pid(&cfg.pid_file(name)).or_else(|| sys::port_owner(port));
    if pid.is_none() && !sys::port_listening(port) {
        println!("  {name} not running");
        sys::remove_pid(&cfg.pid_file(name));
        return;
    }
    if let Some(pid) = pid {
        // Ignore taskkill's exit code (it returns 128 when the process is
        // already gone); the port is the real signal.
        let _ = sys::kill(pid);
    }
    let stopped = (0..10).any(|_| {
        if !sys::port_listening(port) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
        false
    });
    if stopped {
        println!("  {name} stopped");
    } else {
        eprintln!("  {name} may still be running on port {port}");
    }
    sys::remove_pid(&cfg.pid_file(name));
}

// ---- commands --------------------------------------------------------------

fn cmd_up(cfg: &Config) -> Result<()> {
    if !tscale::backend_running(cfg) {
        bail!("Tailscale is not running; start it first");
    }
    if !secrets::filled(&cfg.oauth_env()) || !secrets::filled(&cfg.emails_file()) {
        bail!(
            "the Google gate is not configured. Fill {} and {} (see ops/README.md), then retry.",
            cfg.oauth_env().display(),
            cfg.emails_file().display()
        );
    }
    println!("bringing the vault up (public, behind the Google gate)...");
    start_vault(cfg, &format!("127.0.0.1:{VAULT_PORT}"))?;
    start_gate(cfg)?;
    tscale::funnel_on(cfg, FUNNEL_PORT, &format!("http://127.0.0.1:{GATE_PORT}"))?;
    let dns = tscale::dns_name(cfg)?;
    println!("public: https://{dns}:{FUNNEL_PORT}  (Google login, then the vault)");
    Ok(())
}

fn cmd_tailnet(cfg: &Config) -> Result<()> {
    if !tscale::backend_running(cfg) {
        bail!("Tailscale is not running; start it first");
    }
    let ip = tscale::tailnet_ip(cfg)?;
    println!("bringing the vault up (private tailnet path)...");
    start_vault(cfg, &format!("{ip}:{VAULT_PORT}"))?;
    println!("tailnet: http://{ip}:{VAULT_PORT}");
    println!("clients: password-manager sync --server http://{ip}:{VAULT_PORT}");
    Ok(())
}

fn cmd_down(cfg: &Config) -> Result<()> {
    println!("taking the vault down...");
    if tscale::funnel_state(cfg, FUNNEL_PORT)
        .map(|s| s.on)
        .unwrap_or(false)
    {
        tscale::funnel_off(cfg, FUNNEL_PORT)?;
        println!("  funnel {FUNNEL_PORT} off");
    } else {
        println!("  funnel {FUNNEL_PORT} already off");
    }
    stop_service(cfg, "gate", GATE_PORT);
    stop_service(cfg, "vault", VAULT_PORT);
    Ok(())
}

fn cmd_status(cfg: &Config) -> Result<()> {
    let dns = tscale::dns_name(cfg).unwrap_or_else(|_| "<tailscale down>".into());
    println!("vaultctl status  ({dns})");
    println!(
        "  tailscale : {}",
        yn(tscale::backend_running(cfg), "running", "down")
    );
    println!(
        "  vault     : {}",
        yn(
            sys::port_listening(VAULT_PORT),
            &format!("up on {VAULT_PORT}"),
            "stopped"
        )
    );
    println!(
        "  gate      : {}",
        yn(
            sys::port_listening(GATE_PORT),
            &format!("up on {GATE_PORT}"),
            "stopped"
        )
    );
    println!(
        "  secrets   : {}",
        yn(
            secrets::filled(&cfg.oauth_env()) && secrets::filled(&cfg.emails_file()),
            "configured",
            "not configured"
        )
    );
    println!("  funnel (this node, ports 443/8443):");
    for r in load_resources(cfg) {
        let st = tscale::funnel_state(cfg, r.funnel_port).ok();
        let on = st.as_ref().map(|s| s.on).unwrap_or(false);
        let tgt = st.and_then(|s| s.target).unwrap_or_default();
        let owner = if r.owned {
            "vault, this tool".to_string()
        } else {
            r.tool.clone().unwrap_or_else(|| "external tool".into())
        };
        let expected = r.target.or(r.local).unwrap_or_default();
        let mut note = String::new();
        if on && !expected.is_empty() && tgt != expected {
            note = format!("  <- serving {tgt}, not this resource");
        }
        println!(
            "    :{:<5} {:<7} {:<26} [{}]{}",
            r.funnel_port,
            if on { "ON" } else { "off" },
            r.label,
            owner,
            note
        );
    }
    if sys::port_listening(FUNNEL_PORT)
        || tscale::funnel_state(cfg, FUNNEL_PORT)
            .map(|s| s.on)
            .unwrap_or(false)
    {
        println!("  public: https://{dns}:{FUNNEL_PORT}");
    }
    Ok(())
}

fn cmd_funnel(cfg: &Config, action: FunnelAction) -> Result<()> {
    match action {
        FunnelAction::On => {
            if !sys::port_listening(GATE_PORT) {
                bail!("the gate is not running on {GATE_PORT}; run `vaultctl up` (or start the gate) first");
            }
            tscale::funnel_on(cfg, FUNNEL_PORT, &format!("http://127.0.0.1:{GATE_PORT}"))?;
            let dns = tscale::dns_name(cfg)?;
            println!("funnel on: https://{dns}:{FUNNEL_PORT}");
        }
        FunnelAction::Off => {
            tscale::funnel_off(cfg, FUNNEL_PORT)?;
            println!("funnel {FUNNEL_PORT} off");
        }
    }
    Ok(())
}

fn cmd_token(cfg: &Config) -> Result<()> {
    let out = Command::new(cfg.server_bin())
        .args(["--db", &cfg.server_db().to_string_lossy(), "token"])
        .output()
        .context("running the server token command")?;
    let token = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    anyhow::ensure!(token.len() >= 32, "token command did not return a token");
    std::fs::create_dir_all(cfg.secrets_dir()).ok();
    std::fs::write(cfg.token_file(), &token)
        .with_context(|| format!("writing {}", cfg.token_file().display()))?;
    println!(
        "API token rotated. Written to {} (old token now invalid).",
        cfg.token_file().display()
    );
    Ok(())
}

fn cmd_doctor(cfg: &Config) -> bool {
    println!("vaultctl doctor");
    let mut ok = true;
    ok &= check(
        "tailscale present",
        std::path::Path::new(&cfg.tailscale()).exists(),
    );
    ok &= check("tailscale running", tscale::backend_running(cfg));
    ok &= check("vault server binary built", cfg.server_bin().exists());
    ok &= check("oauth2-proxy binary present", cfg.proxy_bin().exists());
    ok &= check(
        "google client configured",
        secrets::filled(&cfg.oauth_env()),
    );
    ok &= check(
        "allowed emails configured",
        secrets::filled(&cfg.emails_file()),
    );
    // Non-critical: the browser bundle.
    check(
        "web client built (web/static/pkg)",
        cfg.web_dir().join("pkg/password_manager_web.js").exists(),
    );
    if ok {
        println!("all required checks passed; `vaultctl up` is ready.");
    } else {
        println!("fix the failing checks above before `vaultctl up`.");
    }
    ok
}

fn cmd_logs(cfg: &Config, which: Which) -> Result<()> {
    let name = match which {
        Which::Vault => "vault",
        Which::Gate => "gate",
    };
    let text = sys::tail(&cfg.log_file(name), 40);
    if text.is_empty() {
        println!("no {name} log yet at {}", cfg.log_file(name).display());
    } else {
        println!("{text}");
    }
    Ok(())
}

fn check(label: &str, ok: bool) -> bool {
    println!("  [{}] {label}", if ok { "ok" } else { "!!" });
    ok
}

fn yn(cond: bool, yes: &str, no: &str) -> String {
    if cond {
        yes.to_string()
    } else {
        no.to_string()
    }
}
