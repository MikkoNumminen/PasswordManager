//! Paths, ports, and node identity. Everything the commands need to locate
//! the binaries, data, secrets, and the Tailscale node.

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;

/// The vault server listens here (localhost on the public path, the tailnet
/// IP on the private path).
pub const VAULT_PORT: u16 = 7787;
/// oauth2-proxy (the Google gate) listens here.
pub const GATE_PORT: u16 = 4180;
/// The vault's funnel port. 443 belongs to the GPU RAGs; the vault takes
/// 8443 so it coexists with whichever RAG holds 443.
pub const FUNNEL_PORT: u16 = 8443;

pub struct Config {
    pub repo: PathBuf,
    pub data: PathBuf,
}

impl Config {
    pub fn load() -> Result<Self> {
        let exe = std::env::current_exe().context("locating vaultctl.exe")?;
        // target/release/vaultctl.exe -> repo root is three levels up.
        let repo = exe
            .ancestors()
            .nth(3)
            .ok_or_else(|| anyhow!("cannot locate repo root from {}", exe.display()))?
            .to_path_buf();
        // The ops files (server.db, secrets/, tools/) live directly under
        // %APPDATA%\PasswordManager, matching where the setup put them. This
        // is deliberately not directories::data_dir(), which appends \data.
        let data = std::env::var_os("APPDATA")
            .map(|a| PathBuf::from(a).join("PasswordManager"))
            .or_else(|| directories::BaseDirs::new().map(|b| b.data_dir().join("PasswordManager")))
            .ok_or_else(|| anyhow!("cannot locate the PasswordManager data directory"))?;
        Ok(Self { repo, data })
    }

    pub fn tailscale(&self) -> String {
        std::env::var("TAILSCALE_EXE")
            .unwrap_or_else(|_| r"C:\Program Files\Tailscale\tailscale.exe".to_string())
    }

    pub fn server_bin(&self) -> PathBuf {
        self.repo.join("target/release/password-manager-server.exe")
    }
    pub fn proxy_bin(&self) -> PathBuf {
        self.data.join("tools/oauth2-proxy.exe")
    }
    pub fn web_dir(&self) -> PathBuf {
        self.repo.join("web/static")
    }
    pub fn proxy_cfg(&self) -> PathBuf {
        self.repo.join("ops/oauth2-proxy.cfg")
    }
    pub fn resources_file(&self) -> PathBuf {
        self.repo.join("ops/resources.json")
    }

    pub fn server_db(&self) -> PathBuf {
        self.data.join("server.db")
    }
    pub fn secrets_dir(&self) -> PathBuf {
        self.data.join("secrets")
    }
    pub fn oauth_env(&self) -> PathBuf {
        self.secrets_dir().join("oauth2.env")
    }
    pub fn emails_file(&self) -> PathBuf {
        self.secrets_dir().join("allowed-emails.txt")
    }
    pub fn token_file(&self) -> PathBuf {
        self.secrets_dir().join("api-token.txt")
    }

    pub fn state_dir(&self) -> PathBuf {
        self.data.join(".vaultctl")
    }
    pub fn pid_file(&self, name: &str) -> PathBuf {
        self.state_dir().join(format!("{name}.pid"))
    }
    pub fn log_file(&self, name: &str) -> PathBuf {
        self.state_dir().join(format!("{name}.log"))
    }
    pub fn backups_dir(&self) -> PathBuf {
        self.state_dir().join("funnel-backups")
    }
}
