//! password-manager-server: zero-knowledge sync server.
//!
//! Stores encrypted entry records and cleartext vault metadata. Has no
//! crypto, no key material, and no way to read a vault. Binds to localhost
//! by default; bind it to a tailnet address for use across devices (see the
//! README). Public exposure is a deliberate opt-in step.

#![forbid(unsafe_code)]

use password_manager_server::{app, db};

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

use app::AppState;
use db::ServerDb;

#[derive(Parser)]
#[command(
    name = "password-manager-server",
    version,
    about = "Zero-knowledge sync server for PasswordManager"
)]
struct Cli {
    /// Path to the server database file.
    #[arg(
        long,
        env = "PASSWORD_MANAGER_SERVER_DB",
        default_value = "password-manager-server.db",
        global = true
    )]
    db: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server.
    Serve {
        /// Address to bind. Keep this on localhost or a tailnet address;
        /// public exposure is a deliberate opt-in step.
        #[arg(
            long,
            env = "PASSWORD_MANAGER_SERVER_BIND",
            default_value = "127.0.0.1:7787"
        )]
        bind: SocketAddr,
        /// Directory with the built web client. Enables the browser page,
        /// served from this machine; no third party hosts the crypto code
        /// the browser runs.
        #[arg(long, env = "PASSWORD_MANAGER_SERVER_WEB_DIR")]
        web_dir: Option<PathBuf>,
    },
    /// Generate the API token, store its hash, and print the token once.
    Token,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let db = ServerDb::open(&cli.db)?;

    match cli.command {
        Command::Token => {
            let mut raw = [0u8; 32];
            getrandom::getrandom(&mut raw)
                .map_err(|e| anyhow::anyhow!("system RNG unavailable: {e}"))?;
            let token = hex::encode(raw);
            let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
            db.set_token_hash(&hash)?;
            println!("{token}");
            eprintln!();
            eprintln!("This token is shown once and only its hash is stored.");
            eprintln!("Give it to clients with: password-manager sync --server <URL>");
            eprintln!("Rerun `password-manager-server token` to replace it.");
            Ok(())
        }
        Command::Serve { bind, web_dir } => {
            let Some(token_hash) = db.token_hash()? else {
                bail!("no API token configured; run `password-manager-server token` first");
            };
            // Identity on the public path is Cloudflare Access at the edge,
            // never this process. The app authenticates only the API token,
            // and neither gate touches key derivation.
            let state = Arc::new(AppState {
                db: Mutex::new(db),
                token_hash,
            });
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .with_context(|| format!("binding {bind}"))?;
            eprintln!("password-manager-server listening on http://{bind}");
            eprintln!("database: {}", cli.db.display());
            if let Some(dir) = &web_dir {
                eprintln!("web client: {}", dir.display());
            }
            axum::serve(listener, app::router(state, web_dir))
                .with_graceful_shutdown(shutdown_signal())
                .await?;
            Ok(())
        }
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("shutting down");
}
