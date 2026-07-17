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
        /// Directory with the built web client. Enables the browser page.
        #[arg(long, env = "PASSWORD_MANAGER_SERVER_WEB_DIR")]
        web_dir: Option<PathBuf>,
        /// Google OAuth client id. Enables Google sign-in as a second
        /// credential for the web page. Requires --allowed-email.
        #[arg(long, env = "PASSWORD_MANAGER_GOOGLE_CLIENT_ID")]
        google_client_id: Option<String>,
        /// Email allowed through the Google OIDC gate. Repeatable.
        #[arg(long = "allowed-email")]
        allowed_emails: Vec<String>,
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
        Command::Serve {
            bind,
            web_dir,
            google_client_id,
            allowed_emails,
        } => {
            let Some(token_hash) = db.token_hash()? else {
                bail!("no API token configured; run `password-manager-server token` first");
            };
            let oidc = match &google_client_id {
                Some(client_id) => {
                    if allowed_emails.is_empty() {
                        bail!("--google-client-id requires at least one --allowed-email");
                    }
                    Some(password_manager_server::oidc::OidcVerifier::new(
                        password_manager_server::oidc::OidcConfig {
                            client_id: client_id.clone(),
                            allowed_emails: allowed_emails
                                .iter()
                                .map(|e| e.to_lowercase())
                                .collect(),
                        },
                    )?)
                }
                None => None,
            };
            let state = Arc::new(AppState {
                db: Mutex::new(db),
                token_hash,
                oidc,
                google_client_id,
            });
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .with_context(|| format!("binding {bind}"))?;
            eprintln!("password-manager-server listening on http://{bind}");
            eprintln!("database: {}", cli.db.display());
            if state.oidc.is_some() {
                eprintln!("Google OIDC gate: enabled");
            }
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
