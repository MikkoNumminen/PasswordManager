//! PasswordManager: local-first zero-knowledge password manager, CLI client.
//!
//! All crypto lives in `password-manager-core`. This binary only wires prompts,
//! storage selection, and display together. The master password is prompted
//! interactively and never accepted as a command line argument.

#![forbid(unsafe_code)]

mod prompt;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use password_manager_core::secrecy::ExposeSecret;
use password_manager_core::uuid::Uuid;
use password_manager_core::{
    new_entry_id, next_modified, now_ms, EntryData, EntryRecord, KdfParams, LocalSqlite, Storage,
    Vault, VaultError, VaultMeta,
};
use std::path::PathBuf;
use subtle::ConstantTimeEq;

#[derive(Parser)]
#[command(
    name = "password-manager",
    version,
    about = "Local-first zero-knowledge password manager"
)]
struct Cli {
    /// Path to the vault database file.
    #[arg(
        long,
        env = "PASSWORD_MANAGER_VAULT",
        global = true,
        value_name = "FILE"
    )]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault.
    Init,
    /// Add an entry.
    Add {
        /// Title of the entry, for example the site or service name.
        title: String,
        /// Generate a random password of this length instead of prompting.
        #[arg(long, short = 'g', value_name = "LENGTH", num_args = 0..=1, default_missing_value = "24")]
        generate: Option<usize>,
    },
    /// Show one entry. The password stays masked without --reveal.
    Get {
        /// Title (exact or substring) or full entry UUID.
        query: String,
        /// Print the password in cleartext.
        #[arg(long)]
        reveal: bool,
    },
    /// List all entries.
    List,
    /// Edit an entry field by field.
    Edit {
        /// Title (exact or substring) or full entry UUID.
        query: String,
        /// Generate a new random password of this length.
        #[arg(long, short = 'g', value_name = "LENGTH", num_args = 0..=1, default_missing_value = "24")]
        generate: Option<usize>,
    },
    /// Delete an entry.
    Rm {
        /// Title (exact or substring) or full entry UUID.
        query: String,
        /// Skip the confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Sync with a password-manager-server. Last write wins; conflicting versions are
    /// kept as conflict copies, never dropped silently.
    Sync {
        /// Server URL, for example http://100.64.0.5:7787. Needed the first
        /// time; stored afterwards. The API token is prompted, never passed
        /// as an argument.
        #[arg(long)]
        server: Option<String>,
        /// Prompt for the API token again and replace the stored one. Use
        /// after rotating the server token with `password-manager-server token`.
        #[arg(long)]
        set_token: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let path = vault_path(cli.vault)?;
    let mut store = LocalSqlite::open(&path)
        .with_context(|| format!("opening vault database {}", path.display()))?;

    match cli.command {
        Command::Init => cmd_init(&mut store, &path),
        Command::Add { title, generate } => cmd_add(&mut store, &title, generate),
        Command::Get { query, reveal } => cmd_get(&mut store, &query, reveal),
        Command::List => cmd_list(&mut store),
        Command::Edit { query, generate } => cmd_edit(&mut store, &query, generate),
        Command::Rm { query, yes } => cmd_rm(&mut store, &query, yes),
        Command::Sync { server, set_token } => cmd_sync(&mut store, server, set_token),
    }
}

fn vault_path(cli_arg: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = cli_arg {
        return Ok(path);
    }
    let dirs = directories::ProjectDirs::from("", "", "PasswordManager")
        .context("no home directory found; pass --vault or set PASSWORD_MANAGER_VAULT")?;
    Ok(dirs.data_dir().join("vault.db"))
}

fn cmd_init(store: &mut LocalSqlite, path: &std::path::Path) -> Result<()> {
    if store.vault_meta()?.is_some() {
        bail!("a vault already exists at {}", path.display());
    }
    eprintln!("Creating a new vault at {}", path.display());
    let pw = prompt::read_password("Master password: ")?;
    if pw.expose_secret().is_empty() {
        bail!("the master password must not be empty");
    }
    let confirm = prompt::read_password("Repeat master password: ")?;
    let same: bool = pw
        .expose_secret()
        .as_bytes()
        .ct_eq(confirm.expose_secret().as_bytes())
        .into();
    if !same {
        bail!("passwords do not match");
    }
    let (_vault, meta) = Vault::create(&pw, KdfParams::default())?;
    store.init_vault(&meta)?;
    println!("Vault created at {}", path.display());
    println!("There is no password recovery. Losing the master password loses the vault.");
    Ok(())
}

/// Unlock the vault or exit with a clear message.
fn unlock(store: &mut LocalSqlite) -> Result<(Vault, VaultMeta)> {
    let Some(meta) = store.vault_meta()? else {
        bail!("no vault found; run `password-manager init` first");
    };
    let pw = prompt::read_password("Master password: ")?;
    match Vault::unlock(&pw, &meta) {
        Ok(vault) => Ok((vault, meta)),
        Err(VaultError::WrongPassword) => bail!("wrong master password"),
        Err(e) => Err(e.into()),
    }
}

/// Decrypt every live entry. A record that fails to decrypt means the
/// stored data was modified outside the vault, and everything stops.
fn live_entries(vault: &Vault, store: &mut LocalSqlite) -> Result<Vec<(EntryRecord, EntryData)>> {
    let mut out = Vec::new();
    for record in store.entries()? {
        if record.deleted {
            continue;
        }
        let data = vault.open_entry(&record).with_context(|| {
            format!(
                "entry {} failed authentication; the vault data was tampered with or corrupted",
                record.id
            )
        })?;
        out.push((record, data));
    }
    Ok(out)
}

/// Match a query against entries: full UUID first, then exact title
/// (case-insensitive), then title substring. Exactly one match is required.
fn find_one(
    query: &str,
    entries: Vec<(EntryRecord, EntryData)>,
) -> Result<(EntryRecord, EntryData)> {
    if let Ok(id) = Uuid::parse_str(query) {
        if let Some(hit) = entries.into_iter().find(|(r, _)| r.id == id) {
            return Ok(hit);
        }
        bail!("no entry with id {id}");
    }
    let q = query.to_lowercase();
    let mut matches: Vec<(EntryRecord, EntryData)> = entries
        .into_iter()
        .filter(|(_, d)| d.title.to_lowercase().contains(&q))
        .collect();
    // An exact title beats other substring hits.
    if matches.len() > 1 && matches.iter().any(|(_, d)| d.title.to_lowercase() == q) {
        matches.retain(|(_, d)| d.title.to_lowercase() == q);
    }
    if matches.len() > 1 {
        let mut msg = format!("'{query}' matches {} entries:\n", matches.len());
        for (r, d) in &matches {
            msg.push_str(&format!("  {}  {}\n", r.id, d.title));
        }
        msg.push_str("narrow the query or use the full id");
        bail!(msg);
    }
    matches
        .pop()
        .ok_or_else(|| anyhow::anyhow!("no entry matches '{query}'"))
}

fn cmd_add(store: &mut LocalSqlite, title: &str, generate: Option<usize>) -> Result<()> {
    let (vault, _) = unlock(store)?;
    let username = prompt::read_line("Username: ")?;
    let password = match generate {
        Some(len) => {
            let pw = prompt::generate_password(len)?;
            eprintln!("Generated a {len} character password.");
            pw
        }
        None => prompt::read_password("Entry password (may be empty): ")?
            .expose_secret()
            .to_string(),
    };
    let url = prompt::read_line("URL: ")?;
    let notes = prompt::read_line("Notes: ")?;

    let now = now_ms();
    let data = EntryData {
        title: title.to_string(),
        username,
        password,
        url,
        notes,
        created_ms: now,
    };
    let id = new_entry_id()?;
    let record = vault.seal_entry(id, next_modified(0, now), &data)?;
    store.upsert_entry(&record)?;
    println!("Added '{title}' ({id})");
    if generate.is_some() {
        println!("View the generated password with: password-manager get \"{title}\" --reveal");
    }
    Ok(())
}

fn cmd_get(store: &mut LocalSqlite, query: &str, reveal: bool) -> Result<()> {
    let (vault, _) = unlock(store)?;
    let entries = live_entries(&vault, store)?;
    let (record, data) = find_one(query, entries)?;

    println!("Title:    {}", data.title);
    println!("Username: {}", data.username);
    if reveal {
        println!("Password: {}", data.password);
    } else if data.password.is_empty() {
        println!("Password: (empty)");
    } else {
        println!("Password: ******** (use --reveal to show)");
    }
    println!("URL:      {}", data.url);
    println!("Notes:    {}", data.notes);
    println!("Id:       {}", record.id);
    println!("Created:  {}", fmt_ts(data.created_ms));
    println!("Modified: {}", fmt_ts(record.modified_ms));
    Ok(())
}

fn cmd_list(store: &mut LocalSqlite) -> Result<()> {
    let (vault, _) = unlock(store)?;
    let mut entries = live_entries(&vault, store)?;
    if entries.is_empty() {
        println!("The vault is empty.");
        return Ok(());
    }
    entries.sort_by_key(|(_, d)| d.title.to_lowercase());

    let title_w = entries
        .iter()
        .map(|(_, d)| d.title.len())
        .chain(["TITLE".len()])
        .max()
        .unwrap_or(5);
    let user_w = entries
        .iter()
        .map(|(_, d)| d.username.len())
        .chain(["USERNAME".len()])
        .max()
        .unwrap_or(8);
    println!(
        "{:<title_w$}  {:<user_w$}  {:<16}  URL",
        "TITLE", "USERNAME", "MODIFIED (UTC)"
    );
    for (record, data) in &entries {
        println!(
            "{:<title_w$}  {:<user_w$}  {:<16}  {}",
            data.title,
            data.username,
            fmt_ts(record.modified_ms),
            data.url
        );
    }
    Ok(())
}

fn cmd_edit(store: &mut LocalSqlite, query: &str, generate: Option<usize>) -> Result<()> {
    let (vault, _) = unlock(store)?;
    let entries = live_entries(&vault, store)?;
    let (record, current) = find_one(query, entries)?;

    let title = prompt::read_line_with_default("Title", &current.title)?;
    if title.is_empty() {
        bail!("the title must not be empty");
    }
    let username = prompt::read_line_with_default("Username", &current.username)?;
    let password = match generate {
        Some(len) => {
            let pw = prompt::generate_password(len)?;
            eprintln!("Generated a {len} character password.");
            pw
        }
        None => {
            let input = prompt::read_password("Entry password (Enter keeps current): ")?;
            if input.expose_secret().is_empty() {
                current.password.clone()
            } else {
                input.expose_secret().to_string()
            }
        }
    };
    let url = prompt::read_line_with_default("URL", &current.url)?;
    let notes = prompt::read_line_with_default("Notes", &current.notes)?;

    let data = EntryData {
        title,
        username,
        password,
        url,
        notes,
        created_ms: current.created_ms,
    };
    let modified = next_modified(record.modified_ms, now_ms());
    let updated = vault.seal_entry(record.id, modified, &data)?;
    store.upsert_entry(&updated)?;
    println!("Updated '{}' ({})", data.title, record.id);
    Ok(())
}

fn cmd_rm(store: &mut LocalSqlite, query: &str, yes: bool) -> Result<()> {
    let (vault, _) = unlock(store)?;
    let entries = live_entries(&vault, store)?;
    let (record, data) = find_one(query, entries)?;

    if !yes {
        let answer =
            prompt::read_line(&format!("Delete '{}' ({})? [y/N]: ", data.title, record.id))?;
        if !answer.eq_ignore_ascii_case("y") {
            println!("Not deleted.");
            return Ok(());
        }
    }
    // Tombstone: the UUID and timestamp stay so deletion propagates through
    // sync. It is sealed under the vault key so the sync server cannot forge
    // or re-stamp a deletion.
    let modified = next_modified(record.modified_ms, now_ms());
    let tombstone = vault.seal_tombstone(record.id, modified)?;
    store.upsert_entry(&tombstone)?;
    println!("Deleted '{}' ({})", data.title, record.id);
    Ok(())
}

fn cmd_sync(store: &mut LocalSqlite, server_arg: Option<String>, set_token: bool) -> Result<()> {
    use password_manager_core::sync::{sync, Side, SyncError, SyncRemote};
    use password_manager_core::RemoteSync;

    // Resolve server URL and token: stored config, overridden or created by
    // --server. The token is prompted, never taken as an argument. --set-token
    // (or a first-time or changed URL) forces a fresh prompt, so a rotated
    // server token can always be re-entered for the same URL.
    let stored = store.sync_config()?;
    let url = match (&server_arg, &stored) {
        (Some(url), _) => url.clone(),
        (None, Some(cfg)) => cfg.server_url.clone(),
        (None, None) => {
            bail!("sync is not configured; run `password-manager sync --server <URL>` once")
        }
    };
    let reuse_token = stored
        .as_ref()
        .filter(|c| c.server_url == url)
        .map(|c| c.token.clone());
    let token = match reuse_token {
        Some(token) if !set_token => token,
        _ => {
            let entered = prompt::read_password("Server API token: ")?;
            let entered = entered.expose_secret().to_string();
            store.save_sync_config(&url, &entered)?;
            entered
        }
    };
    let mut remote = RemoteSync::new(&url, &token)?;

    // Bootstrap: a fresh device adopts the vault metadata from the server,
    // then the master password proves itself against the key check.
    if store.vault_meta()?.is_none() {
        let Some(remote_meta) = remote.vault_meta()? else {
            bail!("no vault locally or on the server; run `password-manager init` first");
        };
        store.init_vault(&remote_meta)?;
        eprintln!("Adopted the vault from {url}. Enter its master password.");
    }

    let (vault, _) = unlock(store)?;

    let report = match sync(&vault, store, &mut remote, now_ms()) {
        Ok(result) => result,
        Err(SyncError::VaultMismatch(msg)) => {
            bail!("refusing to sync: {msg}\nThe server at {url} holds a different vault.")
        }
        Err(e) => return Err(e.into()),
    };

    println!(
        "Sync complete: pushed {}, pulled {}, conflicts {}",
        report.pushed,
        report.pulled,
        report.conflicts.len()
    );
    for conflict in &report.conflicts {
        let winner = match conflict.winner {
            Side::Local => "this device",
            Side::Remote => "the server",
        };
        println!(
            "CONFLICT on {}: the version from {winner} won.",
            conflict.id
        );
        for (copy_id, title) in &conflict.copies {
            println!("  losing version kept as '{title}' ({copy_id})");
        }
        if conflict.copies.is_empty() {
            println!("  the losing version was a deletion; nothing to keep");
        }
    }
    Ok(())
}

fn fmt_ts(ms: i64) -> String {
    use time::macros::format_description;
    use time::OffsetDateTime;
    let format = format_description!("[year]-[month]-[day] [hour]:[minute]");
    OffsetDateTime::from_unix_timestamp(ms.div_euclid(1000))
        .ok()
        .and_then(|t| t.format(&format).ok())
        .unwrap_or_else(|| ms.to_string())
}
