//! Server-side storage: encrypted entry records and cleartext vault
//! metadata, nothing else. This module has no access to crypto and stores
//! exactly what clients send: ciphertext plus non-secret metadata.

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

use password_manager_core::uuid::Uuid;
use password_manager_core::{EntryRecord, VaultMeta};

pub struct ServerDb {
    conn: Connection,
}

impl ServerDb {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening server database {}", path.display()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS config (
                 key   TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS entries (
                 uuid        BLOB    PRIMARY KEY,
                 modified_ms INTEGER NOT NULL,
                 nonce       BLOB    NOT NULL,
                 ciphertext  BLOB    NOT NULL,
                 deleted     INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS idx_entries_modified
                 ON entries (modified_ms);",
        )?;
        Ok(Self { conn })
    }

    fn config_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM config WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn config_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Vault metadata as pushed by a client. Cleartext by design: salt, KDF
    /// parameters, and the key check ciphertext are non-secret.
    pub fn vault_meta(&self) -> Result<Option<VaultMeta>> {
        match self.config_get("vault_meta")? {
            None => Ok(None),
            Some(json) => Ok(Some(
                serde_json::from_str(&json).context("stored vault metadata is corrupt")?,
            )),
        }
    }

    pub fn set_vault_meta(&self, meta: &VaultMeta) -> Result<()> {
        self.config_set("vault_meta", &serde_json::to_string(meta)?)
    }

    /// SHA-256 of the API token. The token itself is never stored.
    pub fn token_hash(&self) -> Result<Option<[u8; 32]>> {
        match self.config_get("token_hash")? {
            None => Ok(None),
            Some(hex_hash) => {
                let bytes = hex::decode(hex_hash).context("stored token hash is corrupt")?;
                let hash: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("stored token hash has the wrong length"))?;
                Ok(Some(hash))
            }
        }
    }

    pub fn set_token_hash(&self, hash: &[u8; 32]) -> Result<()> {
        self.config_set("token_hash", &hex::encode(hash))
    }

    pub fn entry(&self, id: Uuid) -> Result<Option<EntryRecord>> {
        Ok(self
            .conn
            .query_row(
                "SELECT uuid, modified_ms, nonce, ciphertext, deleted
                 FROM entries WHERE uuid = ?1",
                params![id.as_bytes().as_slice()],
                row_to_record,
            )
            .optional()?)
    }

    pub fn upsert_entry(&self, record: &EntryRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO entries (uuid, modified_ms, nonce, ciphertext, deleted)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (uuid) DO UPDATE SET
                 modified_ms = excluded.modified_ms,
                 nonce = excluded.nonce,
                 ciphertext = excluded.ciphertext,
                 deleted = excluded.deleted",
            params![
                record.id.as_bytes().as_slice(),
                record.modified_ms,
                record.nonce,
                record.ciphertext,
                record.deleted as i64,
            ],
        )?;
        Ok(())
    }

    /// Records with `modified_ms` strictly greater than `since_ms`,
    /// tombstones included.
    pub fn changed_since(&self, since_ms: i64) -> Result<Vec<EntryRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT uuid, modified_ms, nonce, ciphertext, deleted
             FROM entries WHERE modified_ms > ?1 ORDER BY modified_ms",
        )?;
        let rows = stmt.query_map(params![since_ms], row_to_record)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntryRecord> {
    let id_bytes: Vec<u8> = row.get(0)?;
    let id = Uuid::from_slice(&id_bytes).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(e))
    })?;
    Ok(EntryRecord {
        id,
        modified_ms: row.get(1)?,
        nonce: row.get(2)?,
        ciphertext: row.get(3)?,
        deleted: row.get::<_, i64>(4)? != 0,
    })
}
