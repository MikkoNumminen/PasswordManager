//! `LocalSqlite`: the on-disk storage backend.
//!
//! The database holds exactly what the data model allows: cleartext vault
//! metadata (salt, KDF parameters, key check ciphertext) and encrypted entry
//! records. Plaintext never reaches this module.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use uuid::Uuid;

use crate::crypto::KdfParams;
use crate::error::StorageError;
use crate::model::{EntryRecord, VaultMeta};
use crate::storage::Storage;

pub struct LocalSqlite {
    conn: Connection,
}

/// Client-side sync settings. The token authorizes ciphertext access on the
/// sync server; it has no role in key derivation and cannot decrypt
/// anything.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub server_url: String,
    pub token: String,
}

impl LocalSqlite {
    /// Open or create the database file and ensure the schema exists.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    /// An in-memory database, for tests.
    pub fn open_in_memory() -> Result<Self, StorageError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self, StorageError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA secure_delete = ON;
             CREATE TABLE IF NOT EXISTS entries (
                 uuid        BLOB    PRIMARY KEY,
                 modified_ms INTEGER NOT NULL,
                 nonce       BLOB    NOT NULL,
                 ciphertext  BLOB    NOT NULL,
                 deleted     INTEGER NOT NULL DEFAULT 0,
                 -- The modified_ms last confirmed in sync with the remote.
                 -- NULL, or a value below modified_ms, means the row is a
                 -- local edit not yet pushed. See dirty_entries.
                 synced_ms   INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_entries_modified
                 ON entries (modified_ms);
             CREATE TABLE IF NOT EXISTS sync_config (
                 id           INTEGER PRIMARY KEY CHECK (id = 1),
                 server_url   TEXT    NOT NULL,
                 token        TEXT    NOT NULL
             );",
        )?;
        Self::add_column_if_missing(&conn, "entries", "synced_ms", "INTEGER")?;
        Self::ensure_meta_table(&conn)?;
        Ok(Self { conn })
    }

    /// Add a column to an existing table if it is not already present, so
    /// databases created by an earlier schema pick up the new column instead
    /// of failing. New databases already have it from the CREATE TABLE above.
    fn add_column_if_missing(
        conn: &Connection,
        table: &str,
        column: &str,
        decl: &str,
    ) -> Result<(), StorageError> {
        let existing = Self::column_names(conn, table)?;
        if !existing.iter().any(|c| c == column) {
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))?;
        }
        Ok(())
    }

    fn column_names(conn: &Connection, table: &str) -> Result<Vec<String>, StorageError> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let names = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(names)
    }

    /// Vault metadata is stored as one JSON value: the serde model is the
    /// canonical encoding on the wire and on the server, and keeping a third
    /// column-flattened encoding here meant every new field needed hand edits
    /// in two mapping sites. Databases created by the earlier columnar schema
    /// are migrated in place.
    fn ensure_meta_table(conn: &Connection) -> Result<(), StorageError> {
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'vault_meta'",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            conn.execute_batch(
                "CREATE TABLE vault_meta (
                     id   INTEGER PRIMARY KEY CHECK (id = 1),
                     meta TEXT NOT NULL
                 );",
            )?;
            return Ok(());
        }
        let columns = Self::column_names(conn, "vault_meta")?;
        if columns.iter().any(|c| c == "meta") {
            return Ok(());
        }
        // Old columnar shape: read it back into the model, then replace the
        // table with the JSON shape.
        let old: Option<VaultMeta> = conn
            .query_row(
                "SELECT version, salt, m_cost_kib, t_cost, p_cost,
                        key_check_nonce, key_check_ct
                 FROM vault_meta WHERE id = 1",
                [],
                |row| {
                    Ok(VaultMeta {
                        version: row.get(0)?,
                        salt: row.get(1)?,
                        kdf: KdfParams {
                            m_cost_kib: row.get(2)?,
                            t_cost: row.get(3)?,
                            p_cost: row.get(4)?,
                        },
                        key_check_nonce: row.get(5)?,
                        key_check_ct: row.get(6)?,
                    })
                },
            )
            .optional()?;
        conn.execute_batch(
            "DROP TABLE vault_meta;
             CREATE TABLE vault_meta (
                 id   INTEGER PRIMARY KEY CHECK (id = 1),
                 meta TEXT NOT NULL
             );",
        )?;
        if let Some(meta) = old {
            let json = serde_json::to_string(&meta)
                .map_err(|e| StorageError::Corrupt(format!("re-encoding vault metadata: {e}")))?;
            conn.execute(
                "INSERT INTO vault_meta (id, meta) VALUES (1, ?1)",
                params![json],
            )?;
        }
        Ok(())
    }

    /// Stored sync settings, if `sync` was configured.
    pub fn sync_config(&self) -> Result<Option<SyncConfig>, StorageError> {
        self.conn
            .query_row(
                "SELECT server_url, token FROM sync_config WHERE id = 1",
                [],
                |row| {
                    Ok(SyncConfig {
                        server_url: row.get(0)?,
                        token: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Store or replace the sync settings.
    pub fn save_sync_config(&mut self, server_url: &str, token: &str) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO sync_config (id, server_url, token)
             VALUES (1, ?1, ?2)
             ON CONFLICT (id) DO UPDATE SET
                 server_url = excluded.server_url,
                 token = excluded.token",
            params![server_url, token],
        )?;
        Ok(())
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
}

const RECORD_COLUMNS: &str = "uuid, modified_ms, nonce, ciphertext, deleted";

impl Storage for LocalSqlite {
    fn vault_meta(&mut self) -> Result<Option<VaultMeta>, StorageError> {
        let json: Option<String> = self
            .conn
            .query_row("SELECT meta FROM vault_meta WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        match json {
            None => Ok(None),
            Some(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| StorageError::Corrupt(format!("vault metadata: {e}"))),
        }
    }

    fn init_vault(&mut self, meta: &VaultMeta) -> Result<(), StorageError> {
        if self.vault_meta()?.is_some() {
            return Err(StorageError::AlreadyInitialized);
        }
        let json = serde_json::to_string(meta)
            .map_err(|e| StorageError::Corrupt(format!("encoding vault metadata: {e}")))?;
        self.conn.execute(
            "INSERT INTO vault_meta (id, meta) VALUES (1, ?1)",
            params![json],
        )?;
        Ok(())
    }

    fn upsert_entry(&mut self, record: &EntryRecord) -> Result<(), StorageError> {
        // Local edit: synced_ms is left NULL on insert and untouched on
        // update, so it stays below the new modified_ms and the row reads as
        // dirty until the next successful push.
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

    fn apply_synced(&mut self, record: &EntryRecord) -> Result<(), StorageError> {
        // Pulled from the remote: store it and mark it clean by setting
        // synced_ms equal to modified_ms.
        self.conn.execute(
            "INSERT INTO entries (uuid, modified_ms, nonce, ciphertext, deleted, synced_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?2)
             ON CONFLICT (uuid) DO UPDATE SET
                 modified_ms = excluded.modified_ms,
                 nonce = excluded.nonce,
                 ciphertext = excluded.ciphertext,
                 deleted = excluded.deleted,
                 synced_ms = excluded.modified_ms",
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

    fn mark_synced(&mut self, id: Uuid, modified_ms: i64) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE entries SET synced_ms = ?2 WHERE uuid = ?1",
            params![id.as_bytes().as_slice(), modified_ms],
        )?;
        Ok(())
    }

    fn entry(&mut self, id: Uuid) -> Result<Option<EntryRecord>, StorageError> {
        self.conn
            .query_row(
                &format!("SELECT {RECORD_COLUMNS} FROM entries WHERE uuid = ?1"),
                params![id.as_bytes().as_slice()],
                Self::row_to_record,
            )
            .optional()
            .map_err(StorageError::from)
    }

    fn entries(&mut self) -> Result<Vec<EntryRecord>, StorageError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM entries ORDER BY modified_ms"
        ))?;
        let rows = stmt.query_map([], Self::row_to_record)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    fn dirty_entries(&mut self) -> Result<Vec<EntryRecord>, StorageError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM entries
             WHERE synced_ms IS NULL OR synced_ms <> modified_ms
             ORDER BY modified_ms"
        ))?;
        let rows = stmt.query_map([], Self::row_to_record)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }
}
