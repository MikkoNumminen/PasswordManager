//! `RemoteSync`: the sync remote over the password-manager server HTTP API.
//!
//! Like every other backend it moves ciphertext and cleartext metadata only.
//! The bearer token authorizes blob access and has no role in key derivation.

use reqwest::blocking::{Client, Response};
use reqwest::StatusCode;
use std::time::Duration;

use crate::api;
use crate::error::StorageError;
use crate::model::{EntryRecord, VaultMeta};
use crate::sync::{PushOutcome, SyncRemote};

pub struct RemoteSync {
    base: String,
    token: String,
    client: Client,
}

fn net_err(e: reqwest::Error) -> StorageError {
    StorageError::Backend(format!("sync server request failed: {e}"))
}

fn status_err(action: &str, resp: Response) -> StorageError {
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    let detail = if body.is_empty() {
        String::new()
    } else {
        format!(": {}", body.chars().take(200).collect::<String>())
    };
    StorageError::Backend(format!("{action} failed with {status}{detail}"))
}

impl RemoteSync {
    pub fn new(base_url: &str, token: &str) -> Result<Self, StorageError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(net_err)?;
        Ok(Self {
            base: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            client,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn fetch_vault_meta(&self) -> Result<Option<VaultMeta>, StorageError> {
        let resp = self
            .client
            .get(self.url(api::VAULT))
            .bearer_auth(&self.token)
            .send()
            .map_err(net_err)?;
        match resp.status() {
            StatusCode::OK => Ok(Some(resp.json().map_err(net_err)?)),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(status_err("fetching vault metadata", resp)),
        }
    }

    fn put_vault_meta(&self, meta: &VaultMeta) -> Result<(), StorageError> {
        let resp = self
            .client
            .put(self.url(api::VAULT))
            .bearer_auth(&self.token)
            .json(meta)
            .send()
            .map_err(net_err)?;
        match resp.status() {
            StatusCode::OK | StatusCode::CREATED => Ok(()),
            StatusCode::CONFLICT => Err(StorageError::AlreadyInitialized),
            _ => Err(status_err("initializing remote vault", resp)),
        }
    }

    fn fetch_changed_since(&self, since_ms: i64) -> Result<Vec<EntryRecord>, StorageError> {
        let resp = self
            .client
            .get(self.url(api::ENTRIES))
            .query(&[("since_ms", since_ms)])
            .bearer_auth(&self.token)
            .send()
            .map_err(net_err)?;
        if resp.status() != StatusCode::OK {
            return Err(status_err("listing changed entries", resp));
        }
        resp.json().map_err(net_err)
    }

    /// Push one record. The server applies last-write-wins and answers 409
    /// with its own record when that record wins.
    pub fn push_record(&self, record: &EntryRecord) -> Result<PushOutcome, StorageError> {
        let resp = self
            .client
            .put(self.url(&api::entry_path(record.id)))
            .bearer_auth(&self.token)
            .json(record)
            .send()
            .map_err(net_err)?;
        match resp.status() {
            StatusCode::OK | StatusCode::CREATED => Ok(PushOutcome::Applied),
            StatusCode::CONFLICT => Ok(PushOutcome::Rejected(resp.json().map_err(net_err)?)),
            _ => Err(status_err("pushing entry", resp)),
        }
    }
}

impl SyncRemote for RemoteSync {
    fn vault_meta(&mut self) -> Result<Option<VaultMeta>, StorageError> {
        self.fetch_vault_meta()
    }

    fn init_vault(&mut self, meta: &VaultMeta) -> Result<(), StorageError> {
        self.put_vault_meta(meta)
    }

    fn changed_since(&mut self, since_ms: i64) -> Result<Vec<EntryRecord>, StorageError> {
        self.fetch_changed_since(since_ms)
    }

    fn push(&mut self, record: &EntryRecord) -> Result<PushOutcome, StorageError> {
        self.push_record(record)
    }
}
