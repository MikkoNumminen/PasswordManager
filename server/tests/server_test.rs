//! Server tests: auth, last-write-wins push rules, the zero-knowledge
//! guarantee checked against the raw database file, and a full two-device
//! sync over real HTTP.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use password_manager_core::secrecy::SecretString;
use password_manager_core::sync::sync;
use password_manager_core::{
    new_entry_id, next_modified, EntryData, EntryRecord, KdfParams, LocalSqlite, RemoteSync,
    Storage, Vault, VaultMeta,
};
use password_manager_server::app::{router, AppState};
use password_manager_server::db::ServerDb;

const TOKEN: &str = "test-token-not-secret-in-tests";

fn test_kdf() -> KdfParams {
    KdfParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

fn make_state(db_path: &std::path::Path) -> Arc<AppState> {
    let db = ServerDb::open(db_path).unwrap();
    let token_hash: [u8; 32] = Sha256::digest(TOKEN.as_bytes()).into();
    db.set_token_hash(&token_hash).unwrap();
    Arc::new(AppState {
        db: Mutex::new(db),
        token_hash,
        oidc: None,
        google_client_id: None,
    })
}

fn authed(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
}

async fn send_json(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<String>,
    with_token: bool,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if with_token {
        builder = authed(builder);
    }
    let request = match body {
        Some(json) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.to_vec())
}

#[tokio::test]
async fn requests_without_valid_token_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(make_state(&dir.path().join("s.db")), None);

    let (status, _) = send_json(&app, "GET", "/api/v1/entries", None, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/entries")
        .header(header::AUTHORIZATION, "Bearer wrong-token")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Health stays open: it reveals presence, never data.
    let (status, _) = send_json(&app, "GET", "/api/v1/health", None, false).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn vault_meta_is_write_once() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(make_state(&dir.path().join("s.db")), None);
    let (_, meta) = Vault::create(&SecretString::from("pw".to_string()), test_kdf()).unwrap();
    let (_, other) = Vault::create(&SecretString::from("pw".to_string()), test_kdf()).unwrap();
    let meta_json = serde_json::to_string(&meta).unwrap();

    let (status, _) = send_json(&app, "GET", "/api/v1/vault", None, true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = send_json(&app, "PUT", "/api/v1/vault", Some(meta_json.clone()), true).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = send_json(&app, "GET", "/api/v1/vault", None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_slice::<VaultMeta>(&body).unwrap(), meta);

    // Idempotent re-put of the identical vault.
    let (status, _) = send_json(&app, "PUT", "/api/v1/vault", Some(meta_json), true).await;
    assert_eq!(status, StatusCode::OK);

    // A different vault is refused.
    let other_json = serde_json::to_string(&other).unwrap();
    let (status, _) = send_json(&app, "PUT", "/api/v1/vault", Some(other_json), true).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn push_applies_last_write_wins() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(make_state(&dir.path().join("s.db")), None);
    let (vault, _) = Vault::create(&SecretString::from("pw".to_string()), test_kdf()).unwrap();
    let id = new_entry_id().unwrap();
    let data = EntryData {
        title: "t".into(),
        username: String::new(),
        password: String::new(),
        url: String::new(),
        notes: String::new(),
        created_ms: 0,
    };

    let rec100 = vault.seal_entry(id, 100, &data).unwrap();
    let rec90 = vault.seal_entry(id, 90, &data).unwrap();
    let rec150 = vault.seal_entry(id, 150, &data).unwrap();
    let uri = format!("/api/v1/entries/{id}");
    let to_json = |r: &EntryRecord| serde_json::to_string(r).unwrap();

    let (status, _) = send_json(&app, "PUT", &uri, Some(to_json(&rec100)), true).await;
    assert_eq!(status, StatusCode::OK);

    // Older timestamp: rejected, server record returned.
    let (status, body) = send_json(&app, "PUT", &uri, Some(to_json(&rec90)), true).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        serde_json::from_slice::<EntryRecord>(&body).unwrap(),
        rec100
    );

    // Identical record: idempotent.
    let (status, _) = send_json(&app, "PUT", &uri, Some(to_json(&rec100)), true).await;
    assert_eq!(status, StatusCode::OK);

    // Newer timestamp: applied.
    let (status, _) = send_json(&app, "PUT", &uri, Some(to_json(&rec150)), true).await;
    assert_eq!(status, StatusCode::OK);

    // list-changed-since filters on the stored timestamp.
    let (status, body) = send_json(&app, "GET", "/api/v1/entries?since_ms=100", None, true).await;
    assert_eq!(status, StatusCode::OK);
    let records: Vec<EntryRecord> = serde_json::from_slice(&body).unwrap();
    assert_eq!(records, vec![rec150.clone()]);

    // Mismatched path and body id is a client bug and gets refused.
    let other_uri = format!("/api/v1/entries/{}", new_entry_id().unwrap());
    let (status, _) = send_json(&app, "PUT", &other_uri, Some(to_json(&rec150)), true).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The core zero-knowledge assertion: after real client pushes, the raw
/// bytes of the server database contain the ciphertext metadata schema and
/// nothing derived from any plaintext or the master password.
#[tokio::test]
async fn server_database_holds_only_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("s.db");
    let app = router(make_state(&db_path), None);

    let master = "MASTER-PASSWORD-MARKER-7d1f";
    let secret_marker = "TOP-SECRET-PAYLOAD-MARKER-42";
    let (vault, meta) = Vault::create(&SecretString::from(master.to_string()), test_kdf()).unwrap();
    let data = EntryData {
        title: format!("{secret_marker}-title"),
        username: format!("{secret_marker}-user"),
        password: format!("{secret_marker}-password"),
        url: format!("https://{secret_marker}.example"),
        notes: format!("{secret_marker}-notes"),
        created_ms: 1,
    };
    let record = vault
        .seal_entry(new_entry_id().unwrap(), 100, &data)
        .unwrap();

    let meta_json = serde_json::to_string(&meta).unwrap();
    let (status, _) = send_json(&app, "PUT", "/api/v1/vault", Some(meta_json), true).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = send_json(
        &app,
        "PUT",
        &format!("/api/v1/entries/{}", record.id),
        Some(serde_json::to_string(&record).unwrap()),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Read the raw database file.
    drop(app);
    let raw = std::fs::read(&db_path).unwrap();
    let raw_text = String::from_utf8_lossy(&raw).into_owned();

    // No plaintext marker, no master password, in raw or base64 form.
    use base64::Engine;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    for needle in [
        secret_marker.to_string(),
        master.to_string(),
        b64(secret_marker),
        b64(master),
    ] {
        assert!(
            !raw_text.contains(&needle),
            "server database leaked '{needle}'"
        );
    }

    // The schema holds exactly the allowed tables and columns.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .unwrap();
    let mut tables: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    tables.sort();
    assert_eq!(tables, vec!["config".to_string(), "entries".to_string()]);

    let mut stmt = conn.prepare("PRAGMA table_info(entries)").unwrap();
    let mut columns: Vec<String> = stmt
        .query_map([], |row| row.get(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    columns.sort();
    assert_eq!(
        columns,
        vec!["ciphertext", "deleted", "modified_ms", "nonce", "uuid"]
    );

    // The ciphertext column itself must not contain the serialized
    // plaintext either (defense against accidentally storing plaintext in
    // a BLOB, which the text scan above could miss on encoding grounds).
    let blob: Vec<u8> = conn
        .query_row("SELECT ciphertext FROM entries", [], |row| row.get(0))
        .unwrap();
    let plain = serde_json::to_vec(&data).unwrap();
    assert!(!blob
        .windows(secret_marker.len())
        .any(|w| w == secret_marker.as_bytes()));
    assert_ne!(blob, plain);
}

/// Two devices, one real HTTP server: device A pushes, device B bootstraps
/// from the server, pulls, and decrypts with the shared master password.
#[test]
fn two_devices_sync_over_http() {
    let dir = tempfile::tempdir().unwrap();
    let state = make_state(&dir.path().join("s.db"));

    // Real server on an ephemeral local port.
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap();
    std_listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
            axum::serve(listener, router(state, None)).await.unwrap();
        });
    });
    let base = format!("http://{addr}");

    let password = SecretString::from("shared master password".to_string());

    // Device A: create vault, add an entry, sync.
    let (vault_a, meta) = Vault::create(&password, test_kdf()).unwrap();
    let mut store_a = LocalSqlite::open_in_memory().unwrap();
    store_a.init_vault(&meta).unwrap();
    let data = EntryData {
        title: "synced entry".into(),
        username: "mikko".into(),
        password: "entry password".into(),
        url: String::new(),
        notes: String::new(),
        created_ms: 1,
    };
    let record = vault_a
        .seal_entry(new_entry_id().unwrap(), 100, &data)
        .unwrap();
    store_a.upsert_entry(&record).unwrap();

    let mut remote_a = RemoteSync::new(&base, TOKEN).unwrap();
    let report = sync(&vault_a, &mut store_a, &mut remote_a, 500).unwrap();
    assert_eq!(report.pushed, 1);

    // Device B: bootstrap the vault meta from the server, unlock with the
    // same master password, pull.
    let mut remote_b = RemoteSync::new(&base, TOKEN).unwrap();
    let server_meta = password_manager_core::sync::SyncRemote::vault_meta(&mut remote_b)
        .unwrap()
        .expect("server has the vault");
    assert_eq!(server_meta, meta);
    let vault_b = Vault::unlock(&password, &server_meta).unwrap();
    let mut store_b = LocalSqlite::open_in_memory().unwrap();
    store_b.init_vault(&server_meta).unwrap();

    let report = sync(&vault_b, &mut store_b, &mut remote_b, 600).unwrap();
    assert_eq!(report.pulled, 1);

    let pulled = store_b.entry(record.id).unwrap().unwrap();
    assert_eq!(pulled, record);
    assert_eq!(vault_b.open_entry(&pulled).unwrap(), data);

    // A tombstone created on device B propagates a verifiable deletion.
    let tombstone = vault_b
        .seal_tombstone(record.id, next_modified(pulled.modified_ms, 700))
        .unwrap();
    store_b.upsert_entry(&tombstone).unwrap();
    sync(&vault_b, &mut store_b, &mut remote_b, 800).unwrap();
    sync(&vault_a, &mut store_a, &mut remote_a, 900).unwrap();
    assert!(store_a.entry(record.id).unwrap().unwrap().deleted);

    // Wrong token gets nothing.
    let mut bad = RemoteSync::new(&base, "wrong-token").unwrap();
    assert!(password_manager_core::sync::SyncRemote::vault_meta(&mut bad).is_err());
}
