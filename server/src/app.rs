//! HTTP API: auth, push, pull, list-changed-since.
//!
//! Every handler moves ciphertext and cleartext metadata only. Push applies
//! last-write-wins by modified timestamp and answers 409 with the winning
//! server record, so clients can surface conflicts instead of losing data.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, Request, State};
use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use password_manager_core::sync::{lww_push_decision, PushDecision};
use password_manager_core::uuid::Uuid;
use password_manager_core::{api, EntryRecord, VaultMeta};

use crate::db::ServerDb;

/// The app itself knows exactly one credential: the API token. Identity on
/// the public path (Google via Cloudflare Access) is enforced at the edge
/// before a request ever reaches this process, and is never an input to
/// anything cryptographic. The server holds no key material and has no code
/// path that could decrypt a record.
pub struct AppState {
    pub db: Mutex<ServerDb>,
    pub token_hash: [u8; 32],
}

type ApiError = (StatusCode, Json<serde_json::Value>);

/// The one error envelope the API speaks: `{"error": "..."}` with a status.
/// Every handler and the web client's error path rely on this shape.
fn api_err(status: StatusCode, message: &str) -> ApiError {
    (status, Json(json!({ "error": message })))
}

fn internal(err: anyhow::Error) -> ApiError {
    // No secrets exist in this process, so the error text is safe to log.
    eprintln!("internal error: {err:#}");
    api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

pub fn router(state: Arc<AppState>, web_dir: Option<std::path::PathBuf>) -> Router {
    let protected = Router::new()
        .route(api::VAULT, get(get_vault).put(put_vault))
        .route(api::ENTRIES, get(list_entries))
        .route(api::ENTRY_ROUTE, get(get_entry).put(put_entry))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth));
    let mut router = Router::new()
        .route(api::HEALTH, get(|| async { "ok" }))
        .merge(protected);
    if let Some(dir) = web_dir {
        router = router.fallback_service(tower_http::services::ServeDir::new(dir));
    }
    router.with_state(state)
}

/// Bearer token check: the API token authorizes ciphertext access and
/// nothing else. It has no role in key derivation; a valid token yields
/// only ciphertext. Who may reach this service at all is decided upstream
/// (tailnet membership, or Cloudflare Access on the public path).
async fn auth(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let presented = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let ok = match presented {
        Some(token) => {
            let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
            bool::from(hash.ct_eq(&state.token_hash))
        }
        None => false,
    };
    if !ok {
        return api_err(StatusCode::UNAUTHORIZED, "missing or invalid token").into_response();
    }
    next.run(req).await
}

async fn get_vault(State(state): State<Arc<AppState>>) -> Result<Json<VaultMeta>, ApiError> {
    let db = state.db.lock().expect("db mutex");
    db.vault_meta()
        .map_err(internal)?
        .map(Json)
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "no vault on this server yet"))
}

/// Store vault metadata once. Re-putting identical metadata is fine;
/// different metadata means a different vault and is refused, because
/// overwriting would orphan every stored ciphertext.
async fn put_vault(
    State(state): State<Arc<AppState>>,
    Json(meta): Json<VaultMeta>,
) -> Result<Response, ApiError> {
    let db = state.db.lock().expect("db mutex");
    match db.vault_meta().map_err(internal)? {
        None => {
            db.set_vault_meta(&meta).map_err(internal)?;
            Ok((StatusCode::CREATED, Json(json!({"created": true}))).into_response())
        }
        Some(existing) if existing.same_vault(&meta) => {
            Ok(Json(json!({"created": false})).into_response())
        }
        Some(_) => Err(api_err(
            StatusCode::CONFLICT,
            "a different vault already exists on this server",
        )),
    }
}

#[derive(Deserialize)]
struct ListParams {
    since_ms: Option<i64>,
}

async fn list_entries(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<EntryRecord>>, ApiError> {
    let db = state.db.lock().expect("db mutex");
    let records = db
        .changed_since(params.since_ms.unwrap_or(-1))
        .map_err(internal)?;
    Ok(Json(records))
}

async fn get_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<EntryRecord>, ApiError> {
    let db = state.db.lock().expect("db mutex");
    db.entry(id)
        .map_err(internal)?
        .map(Json)
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "no such entry"))
}

/// Push one record. The decision is core's `lww_push_decision`, the same
/// function the sync engine's tests run against:
/// - apply: stored
/// - idempotent: 200 without writing
/// - reject: 409 with the server's record in the body
async fn put_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(record): Json<EntryRecord>,
) -> Result<Response, ApiError> {
    if record.id != id {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "record id does not match the path",
        ));
    }
    let db = state.db.lock().expect("db mutex");
    let existing = db.entry(id).map_err(internal)?;
    match lww_push_decision(existing.as_ref(), &record) {
        PushDecision::Apply => {
            db.upsert_entry(&record).map_err(internal)?;
            Ok(Json(json!({"applied": true})).into_response())
        }
        PushDecision::Idempotent => Ok(Json(json!({"applied": true})).into_response()),
        PushDecision::Reject => {
            let server_rec = existing
                .ok_or_else(|| internal(anyhow::anyhow!("reject without an existing record")))?;
            Ok((StatusCode::CONFLICT, Json(server_rec)).into_response())
        }
    }
}
