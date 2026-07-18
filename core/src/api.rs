//! The HTTP API surface, defined once. The axum server mounts these paths
//! and `RemoteSync` requests them, so a route rename cannot drift between
//! client and server. web/static/app.js cannot consume Rust constants and
//! keeps its own copies; when changing anything here, update it too.

use uuid::Uuid;

pub const HEALTH: &str = "/api/v1/health";
/// Reports the extension version this server was built from, so the browser
/// extension can tell the user when a newer build is available. Unauthenticated
/// like HEALTH: a version string is not secret.
pub const VERSION: &str = "/api/v1/version";
pub const VAULT: &str = "/api/v1/vault";
pub const ENTRIES: &str = "/api/v1/entries";
/// axum route pattern for one entry.
pub const ENTRY_ROUTE: &str = "/api/v1/entries/{id}";

/// Request path for one entry.
pub fn entry_path(id: Uuid) -> String {
    format!("{ENTRIES}/{id}")
}
