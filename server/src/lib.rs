//! Library surface of password-manager-server, so integration tests can build the
//! router and drive it directly.

#![forbid(unsafe_code)]

pub mod app;
pub mod db;
pub mod oidc;
