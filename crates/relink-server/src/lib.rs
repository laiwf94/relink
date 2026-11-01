//! The relink origin server. The binary (`src/main.rs`) documents
//! configuration and `docs/DESIGN.md` the design. Roughly in request order:
//! [`redirect`] is `GET /{code}`, on top of [`resolver`], [`cache`] and
//! [`singleflight`]; [`limiter`] holds click leases; [`clicks`] is the
//! analytics pipeline; [`api`], [`auth`] and [`ratelimit`] are the management
//! API, and [`tenant`] scopes each of its requests to one workspace; [`trust`]
//! decides which forwarding headers to believe; [`health`] probes
//! destinations; [`kvsync`] publishes links for the edge; [`store`] is
//! Postgres and [`server`] wires it together; [`cli`] parses the key
//! commands. The rules shared with the edge come from `relink_core` and are
//! re-exported below.

pub mod api;
pub mod auth;
pub mod cache;
pub mod cli;
pub mod clicks;
pub mod code;
pub mod config;
pub mod health;
pub mod kvsync;
pub mod limiter;
pub mod metrics;
pub mod ratelimit;
pub mod redirect;
pub mod resolver;
pub mod server;
pub mod singleflight;
pub mod store;
pub mod tenant;
pub mod trust;
pub mod util;

pub use relink_core::{abtest, classify, destination, model, netguard, rules};
