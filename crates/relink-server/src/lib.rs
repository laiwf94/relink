//! The relink origin server. The binary (`src/main.rs`) documents
//! configuration and `docs/DESIGN.md` the design. Roughly in request order:
//! [`redirect`] is `GET /{code}`, on top of [`resolver`], [`cache`] and
//! [`singleflight`]; [`limiter`] holds click leases; [`clicks`] is the
//! analytics pipeline; [`api`], [`auth`] and [`ratelimit`] are the management
//! API; [`trust`] decides which forwarding headers to believe; [`health`]
//! probes destinations; [`kvsync`] publishes links for the edge; [`store`] is
//! Postgres and [`server`] wires it together. The rules shared with the edge
//! come from `relink_core` and are re-exported below.

pub mod cache;
pub mod code;
pub mod limiter;
pub mod metrics;
pub mod ratelimit;
pub mod singleflight;
pub mod util;

pub use relink_core::{abtest, classify, destination, model, netguard, rules};
