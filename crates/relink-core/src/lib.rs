//! The parts of relink that both the origin server and the edge worker run.
//! Nothing here does I/O or needs an async runtime, so it builds for
//! `wasm32-unknown-unknown` as well as for the server.

pub mod abtest;
pub mod classify;
pub mod code;
pub mod conversion;
pub mod deeplink;
pub mod destination;
pub mod gate;
pub mod hex;
pub mod hll;
pub mod host;
pub mod model;
pub mod netguard;
pub mod qr;
pub mod rules;
pub mod rules_v2;
pub mod site;
pub mod visitor;
pub mod wire;
