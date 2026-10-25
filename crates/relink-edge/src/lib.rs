//! relink at the edge: a Cloudflare Worker that answers `GET /{code}` from
//! Workers KV with the same rules as the origin, and hands everything it
//! cannot answer to the origin.

pub mod logic;

#[cfg(target_arch = "wasm32")]
mod worker;
