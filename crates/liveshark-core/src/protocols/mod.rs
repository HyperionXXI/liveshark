//! Protocol decoding modules.
//!
//! Each protocol follows a layered structure:
//! - `layout`: byte offsets and ranges (source of truth)
//! - `reader`: safe byte access and protocol conventions
//! - `parser`: domain-level decoding (no direct byte indexing)
//! - `error`: explicit, actionable errors
//!
//! Parsers are pure and contain no I/O; sources and analysis layers handle
//! file access and aggregation.

pub mod artnet;
pub(crate) mod common;
pub mod sacn;
