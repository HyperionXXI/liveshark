//! sACN (E1.31) protocol decoding.
//!
//! The parser validates ACN PID and vectors, then decodes framing and DMP
//! fields into DMX payloads. Start code and property count constraints are
//! enforced to avoid invalid frames.
//!
//! Errors report invalid vectors, lengths, or payload sizes. Wire-format
//! details are defined in `layout`, while conventions and safe reads live in
//! `reader`.
//!
pub mod error;
pub mod layout;
pub mod parser;
pub mod reader;

pub use parser::parse_sacn_dmx;
