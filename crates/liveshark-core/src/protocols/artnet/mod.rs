//! Art-Net protocol decoding.
//!
//! The parser validates the Art-Net signature and opcode, then decodes ArtDMX
//! payloads into domain-friendly structures. Length and universe constraints
//! are enforced to avoid invalid frame reconstruction; ArtDMX length is
//! required to be even and within 2..=512.
//!
//! Errors are explicit and actionable (e.g., invalid length, universe id, or
//! unsupported opcode). Byte offsets and protocol conventions live in
//! `layout` and `reader` respectively.
//!
pub mod error;
pub mod layout;
pub mod parser;
pub mod reader;

pub use parser::parse_artdmx;
