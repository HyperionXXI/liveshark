//! PCAP/PCAPNG source implementation.
//!
//! This module provides a `PacketSource` backed by PCAP or PCAPNG files. It
//! handles file I/O and low-level parsing, emitting raw packet events for the
//! analysis pipeline.

pub mod error;
pub mod layout;
pub mod parser;
pub mod reader;

pub use parser::PcapFileSource;
