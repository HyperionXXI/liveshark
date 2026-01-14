# Rust Architecture Rules (Normative)

This document is normative for LiveShark Rust code. It defines how external data
is parsed and how code is structured. EN is authoritative; FR is a translation.

## Scope

These rules apply to all external inputs: PCAP/PCAPNG, network frames, files,
and any protocol payloads.

## Layered parsing model (mandatory)

For each protocol or message type, use the following modules:

- `layout`: constants for offsets, lengths, and ranges of the format
- `reader`: safe helpers to read bytes, integers, slices, and strings
- `parser`: domain logic only (convert to domain structs)
- `error`: dedicated error type with actionable messages
- `tests`: unit tests; golden tests when output feeds reports

The parser must not contain low-level byte access. All byte reads go through
`reader`.

## No magic numbers (mandatory)

No numeric literals in parsing logic. All offsets/lengths/ranges must be defined
once in `layout` as named `const` in SCREAMING_SNAKE_CASE.

## No panics on external data (mandatory)

No `unwrap`, `expect`, direct indexing, or any operation that can panic on
invalid/short input. All parsing returns `Result<_, ParseError>` (or module
`Error`) and uses non-panicking access (`.get`, safe readers).

## Reader helpers (mandatory)

Centralize helpers in `reader`:

- `read_u8(offset) -> Result<u8, _>`
- `read_u16_be(range) -> Result<u16, _>`
- `read_u16_le(range) -> Result<u16, _>`
- `read_u32_be(range) -> Result<u32, _>`
- `read_slice(range) -> Result<&[u8], _>`
- `read_ascii_string(range) -> Result<String, _>`

Protocol conventions (e.g., "0 means absent") must be encapsulated in a helper
function (e.g., `parse_optional_nonzero`), not repeated.

## Tests (mandatory)

Every parser has unit tests. If the parser impacts report output, add golden
tests with representative inputs.

## Formatting (mandatory)

All Rust code must be formatted with `cargo fmt` (default rustfmt). No manual
style deviations.

## Reference links

- Rust Style Guide: https://doc.rust-lang.org/style-guide/
- Rust Book (error handling, Result vs panic): https://doc.rust-lang.org/book/ch09-00-error-handling.html
- RFC 1679 (panic-safe slicing): https://rust-lang.github.io/rfcs/1679-panic-safe-slicing.html
- Rust std slice `.get`: https://doc.rust-lang.org/std/primitive.slice.html#method.get
- Separation of Concerns (SoC): https://en.wikipedia.org/wiki/Separation_of_concerns
- DRY: https://en.wikipedia.org/wiki/Don%27t_repeat_yourself
