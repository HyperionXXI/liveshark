# LiveShark v0.1.2 Release Notes

**Date:** January 2026  
**Schema Contract:** v0.2 additive (JSON report backward compatible)

## Summary

v0.1.2 adds optional fields to enable future GUI compare/timeline features and tightens the specification contract with critical normative fixes.

## What's New

### JSON Report: Optional Fields (Additive)
- **SourceSummary.source_id** (optional string): Stable, deterministic identifier for each source, enabling reliable cross-report source tracking for GUI compare/timeline groundwork. Format: `proto:source` (e.g., `artnet:192.168.0.1:6454`, `sacn:cid:000102030405060708090a0b0c0d0e0f`). Field is opaque; consumers must not parse it.
- **ConflictSummary.proto** (optional string): Protocol tag for each conflict record. Values: `artnet`, `sacn`, or future protocol names. Enables protocol-aware filtering/rendering in the GUI. Unknown protocols must be treated as opaque strings.

Both fields use `skip_serializing_if` semantics: absent in JSON when null, ensuring backward compatibility with v0.1 consumers.

### Specification: Normative Fixes (EN + FR)
- Fixed appendix numbering (Appendix E for v0.2 fields, consistent EN/FR).
- Refined stability guarantee: source_id is MUST-stable within a report, SHOULD-stable across reports when identity unchanged (addresses DHCP/NAT/IP reconfig scenarios).
- Explicit format opaqueness protection: format examples are informational only, MUST NOT be used for parsing logic (prevents failures on IPv6, sacn:cid: colons, future formats).
- Clarified unknown protocol handling: consumers MUST treat unknown proto values as opaque strings and pass-through as-is.

## Backward Compatibility

✅ **Full backward compatibility.** All new fields are optional. Existing v0.1 consumers that ignore source_id/proto will continue to work unchanged.

## Testing

- ✅ 112/112 tests passing (unit + golden + source + doc)
- ✅ Zero clippy warnings
- ✅ Both EN and FR specifications compile without errors

## Known Limitations

- GUI timeline/compare features do not yet render source_id/proto. These are groundwork fields for future development.
- No first_seen/last_seen timestamps on universes or conflicts yet; timeline visualization would benefit from these in a future release.

## See Also

- [v0.2 Schema Specification (EN)](../spec/en/LiveShark_Spec.tex)
- [v0.2 Schema Specification (FR)](../spec/fr/LiveShark_Spec.tex)
