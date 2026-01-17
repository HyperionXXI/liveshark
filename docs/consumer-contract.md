# Consumer Contract for LiveShark JSON Reports

This document is a concise compatibility guide for consumers of LiveShark reports.
It does not replace the specification; the spec remains authoritative.

## Compatibility Rules

- Additive fields are non-breaking.
- Consumers MUST ignore unknown fields.
- Optional fields are omitted when not computable; absence does not mean zero.
- `report_version` denotes the base schema and does not necessarily change for additive fields.
- Loss is reported only when protocol sequence numbers exist (e.g., sACN).

## Windowing Convention (Metrics)

All sliding windows include packets with timestamps in `[t - W, t]` (inclusive).

## Minimal Example (Presence vs Absence)

```json
{
  "report_version": 1,
  "flows": [
    { "app_proto": "udp", "src": "10.0.0.1:1000", "dst": "10.0.0.2:2000" }
  ]
}
```

The absence of `pps` or `bps` above means the values are not computable, not zero.

## Example (Optional Metrics Present)

```json
{
  "flows": [
    {
      "app_proto": "udp",
      "src": "10.0.0.1:1000",
      "dst": "10.0.0.2:2000",
      "pps": 2.0,
      "bps": 20.0,
      "pps_peak_1s": 3,
      "bps_peak_1s": 30
    }
  ]
}
```
