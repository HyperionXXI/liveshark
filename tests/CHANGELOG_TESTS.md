Test fixture notes

- compliance examples are deduplicated and capped (stable ordering); changes affect only `compliance[].violations[].examples` fields in:
  - tests/golden/artnet_conflict/expected_report.json
  - tests/golden/sacn_conflict/expected_report.json
  Metrics (universes/flows/conflicts) are unchanged.
