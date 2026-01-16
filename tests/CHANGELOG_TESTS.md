Test fixture notes

- compliance examples are deduplicated and capped (stable ordering); changes affect only `compliance[].violations[].examples` fields in:
  - tests/golden/artnet_conflict/expected_report.json
  - tests/golden/sacn_conflict/expected_report.json
  Metrics (universes/flows/conflicts) are unchanged.

- compliance examples now include source and timestamp context (`source IP:port @ timestamp`); changes affect only
  `compliance[].violations[].examples` fields in:
  - tests/golden/artnet/expected_report.json
  - tests/golden/artnet_burst/expected_report.json
  - tests/golden/artnet_conflict/expected_report.json
  - tests/golden/artnet_gap/expected_report.json
  - tests/golden/artnet_invalid_length/expected_report.json
  - tests/golden/flow_only/expected_report.json
  - tests/golden/sacn/expected_report.json
  - tests/golden/sacn_burst/expected_report.json
  - tests/golden/sacn_conflict/expected_report.json
  - tests/golden/sacn_gap/expected_report.json
  - tests/golden/sacn_invalid_start_code/expected_report.json
  Metrics (universes/flows/conflicts) are unchanged.

- UDP missing network layer/payload violations are now `warning` severity; changes affect only
  `compliance[].violations[].severity` fields in:
  - tests/golden/flow_only/expected_report.json
