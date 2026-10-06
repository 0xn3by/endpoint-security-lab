# Evidence provenance

- `private/` is ignored by Git. It contains original local telemetry, exported manager alerts and Windows evidence when collected. Treat it as sensitive.
- `validation/live-network/` contains actual redacted Linux helper events, extracts from matching real Wazuh alerts, and a verification summary. Redacted extracts are not raw forensic originals.
- `validation/rule-tests/` contains actual Wazuh logtest output for explicitly synthetic test inputs. These files prove only contract-test behavior with the documented test decoder bridge. They are never incident evidence or real Windows alerts.

Raw event-file hashes refer to originals before redaction; do not expect a redacted file to have the same hash. The original matching network run ID is retained in incident 004. Keep separate copies when repeating experiments, and update the report if publishing a newer run. Public evidence must not be described as production telemetry.
