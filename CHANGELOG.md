# Changelog

## Unreleased

- Added Docker-first GHCR release workflow.
- Added persistent analysis run manifests and artifact indexing.
- Added `get_run_manifest`, `list_runs`, and `cleanup_runs`.
- Added opt-in artifact retention and cleanup controls.
- Standardized Docker intake/output workflow for MCP clients.
- Added TLS support for HTTP transport (`--tls-cert`, `--tls-key`).
- Added `ZEEK_INSPECT_TIMEOUT_SECONDS` and `ZEEK_PARSE_TIMEOUT_SECONDS` for fine-grained timeout control.
- Enhanced `validateCustomScriptSafety` to strip comments before checking blocked patterns.
- Refactored `Executor.WithTimeout` to avoid unsafe struct value copy.
