# Changelog

## Unreleased

### Breaking (v2.0 tool surface)

- Renamed `triage_pcap` to `analyze_pcap` with profile-based analysis: `baseline` (protocol logs and Community ID only), `standard` (protocol-relevant detections), `full` (every enabled detection). The `scripts` array parameter was removed.
- Renamed `summarize_logs` to `query_logs`: queries persisted JSON logs from an existing run by `run_id`/`log` with `select` projection, `predicates` filtering, `aggregate`, and cursor pagination. Never reparses the pcap.
- Removed the `hunt_signature` tool; signature handling is no longer exposed on the MCP surface.
- Removed the `list_runs`, `get_run_manifest`, and `cleanup_runs` tools; run discovery now uses the `zeek://runs` resource.
- Tool results use the versioned `ToolResultV2` envelope with `schema_version: 2.0`.
- `build.sh` now emits `bin/zeek-mcp` (server) and `bin/zeek-pcap` (CLI); the default version is 2.0.0.

### Added

- Added the `zeek-pcap` CLI, which dispatches through the same handlers as MCP so validation, schemas, execution, and artifact semantics stay identical across transports.
- Script registry parses rich metadata headers: `RuleVersion`, `DetectionPack`, `PackVersion`, `Severity`, `Confidence`, `Protocols`, `ATT&CK`, `FalsePositives`, `RequiredLogs`, and `TestPcap`.
- Added detection scripts for firmware download hijack, firmware upgrade hijack, and Tenda CVE-2018-5767.

### Fixed and Changed

- Upgraded target Zeek version to 9.0.0 LTS (Dockerfile, server banner, README, SECURITY).
- Upgraded mcp-go from v0.57.0 to v1.1.1.
- Bumped Go toolchain floor to 1.26.8 (go.mod, Docker builder image) to pick up the 1.26.6–1.26.8 security fixes.
- Fixed `Executor.WithTimeout` dropping the concurrency semaphore, which deadlocked `run_custom_script` until timeout.
- Fixed `zeekCompatibility` version-prefix detection (was never reporting `same_lts_line`) and wired it into startup logs and artifact manifests.
- Propagated `ZEEK_BINARY` to pcap metadata fallback, `validate_script`, and version detection.
- Notice parsing: fall back to `$src`/`$dst` fields (Zeek 7+) when `id.orig_h`/`id.resp_h` are absent; parse `id.orig_p`/`id.resp_p` and `$src_p`/`$dst_p` including `port/proto` string format.
- Coverage report in `analyze_pcap` now marks scripts that failed staging as `error`/`staging_failed` instead of `no_match`.
- `analyze_pcap` envelope now reports `truncated` and `capture.sampled` when pcap metadata was derived from sampled Zeek logs.
- Capture duration estimation now uses conn.log `duration` field and warns when estimated from samples.
- Log summaries report `sample_truncated` and `read_error` per log; Zeek log readers surface `scanner` errors instead of silently stopping.
- Extracted file integrity is now derived from files.log (`missing_bytes`/`timeout`) instead of hardcoded values.
- Script staging failures now surface as `staging_failed` execution errors and adjust `total_scripts_run`.
- Alert `log_locator.path` now points to persisted log artifacts instead of the removed work directory.
- Added NTP log hints (`ntp`, `ntp_control`, `ntp_private`) for Zeek 9 metadata detection.
- Added Docker-first GHCR release workflow; releases now run `go vet`/`go test -race` in CI and smoke-verify the built image (Zeek 9.0 line and `zeek-mcp` entrypoint) before pushing.
- Added persistent analysis run manifests and artifact indexing.
- Added opt-in artifact retention and cleanup controls.
- Standardized Docker intake/output workflow for MCP clients.
- Added TLS support for HTTP transport (`--tls-cert`, `--tls-key`).
- Added `ZEEK_INSPECT_TIMEOUT_SECONDS` and `ZEEK_PARSE_TIMEOUT_SECONDS` for fine-grained timeout control.
- Enhanced `validateCustomScriptSafety` to strip comments before checking blocked patterns.
- Refactored `Executor.WithTimeout` to avoid unsafe struct value copy.
- Unified docs to English and synced tool names, binary names, and version references to the v2.0 surface.
