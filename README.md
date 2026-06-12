# Zeek MCP

Zeek MCP is a local stdio MCP server that lets agents inspect pcaps, run bundled Zeek detection scripts, extract suspicious files, validate generated Zeek scripts, generate Zeek log summaries, run Intel matching, and execute Zeek signatures.

The project targets offline pcap analysis on Zeek 8.0.8 LTS. Newer feature releases may work, but release validation should include the Zeek 8.0.8 container. Live Zeek cluster and supervisor operations are intentionally out of scope.

## Requirements

- Docker, for the recommended GHCR image runtime
- Go 1.22 or newer, only for native builds
- Zeek 8.0.8 LTS or compatible, only for native runtime
- Optional Wireshark CLI tools for richer native pcap inspection: `capinfos` and `tshark`

## Install From GHCR

Docker is the recommended installation path because the image includes the validated Zeek 8.0.8 runtime. The published image for this repository is:

```bash
docker pull ghcr.io/randolphcyg/zeek:latest
mkdir -p ~/zeek_outputs
```

Use this command shape in MCP clients (macOS):

```bash
docker run --rm -i \
  -v /Users:/Users:ro \
  -v ~/zeek_outputs:/outputs \
  -e ZEEK_ENABLE_CUSTOM_SCRIPT=false \
  ghcr.io/randolphcyg/zeek:latest \
  --base-dir /app \
  --scripts-dir /app/scripts
```

By mounting `/Users:/Users:ro`, agents can reference any pcap by its original absolute path (e.g. `/Users/alice/Downloads/capture.pcap`) without path mapping.

For first-time setup, see `docs/quickstart.md`. For MCP tool parameters and examples, see `docs/tools.md`.

## Build

Native builds are advanced mode because the host must provide Zeek:

```bash
./build.sh -s
```

The server binary is written to `bin/zeek`.

Docker builds use `zeek/zeek:8.0.8` by default. The default image is Zeek-only and does not install Wireshark CLI tools:

```bash
./build.sh -d
```

Build the larger inspection image when you want `inspect_capture` to use `capinfos` and `tshark` for packet counts, durations, and protocol hierarchy summaries:

```bash
./build.sh -d --with-pcap-tools
```

Docker builds use the current Docker daemon platform by default. Pass `--platform` only when you need a specific target architecture:

```bash
./build.sh -d --platform linux/amd64
./build.sh -d --platform linux/arm64
```

## Run

```bash
./bin/zeek --base-dir /path/to/zeek --scripts-dir /path/to/zeek/scripts
```

Docker is the recommended MCP runtime when you need the bundled Zeek 8.0.8 environment. Mount the host user directory at the same path for transparent path access:

```bash
# macOS — mount /Users so any absolute path works directly
docker run --rm -i \
  -v /Users:/Users:ro \
  -v ~/zeek_outputs:/outputs \
  ghcr.io/randolphcyg/zeek:latest \
  --base-dir /app \
  --scripts-dir /app/scripts

# Linux — mount /home (add other directories as needed)
docker run --rm -i \
  -v /home:/home:ro \
  -v ~/zeek_outputs:/outputs \
  ghcr.io/randolphcyg/zeek:latest \
  --base-dir /app \
  --scripts-dir /app/scripts
```

With this approach, agents can use any host path directly (e.g. `/Users/alice/Downloads/capture.pcap`). No `ZEEK_PATH_MAPS` configuration is needed.

For restricted environments where you want to limit pcap access to a specific directory, use explicit path maps:

```bash
docker run --rm -i \
  -v /host/pcaps:/pcaps:ro \
  -v /host/outputs:/outputs \
  -e ZEEK_PATH_MAPS=/host/pcaps=/pcaps,/host/outputs=/outputs \
  zeek:latest \
  --base-dir /app \
  --scripts-dir /app/scripts
```

Execution tools write persistent artifacts under `/outputs/runs/<run_id>/` by default:

```text
runs/<run_id>/
  logs/
  extracted/
  reports/
  manifest.json
```

The response includes `run_id`, `run_dir`, `manifest_path`, and `artifacts`. Downstream agents should read `manifest.json` or call `get_run_manifest` instead of guessing output paths.

`tshark` and `capinfos` are not required for core detection, extraction, log generation, Intel matching, signature matching, or custom script execution. Without them, `inspect_capture` still validates paths and returns Zeek-driven suggestions where possible, but protocol and timing metadata may be sparse and warnings will explain the reduced inspection capability.

If Docker BuildKit fails while checking remote base-image metadata but `zeek/zeek:8.0.8` is already cached locally, use the local builder:

```bash
./build.sh -d --legacy-builder
```

Useful environment variables:

- `ZEEK_BINARY=zeek` — path to Zeek binary (default: `zeek`).
- `ZEEK_TIMEOUT_SECONDS=120` — default execution timeout for Zeek runs.
- `ZEEK_PARSE_TIMEOUT_SECONDS=30` — timeout for `zeek --parse-only` syntax checks.
- `ZEEK_INSPECT_TIMEOUT_SECONDS=60` — timeout for Zeek-inspection fallback in `enrichPcapInfoFromZeek`.
- `ZEEK_MAX_LOG_RECORDS=20` — default max records per log summary.
- `ZEEK_ENABLE_CUSTOM_SCRIPT=true` enables `run_custom_script`.
- `ZEEK_RETAIN_WORKDIR=true` keeps temporary Zeek work directories and returns log paths for debugging.
- `ZEEK_PATH_MAPS=/host/pcaps=/pcaps,/host/outputs=/outputs` maps host paths that an MCP client may send into Docker-visible paths. Not needed when using same-path mounts like `-v /Users:/Users:ro`.
- `ZEEK_HOST_MOUNT=/host` fallback mount point for container environments where the host filesystem is mounted at a different prefix (e.g. `-v /:/host:ro`).
- `ZEEK_ARTIFACT_RETENTION_DAYS=0` disables automatic age-based cleanup by default.
- `ZEEK_ARTIFACT_CLEANUP_ON_START=false` disables startup cleanup by default.
- `ZEEK_ARTIFACT_MAX_BYTES=0` disables automatic size-based cleanup by default.
- `MCP_CALL_LOG_PATH=/path/to/zeek-mcp-calls.jsonl` records JSONL tool-call telemetry with `trace_id`, `tool_name`, `status`, `error_code`, `duration_ms`, and `output_bytes`.
- `MCP_TRACE_ID` overrides the auto-generated trace_id for debugging.

Equivalent CLI flag:

```bash
./bin/zeek --path-map /host/pcaps=/pcaps
```

## Script Layout

Scripts live under one canonical root:

```text
scripts/
  detections/
  extraction/
  utilities/
```

Every script uses the same metadata header:

```zeek
# ScriptID: DETECT_EXAMPLE_v1
# Type: detection
# Category: web_attack
# Description: Detect example behavior.
# Signature: Example traffic feature.
# NoticeTypes: Example::Notice
# Enabled: true
```

Extraction scripts are discoverable, but `detect_threats` only runs `Type: detection` scripts by default. File extraction is enabled through `extract_files` or `extract_files=true`.

## MCP Tools

- `list_scripts`: list bundled scripts and metadata.
- `inspect_capture`: inspect capture metadata and suggest scripts.
- `detect_threats`: run bundled detection scripts and return normalized alerts.
- `extract_files`: extract suspicious transferred files.
- `get_script`: return script metadata and optional source.
- `health_check`: report server and Zeek availability.
- `validate_script`: run `zeek --parse-only`.
- `run_custom_script`: validate and run generated Zeek scripts, only registered when `ZEEK_ENABLE_CUSTOM_SCRIPT=true`.
- `generate_logs`: summarize selected Zeek logs.
- `match_intel`: run Zeek Intel matching for supplied indicators.
- `run_signature`: run Zeek signature files or content.
- `get_run_manifest`: read a saved run manifest by `run_id` or `manifest_path`.
- `list_runs`: list recent saved analysis runs.
- `cleanup_runs`: preview or delete old analysis runs; deletion requires `dry_run=false` and `confirm=true`.
- `list_pcaps`: list configured intake PCAPs and return tool-ready paths.
- `triage_pcap`: inspect a capture, run detections, and return a compact triage summary for downstream Wireshark verification.

`detect_threats` supports multiple scripts in one pcap analysis through the `scripts` array. If `scripts` is omitted, Zeek MCP runs all enabled detection scripts.

Tool names are intentionally breaking and Agent-oriented. Removed legacy names are not registered. Restart MCP clients after upgrading so they refresh the schema.

Set `MCP_CALL_LOG_PATH=/path/to/zeek-mcp-calls.jsonl` to record JSONL tool-call telemetry with `trace_id`, `tool_name`, `status`, `error_code`, `duration_ms`, and `output_bytes`.

## Artifact Retention

Zeek MCP does not delete analysis artifacts by default. This avoids accidental loss of evidence. Use `cleanup_runs` for manual cleanup:

```json
{
  "older_than_days": 30,
  "dry_run": true
}
```

Actual deletion requires:

```json
{
  "older_than_days": 30,
  "dry_run": false,
  "confirm": true
}
```

Startup cleanup is opt-in with `ZEEK_ARTIFACT_CLEANUP_ON_START=true` plus `ZEEK_ARTIFACT_RETENTION_DAYS` or `ZEEK_ARTIFACT_MAX_BYTES`.

## Publishing

The release workflow publishes multi-architecture images to GHCR when a `v*` tag is pushed or the workflow is run manually. After the first publish, set the GHCR package visibility to public if this repository is intended for public installation.

## Safety Model

Generated script execution is disabled by default. When enabled, the server applies a static safety check, writes script content to a temporary file, validates it with `zeek --parse-only`, runs with a timeout, and removes the temporary work directory unless debug retention is enabled.

For production use, run this MCP server in a container or sandbox with resource limits and no network access.
