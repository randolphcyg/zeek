# Tool Reference

MCP clients discover these tools through `tools/list`. This page is a human reference for common calls and expected outputs.

## Path Rules

Docker runtime can only access mounted paths. With the recommended config:

- Use `/pcaps/<file>.pcap` for input captures.
- Use `/outputs` or omit `output_dir` for artifacts.
- Host paths under the configured pcap/output directories are translated through `ZEEK_MCP_PATH_MAPS`.

Unmapped host paths return `path_not_mounted`.

## Common Response Fields

Execution tools return:

- `status`: `completed`, `error`, or `timeout`.
- `requested_path`: path provided by the client.
- `resolved_path`: path used inside the container.
- `run_id`: analysis run identifier.
- `run_dir`: persistent output run directory.
- `manifest_path`: artifact manifest path.
- `artifacts`: persisted logs and extracted files.
- `warnings` and `errors`: execution diagnostics.

## `zeek_health_check`

Checks server and Zeek runtime health.

```json
{}
```

Useful fields:

- `runtime_zeek`
- `zeek_ok`
- `scripts_loaded`
- `path_maps`

## `zeek_inspect_capture`

Inspects a pcap and suggests bundled detection scripts.

```json
{
  "pcap_path": "/pcaps/sample.pcap"
}
```

Useful fields:

- `protocols`
- `services`
- `suggested_scripts`
- `analysis_status`

## `zeek_list_detection_scripts`

Lists bundled scripts. Despite the historical tool name, it can list detection, extraction, and utility scripts.

```json
{
  "type": "detection",
  "enabled_only": true
}
```

Filters:

- `type`: `detection`, `extraction`, or `utility`
- `category`
- `name`
- `enabled_only`

## `zeek_detect_threats`

Runs detection scripts against one pcap.

Run all enabled detection scripts:

```json
{
  "pcap_path": "/pcaps/sample.pcap"
}
```

Run multiple selected scripts in one analysis:

```json
{
  "pcap_path": "/pcaps/sample.pcap",
  "scripts": [
    "detect_dns_flood",
    "detect_syn_flood",
    "detect_http_suspicious_ua"
  ]
}
```

Run detections and file extraction together:

```json
{
  "pcap_path": "/pcaps/sample.pcap",
  "extract_files": true
}
```

The `scripts` array accepts script names or ScriptIDs. Empty or omitted means all enabled detection scripts.

Useful fields:

- `alerts`
- `statistics.total_scripts_run`
- `statistics.total_alerts`
- `manifest_path`
- `artifacts`

## `zeek_extract_files`

Runs bundled extraction scripts and stores extracted files under the run directory.

```json
{
  "pcap_path": "/pcaps/sample.pcap"
}
```

Useful fields:

- `extracted_files`
- `artifacts` where `kind=extracted_file`
- `manifest_path`

## `zeek_generate_logs`

Runs Zeek and returns compact summaries of selected logs.

```json
{
  "pcap_path": "/pcaps/sample.pcap",
  "logs": ["conn", "dns", "http", "notice"],
  "max_records": 20
}
```

Useful logs:

- `conn`, `dns`, `http`, `ssl`, `x509`
- `files`, `ssh`, `smtp`, `smb`, `rdp`
- `tunnel`, `weird`, `notice`, `analyzer`

Useful fields:

- `log_summaries`
- `log_paths`
- `artifacts` where `kind=zeek_log`

## `zeek_match_intel`

Runs Zeek Intel matching from inline indicators or an Intel TSV file.

```json
{
  "pcap_path": "/pcaps/sample.pcap",
  "indicators": {
    "ips": ["203.0.113.10"],
    "domains": ["example-malware.test"],
    "urls": ["http://example-malware.test/payload"],
    "hashes": ["0123456789abcdef0123456789abcdef"]
  }
}
```

Or:

```json
{
  "pcap_path": "/pcaps/sample.pcap",
  "intel_file": "/workspace/intel.tsv"
}
```

## `zeek_run_signature`

Runs Zeek signature content or a mounted signature file.

```json
{
  "pcap_path": "/pcaps/sample.pcap",
  "signature_content": "signature sample-sig {\\n  ip-proto == tcp\\n  event \"sample signature\"\\n}\\n"
}
```

## `zeek_validate_script`

Validates Zeek script syntax with `zeek --parse-only`.

```json
{
  "script_content": "event zeek_init() { print \"ok\"; }"
}
```

Other inputs:

- `script_name`
- `script_path`

## `zeek_run_custom_script`

Runs generated Zeek script content. Disabled unless `ZEEK_MCP_ENABLE_CUSTOM_SCRIPT=true`.

```json
{
  "pcap_path": "/pcaps/sample.pcap",
  "script_content": "event zeek_init() { print \"custom\"; }",
  "timeout_seconds": 60
}
```

Use only in a sandboxed runtime.

## `zeek_get_detection_script`

Returns metadata and optional source for a bundled script.

```json
{
  "script_name": "detect_dns_flood",
  "include_source": true
}
```

## `zeek_reload_scripts`

Reloads script metadata from the script directory.

```json
{}
```

## `zeek_get_version`

Returns MCP build metadata and Zeek runtime version.

```json
{}
```

## `zeek_get_run_manifest`

Reads a saved artifact manifest for downstream agents.

```json
{
  "run_id": "20260528T030544Z_75db3e06"
}
```

Or:

```json
{
  "manifest_path": "/outputs/runs/20260528T030544Z_75db3e06/manifest.json"
}
```

## `zeek_list_runs`

Lists saved analysis runs.

```json
{
  "limit": 10
}
```

Useful fields:

- `total`
- `total_bytes`
- `runs[].artifact_bytes`

## `zeek_cleanup_runs`

Previews or deletes old artifacts. Defaults to dry-run.

Preview:

```json
{
  "older_than_days": 30,
  "dry_run": true
}
```

Delete:

```json
{
  "older_than_days": 30,
  "dry_run": false,
  "confirm": true
}
```

## `zeek_list_pcaps`

Lists PCAP files from configured intake directories. Use the returned `path` directly as `pcap_path` in other tools.

```json
{}
```

Useful fields:

- `pcaps[].name`
- `pcaps[].path`
- `pcaps[].size`

## `zeek_triage_pcap`

Runs the recommended Agent workflow in one call: inspect capture metadata, run bundled detections, persist artifacts, and return a compact summary.

```json
{
  "pcap_path": "/pcaps/sample.pcap"
}
```

Useful fields:

- `capture.protocols`
- `alerts`
- `run_id`
- `manifest_path`
- `recommended_next`

Agents should only delete artifacts after explicit user approval.
