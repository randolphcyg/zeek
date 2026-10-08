# Tool Reference

MCP clients discover these tools through `tools/list`. This page is a human reference for common calls and expected outputs.

## Path Rules

With the recommended Docker config (mounting host directories at the same path inside the container), agents can use original host paths directly for any pcap file. The server resolves path mappings through `ZEEK_PATH_MAPS` when configured.

Use the `zeek://pcaps` resource to discover available pcap files. Unmapped host paths return `INVALID_PATH`.

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

## `analyze_pcap`

Runs one reusable Zeek analysis pass: generate protocol logs with Community ID, optionally run detections, persist artifacts, and return a compact summary.

```json
{
  "pcap_path": "/pcaps/sample.pcap"
}
```

Profiles:

- `baseline` (default): protocol logs and Community ID only, no custom detections. Deterministic preflight pass.
- `standard`: runs protocol-relevant detection scripts.
- `full`: runs every enabled detection script.

Run detections and file extraction together:

```json
{
  "pcap_path": "/pcaps/sample.pcap",
  "profile": "full",
  "extract_files": true
}
```

Useful fields:

- `capture.protocols`
- `alerts`
- `alert_count`
- `detection_coverage`
- `run_id`
- `manifest_path`
- `recommended_next`

## `query_logs`

Queries persisted JSON logs from an existing `analyze_pcap` run. This never reparses the pcap.

```json
{
  "run_id": "run_20260101_120000_abcd",
  "log": "conn",
  "limit": 50
}
```

Filter and project fields:

```json
{
  "run_id": "run_20260101_120000_abcd",
  "log": "http",
  "select": ["id.orig_h", "host", "uri"],
  "predicates": { "status_code": "200" },
  "aggregate": "count"
}
```

Useful fields:

- `records`
- `fields`
- `total`
- `cursor` for pagination (pass back as `cursor`)

## `hunt_intel`

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

## `extract_files`

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

## `validate_script`

Validates Zeek script syntax with `zeek --parse-only`.

```json
{
  "script_content": "event zeek_init() { print \"ok\"; }"
}
```

Other inputs:

- `script_name`
- `script_path`

## `run_custom_script`

Runs generated Zeek script content. Disabled unless `ZEEK_ENABLE_CUSTOM_SCRIPT=true`.

```json
{
  "pcap_path": "/pcaps/sample.pcap",
  "script_content": "event zeek_init() { print \"custom\"; }",
  "timeout_seconds": 60
}
```

Use only in a sandboxed runtime.

## Resources

The server exposes these MCP resources for discovery:

- `zeek://pcaps` — Available PCAP files. Returned path values are directly usable as `pcap_path`.
- `zeek://scripts/detections` — Enabled Zeek detection scripts run by the `standard` and `full` profiles of `analyze_pcap`.
- `zeek://scripts/{id}` — Metadata and full source for a bundled Zeek script. Replace `{id}` with a script name like `detect_dns_flood`.
- `zeek://runs` — Recent analysis run manifests from the configured output directory.

Agents should only delete artifacts after explicit user approval.