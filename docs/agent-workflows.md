# Agent Workflows

## Pcap Triage

1. Use the `zeek://pcaps` resource to discover available pcap files.
2. Call `analyze_pcap` for the default high-success flow.

Agents should report low-confidence or empty findings plainly. They should not invent malicious activity when Zeek returns no relevant evidence.

For packet-level verification, pass alerts from `analyze_pcap` to epan MCP (an external Wireshark-based packet analysis tool) using `verify_zeek_alert`, then create evidence with `build_evidence` only after narrowing the filter.

When the server runs in the default Zeek-only Docker image, `analyze_pcap` uses Zeek's own log output for protocol metadata when `capinfos` is unavailable. Treat fallback warnings as reduced packet-level metadata, not as a detection failure. Use `query_logs` for deeper Zeek-native analysis.

## Intake And Artifacts

Docker-based agents should place pcaps in the mounted intake directory, typically `/pcaps` inside the container and a configured host directory such as `/Users/randolph/goodjob/zeek_runner/pcaps`. A pcap outside mounted paths cannot be analyzed until the MCP server is restarted with a Docker volume and matching path map.

Every execution tool creates a persistent run directory under `/outputs/runs/<run_id>/` unless `output_dir` points to another mapped writable output root. Responses include `run_id`, `run_dir`, `manifest_path`, and `artifacts`.

Use this handoff pattern for multi-agent workflows:

1. Detection agent runs `analyze_pcap`, `query_logs`, or `extract_files`.
2. File-analysis agent reads artifacts where `kind=extracted_file`.
3. Log-analysis agent reads artifacts where `kind=zeek_log`.
4. Report agent writes summaries under the same run's `reports/` directory and references the original `manifest.json`.

## Artifact Cleanup

Artifacts are retained by default. Configure automatic cleanup with `ZEEK_ARTIFACT_CLEANUP_ON_START=true` plus `ZEEK_ARTIFACT_RETENTION_DAYS` or `ZEEK_ARTIFACT_MAX_BYTES`.

Agents should never request destructive cleanup unless the user explicitly asks for it.

## Full Detection Sweep

Call `analyze_pcap` with `profile=full` to run every enabled detection script. Extraction scripts still run only when `extract_files=true`:

```json
{
  "pcap_path": "/pcaps/sample.pcap",
  "profile": "full"
}
```

Use `profile=standard` to run only the protocol-relevant subset of detections, or the default `baseline` for a protocol-logs-only preflight pass.

## File Extraction

Call `extract_files` when the task asks for transferred firmware, executables, archives, packages, disk images, or other suspicious files. Extracted file metadata is returned in `extracted_files` and indexed in the run manifest.

## Generated Zeek Scripts

Use `validate_script` first for any generated script. Use `run_custom_script` only when the MCP server is running in a sandbox and `ZEEK_ENABLE_CUSTOM_SCRIPT=true`.

Generated scripts should prefer Zeek framework APIs and avoid process execution, Broker listeners, cluster control, supervisor APIs, and live deployment management.

## Log-Oriented Reasoning

Use `query_logs` against an existing `analyze_pcap` run when an agent needs raw behavioral context rather than a detection verdict. It reads persisted JSON logs and never reparses the pcap. Useful logs include:

- `conn`, `dns`, `http`, `ssl`, `x509`
- `files`, `ssh`, `smtp`, `smb`, `rdp`
- `tunnel`, `weird`, `notice`, `analyzer`

The tool supports `select` projection, `predicates` filtering, `aggregate`, and cursor pagination so agents can decide whether a custom script or a specific detector is appropriate.

## Intel Matching

Use `hunt_intel` with:

```json
{
  "pcap_path": "/absolute/path/to/sample.pcap",
  "indicators": {
    "ips": ["203.0.113.10"],
    "domains": ["example-malware.test"],
    "urls": ["http://example-malware.test/payload"],
    "hashes": ["0123456789abcdef0123456789abcdef"]
  }
}
```

The tool also accepts `intel_file` for existing Zeek Intel TSV files.