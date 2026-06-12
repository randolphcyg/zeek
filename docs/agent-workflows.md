# Agent Workflows

## Pcap Triage

1. Call `health_check` to confirm Zeek and path maps are available.
2. Call `list_pcaps` and reuse a returned `path` value.
3. Call `triage_pcap` for the default high-success flow.
4. For manual control, call `inspect_capture`, review `protocols` and `suggested_scripts`, then run `detect_threats`.

Agents should report low-confidence or empty findings plainly. They should not invent malicious activity when Zeek returns no relevant evidence.

For packet-level verification, pass alerts from `triage_pcap` to epan MCP (an external Wireshark-based packet analysis tool) using `epan_verify_zeek_alert`, then create evidence with `epan_create_evidence_bundle` only after narrowing the filter.

When the server runs in the default Zeek-only Docker image, `inspect_capture` uses a Zeek log fallback if `tshark` and `capinfos` are unavailable. Treat fallback warnings as reduced packet-level metadata, not as a detection failure. Use `generate_logs` or `detect_threats` for deeper Zeek-native analysis.

## Intake And Artifacts

Docker-based agents should place pcaps in the mounted intake directory, typically `/pcaps` inside the container and a configured host directory such as `/Users/randolph/goodjob/zeek_runner/pcaps`. A pcap outside mounted paths cannot be analyzed until the MCP server is restarted with a Docker volume and matching path map.

Every execution tool creates a persistent run directory under `/outputs/runs/<run_id>/` unless `output_dir` points to another mapped writable output root. Responses include `run_id`, `run_dir`, `manifest_path`, and `artifacts`.

Use this handoff pattern for multi-agent workflows:

1. Detection agent runs `detect_threats`, `generate_logs`, or `extract_files`.
2. File-analysis agent calls `get_run_manifest` and reads artifacts where `kind=extracted_file`.
3. Log-analysis agent reads artifacts where `kind=zeek_log`.
4. Report agent writes summaries under the same run's `reports/` directory and references the original `manifest.json`.

## Artifact Cleanup

Artifacts are retained by default. Use `list_runs` to review `artifact_bytes` and `total_bytes`, then use `cleanup_runs` with `dry_run=true` before deleting.

Actual deletion requires `dry_run=false` and `confirm=true`. Agents should never request destructive cleanup unless the user explicitly asks for it.

## Full Detection Sweep

Call `detect_threats` with only `pcap_path`. The server runs all enabled detection scripts and excludes extraction scripts unless `extract_files=true`.

To run several selected scripts against the same pcap in one execution, pass a `scripts` array:

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

## File Extraction

Call `extract_files` when the task asks for transferred firmware, executables, archives, packages, disk images, or other suspicious files. Extracted file metadata is returned in `extracted_files` and indexed in the run manifest.

## Generated Zeek Scripts

Use `validate_script` first for any generated script. Use `run_custom_script` only when the MCP server is running in a sandbox and `ZEEK_ENABLE_CUSTOM_SCRIPT=true`.

Generated scripts should prefer Zeek framework APIs and avoid process execution, Broker listeners, cluster control, supervisor APIs, and live deployment management.

## Log-Oriented Reasoning

Use `generate_logs` when an agent needs raw behavioral context rather than a detection verdict. Useful logs include:

- `conn`, `dns`, `http`, `ssl`, `x509`
- `files`, `ssh`, `smtp`, `smb`, `rdp`
- `tunnel`, `weird`, `notice`, `analyzer`

The tool returns compact JSON samples and field lists so agents can decide whether a custom script, signature, or specific detector is appropriate.

## Intel Matching

Use `match_intel` with:

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

## Signature Matching

Use `run_signature` for simple packet or stream signatures. Prefer signatures for narrow pattern matching and Zeek scripts for stateful protocol logic.
