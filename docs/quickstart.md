# Quick Start

This guide shows the shortest path from installing Zeek MCP to asking an MCP-capable agent to analyze a pcap.

## 1. Install The Docker Image

```bash
docker pull ghcr.io/randolphcyg/zeek_mcp:latest
```

## 2. Prepare Output Directory

Create a local directory for analysis artifacts:

```bash
mkdir -p ~/zeek_mcp_outputs
```

## 3. Configure Your MCP Client

The recommended configuration mounts `/Users` (macOS) at the same path inside the container, so agents can reference any pcap by its original absolute path:

```json
{
  "mcpServers": {
    "zeek_mcp": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-v",
        "/Users:/Users:ro",
        "-v",
        "/Users/alice/zeek_mcp_outputs:/outputs",
        "-e",
        "ZEEK_MCP_ENABLE_CUSTOM_SCRIPT=false",
        "ghcr.io/randolphcyg/zeek_mcp:latest",
        "--base-dir",
        "/app",
        "--scripts-dir",
        "/app/scripts"
      ]
    }
  }
}
```

Replace `/Users/alice/zeek_mcp_outputs` with your output directory path.

See `examples/mcp/` and `docs/mcp-clients.md` for client-specific configs and Linux setup.

Restart the MCP client after changing its config.

## 4. Ask An Agent

No need to copy pcaps to a special directory. Use the file's original path directly:

```text
Use Zeek MCP to check health.
```

```text
Use Zeek MCP to inspect /Users/alice/Downloads/suspicious.pcap and suggest relevant detection scripts.
```

```text
Run Zeek MCP detection on /Users/alice/research/attack_sample.pcapng using all enabled detection scripts.
```

```text
Run detect_dns_flood and detect_syn_flood against /Users/alice/captures/network.pcap with Zeek MCP.
```

```text
Extract files from /Users/alice/Downloads/malware_traffic.pcap with Zeek MCP.
```

## 5. Read Results

Execution tools return:

- `run_id`
- `manifest_path`
- `artifacts`
- `alerts`
- `extracted_files`
- `log_summaries`

Artifacts are written under:

```text
~/zeek_mcp_outputs/runs/<run_id>/
  logs/
  extracted/
  reports/
  manifest.json
```

Use `zeek_get_run_manifest` when another agent needs to continue from a previous run.

## Troubleshooting

- **pcap_path not found**: verify the file exists at the given absolute path. On macOS, all user files should be under `/Users/`.
- **output_dir_unavailable**: `/outputs` is not mounted or is read-only. Ensure the output volume is writable.
- **docker: command not found**: install Docker Desktop or Docker Engine.
- **pull access denied**: confirm the GHCR package is public or that Docker is logged in with access.
- **No protocol metadata from `zeek_inspect_capture`**: the slim image does not include `tshark/capinfos`; Zeek MCP falls back to Zeek logs where possible. Use `--with-pcap-tools` build for richer metadata.

## Alternative: Native Binary (No Docker)

If Zeek is installed on your host, run `zeek_mcp` directly. Any filesystem path is accessible with zero configuration:

```json
{
  "mcpServers": {
    "zeek_mcp": {
      "command": "/path/to/zeek_mcp",
      "args": [
        "--base-dir", "/path/to/zeek_mcp_project",
        "--scripts-dir", "/path/to/zeek_mcp_project/scripts"
      ]
    }
  }
}
```
