# Quick Start

This guide shows the shortest path from installing Zeek MCP to asking an MCP-capable agent to analyze a pcap.

## 1. Install The Docker Image

```bash
docker pull ghcr.io/randolphcyg/zeek_mcp:latest
```

## 2. Prepare A Zeek MCP Workspace

Create one local workspace that Docker is allowed to access:

```bash
mkdir -p ~/zeek_runner/pcaps ~/zeek_runner/outputs
```

- `~/zeek_runner/pcaps`: input pcaps.
- `~/zeek_runner/outputs`: analysis logs, extracted files, reports, and manifests.

Docker-based MCP servers cannot read arbitrary host paths. Put pcaps in the configured intake directory, then refer to them as `/pcaps/<name>.pcap` in the agent.

## 3. Configure Your MCP Client

Use the config examples in `examples/mcp/` or `docs/mcp-clients.md`. Replace `/absolute/path/to/zeek_runner` with your local workspace path.

For example, if your workspace is `/Users/alice/zeek_runner`, use:

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
        "/Users/alice/zeek_runner/pcaps:/pcaps:ro",
        "-v",
        "/Users/alice/zeek_runner/outputs:/outputs",
        "-e",
        "ZEEK_MCP_ENABLE_CUSTOM_SCRIPT=false",
        "-e",
        "ZEEK_MCP_PATH_MAPS=/Users/alice/zeek_runner/pcaps=/pcaps,/Users/alice/zeek_runner/outputs=/outputs",
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

Restart the MCP client after changing its config.

## 4. Add A Pcap

Copy a pcap into the intake directory:

```bash
cp sample.pcap ~/zeek_runner/pcaps/
```

The MCP-visible path is:

```text
/pcaps/sample.pcap
```

## 5. Ask An Agent

Example prompts:

```text
Use Zeek MCP to check health.
```

```text
Use Zeek MCP to inspect /pcaps/sample.pcap and suggest relevant detection scripts.
```

```text
Run Zeek MCP detection on /pcaps/sample.pcap using all enabled detection scripts.
```

```text
Run detect_dns_flood and detect_syn_flood against /pcaps/sample.pcap with Zeek MCP.
```

```text
Extract files from /pcaps/sample.pcap with Zeek MCP and summarize the generated artifact manifest.
```

## 6. Read Results

Execution tools return:

- `run_id`
- `manifest_path`
- `artifacts`
- `alerts`
- `extracted_files`
- `log_summaries`

Artifacts are written under:

```text
~/zeek_runner/outputs/runs/<run_id>/
  logs/
  extracted/
  reports/
  manifest.json
```

Use `zeek_get_artifact_manifest` when another agent needs to continue from a previous run.

## Troubleshooting

- `path_not_mounted`: the pcap is outside the mounted intake directory. Move it under `~/zeek_runner/pcaps` or update the Docker volume and path map.
- `output_dir_unavailable`: `/outputs` is not mounted or is read-only. Ensure the output volume is writable.
- `docker: command not found`: install Docker Desktop or Docker Engine.
- `pull access denied`: confirm the GHCR package is public or that Docker is logged in with access.
- No protocol metadata from `zeek_inspect_pcap`: the slim image does not include `tshark/capinfos`; Zeek MCP falls back to Zeek logs where possible.
