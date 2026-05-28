# MCP Client Configuration

Docker with GHCR is the default integration path. Use the published GHCR image below and replace host paths with local directories.

Prepare local directories:

```bash
mkdir -p /absolute/path/to/zeek_runner/pcaps /absolute/path/to/zeek_runner/outputs
```

## Codex

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
        "/absolute/path/to/zeek_runner/pcaps:/pcaps:ro",
        "-v",
        "/absolute/path/to/zeek_runner/outputs:/outputs",
        "-e",
        "ZEEK_MCP_ENABLE_CUSTOM_SCRIPT=false",
        "-e",
        "ZEEK_MCP_PATH_MAPS=/absolute/path/to/zeek_runner/pcaps=/pcaps,/absolute/path/to/zeek_runner/outputs=/outputs",
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

## Claude Desktop / Claude Code

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
        "/absolute/path/to/zeek_runner/pcaps:/pcaps:ro",
        "-v",
        "/absolute/path/to/zeek_runner/outputs:/outputs",
        "-e",
        "ZEEK_MCP_ENABLE_CUSTOM_SCRIPT=false",
        "-e",
        "ZEEK_MCP_PATH_MAPS=/absolute/path/to/zeek_runner/pcaps=/pcaps,/absolute/path/to/zeek_runner/outputs=/outputs",
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

## Trae

For Docker-based Trae usage, mount pcap and output directories into the container and pass runtime environment variables with Docker `-e`. This is the recommended Trae integration because the container provides the validated Zeek 8.0.8 runtime:

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
        "/absolute/path/to/zeek_runner/pcaps:/pcaps:ro",
        "-v",
        "/absolute/path/to/zeek_runner/outputs:/outputs",
        "-e",
        "ZEEK_MCP_ENABLE_CUSTOM_SCRIPT=false",
        "-e",
        "ZEEK_MCP_PATH_MAPS=/absolute/path/to/zeek_runner/pcaps=/pcaps,/absolute/path/to/zeek_runner/outputs=/outputs",
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

With that mapping, tools may receive either `/pcaps/sample.pcap` or `/absolute/path/to/zeek_runner/pcaps/sample.pcap`. Unmapped host paths return a `path_not_mounted` error that lists configured path maps.

The `/pcaps` mount is the read-only intake directory. The `/outputs` mount must be writable because execution tools create `/outputs/runs/<run_id>/` with `logs/`, `extracted/`, `reports/`, and `manifest.json`. A project mount is optional and can remain read-only because runtime scripts are baked into the image under `/app/scripts`.

Downstream agents should use `run_id`, `manifest_path`, `zeek_get_run_manifest`, and `zeek_list_runs` to continue file analysis, log analysis, or report generation.

Build options:

```bash
./build.sh -d
./build.sh -d --with-pcap-tools
```

The default Docker image is Zeek-only. `zeek_inspect_capture` will use a Zeek log fallback when `tshark` and `capinfos` are absent. `--with-pcap-tools` adds packet-level metadata from Wireshark CLI tools, which can improve duration, packet count, and protocol hierarchy details but increases image size.

If BuildKit cannot reach the registry metadata endpoint but the base images are already cached locally, build with:

```bash
./build.sh -d --legacy-builder
```

## Cursor / VS Code-Style MCP Clients

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
        "/absolute/path/to/zeek_runner/pcaps:/pcaps:ro",
        "-v",
        "/absolute/path/to/zeek_runner/outputs:/outputs",
        "-e",
        "ZEEK_MCP_ENABLE_CUSTOM_SCRIPT=false",
        "-e",
        "ZEEK_MCP_PATH_MAPS=/absolute/path/to/zeek_runner/pcaps=/pcaps,/absolute/path/to/zeek_runner/outputs=/outputs",
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

## Native Advanced Mode

Use the binary only when the host has Zeek installed:

```bash
./build.sh -s
```

Use an absolute path for both the command and `--base-dir`.

Enable custom script execution only in a sandbox:

```json
{
  "env": {
    "ZEEK_MCP_ENABLE_CUSTOM_SCRIPT": "true",
    "ZEEK_MCP_RETAIN_WORKDIR": "false"
  }
}
```
