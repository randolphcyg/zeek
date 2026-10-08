# MCP Client Configuration

Docker is the default integration path. Mount the host user directory at the **same path** inside the container so agents can reference any pcap by its original absolute path without path mapping.

## Prerequisites

Create an output directory for analysis artifacts:

```bash
# macOS / Linux
mkdir -p ~/zeek_outputs

# Windows (PowerShell)
mkdir "$env:USERPROFILE\zeek_outputs"
```

## Platform Configuration

### macOS

```json
{
  "mcpServers": {
    "zeek": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-v", "/Users:/Users:ro",
        "-v", "/Users/yourname/zeek_outputs:/outputs",
        "-e", "ZEEK_ENABLE_CUSTOM_SCRIPT=false",
        "ghcr.io/randolphcyg/zeek:latest",
        "--base-dir", "/app",
        "--scripts-dir", "/app/scripts"
      ]
    }
  }
}
```

On macOS, all user files reside under `/Users`, so one mount covers all pcap locations.

### Linux

```json
{
  "mcpServers": {
    "zeek": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-v", "/home:/home:ro",
        "-v", "/tmp:/tmp:ro",
        "-v", "/home/yourname/zeek_outputs:/outputs",
        "-e", "ZEEK_ENABLE_CUSTOM_SCRIPT=false",
        "ghcr.io/randolphcyg/zeek:latest",
        "--base-dir", "/app",
        "--scripts-dir", "/app/scripts"
      ]
    }
  }
}
```

If pcap files are spread across directories outside `/home` (e.g., `/opt`, `/var/log`, `/data`), add the corresponding read-only mounts:

```json
"-v", "/opt:/opt:ro",
"-v", "/data:/data:ro"
```

### Windows (Docker Desktop)

On Windows, Docker Desktop uses the WSL2 backend. Host disks are automatically mapped to `/mnt/` paths. Use `ZEEK_PATH_MAPS` to translate Windows paths to Linux paths:

```json
{
  "mcpServers": {
    "zeek": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-v", "C:\\Users:/Users:ro",
        "-v", "C:\\Users\\yourname\\zeek_outputs:/outputs",
        "-e", "ZEEK_ENABLE_CUSTOM_SCRIPT=false",
        "-e", "ZEEK_PATH_MAPS=C:\\Users=/Users,C:/Users=/Users",
        "ghcr.io/randolphcyg/zeek:latest",
        "--base-dir", "/app",
        "--scripts-dir", "/app/scripts"
      ]
    }
  }
}
```

**Windows path resolution:**

| Agent path | Resolved in container | Notes |
|---|---|---|
| `C:\Users\alice\test.pcap` | `/Users/alice/test.pcap` | Via path map |
| `C:/Users/alice/test.pcap` | `/Users/alice/test.pcap` | Via path map |
| `/Users/alice/test.pcap` | `/Users/alice/test.pcap` | Direct (no conversion) |

If pcap files are on other drives (e.g., D:), add additional mounts and mappings:

```json
"-v", "D:\\data:/data:ro",
"-e", "ZEEK_PATH_MAPS=C:\\Users=/Users,C:/Users=/Users,D:\\data=/data,D:/data=/data"
```

## How It Works

The core idea is to mount the host user directory at the **same or predictable path** inside the container:

| OS | User files | Docker mount | Needs PATH_MAPS |
|------|-------------|-------------|----------------|
| macOS | `/Users/` | `-v /Users:/Users:ro` | No |
| Linux | `/home/` | `-v /home:/home:ro` | No |
| Windows | `C:\Users\` | `-v C:\Users:/Users:ro` | Yes (format conversion) |

- Read-only mounts (`:ro`) ensure the container cannot modify host files.
- `/outputs` is mounted writable for storing analysis artifacts.
- macOS/Linux do not need `ZEEK_PATH_MAPS` — paths are identical inside and outside the container.
- Windows needs path maps for `C:\` → `/` prefix conversion.

## Client-Specific Notes

### Trae

Configure in Trae's MCP settings. See `examples/mcp/trae.json`.

### Claude Desktop / Claude Code

Add to Claude's MCP configuration file. See `examples/mcp/claude-desktop.json`.

### Cursor / VS Code / Kiro

Configure in `.cursor/mcp.json` or workspace MCP settings. See `examples/mcp/cursor.json`.

### Codex

See `examples/mcp/codex.json`.

## Usage

After configuration, agents can analyze pcap files at any location:

```text
Analyze /Users/alice/Downloads/suspicious.pcap with Zeek MCP
```

```text
Run threat detection on /Users/alice/research/attack_sample.pcapng
```

```text
Generate Zeek logs for /home/bob/captures/network_dump.pcap
```

Windows users:

```text
Analyze C:\Users\alice\Downloads\capture.pcap with Zeek MCP
```

No manual file copying is required.

## Output Artifacts

Execution tools create artifacts under the `/outputs` mount:

```text
/outputs/runs/<run_id>/
  logs/          # Zeek JSON logs (conn.log, dns.log, etc.)
  extracted/     # Extracted files from pcap
  reports/       # Generated reports
  manifest.json  # Run metadata and artifact index
```

Analysis artifacts are accessible via `manifest.json` and the `zeek://runs` resource.

## Build Options

```bash
# Docker image (default, Zeek-only)
./build.sh -d

# Docker image with tshark/capinfos for richer pcap metadata
./build.sh -d --with-pcap-tools

# Legacy builder (if BuildKit has registry issues)
./build.sh -d --legacy-builder
```

## Native Binary Mode

If Zeek is already installed on the host, run the `zeek-mcp` binary directly. Any filesystem path is accessible with zero configuration:

```bash
./build.sh -s
```

```json
{
  "mcpServers": {
    "zeek": {
      "command": "/path/to/zeek-mcp",
      "args": [
        "--base-dir", "/path/to/zeek_project",
        "--scripts-dir", "/path/to/zeek_project/scripts"
      ]
    }
  }
}
```

Enable custom script execution (sandboxed environments only):

```json
{
  "env": {
    "ZEEK_ENABLE_CUSTOM_SCRIPT": "true"
  }
}
```

## Legacy Configuration (Fixed Directory)

To restrict pcap access to a specific directory, use explicit path mapping:

```json
{
  "mcpServers": {
    "zeek": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/path/to/pcaps:/pcaps:ro",
        "-v", "/path/to/outputs:/outputs",
        "-e", "ZEEK_PATH_MAPS=/path/to/pcaps=/pcaps,/path/to/outputs=/outputs",
        "-e", "ZEEK_ENABLE_CUSTOM_SCRIPT=false",
        "ghcr.io/randolphcyg/zeek:latest",
        "--base-dir", "/app",
        "--scripts-dir", "/app/scripts"
      ]
    }
  }
}
```

In this mode, only files within mapped directories are accessible. Agents must use container paths like `/pcaps/sample.pcap`.
