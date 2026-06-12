# MCP Client Configuration

Docker is the default integration path. The key insight is mounting the host user directory at the **same path** inside the container, so agents can reference any pcap by its original absolute path without path mapping.

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

macOS 上所有用户文件都在 `/Users` 下，一个挂载覆盖所有 pcap 位置。

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

如果 pcap 文件分布在 `/home` 之外（如 `/opt`、`/var/log`、`/data`），添加对应的只读挂载：

```json
"-v", "/opt:/opt:ro",
"-v", "/data:/data:ro"
```

### Windows (Docker Desktop)

Windows 上 Docker Desktop 使用 WSL2 后端，宿主机磁盘自动映射到 `/mnt/` 路径下。需要配合 `ZEEK_PATH_MAPS` 做 Windows 路径到 Linux 路径的转换：

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

**Windows 路径说明：**

| Agent 传入的路径 | 容器内解析为 | 说明 |
|---|---|---|
| `C:\Users\alice\test.pcap` | `/Users/alice/test.pcap` | 通过 path map 转换 |
| `C:/Users/alice/test.pcap` | `/Users/alice/test.pcap` | 通过 path map 转换 |
| `/Users/alice/test.pcap` | `/Users/alice/test.pcap` | 直接可用 |

如果 pcap 在其他磁盘（如 D 盘），添加额外挂载和映射：

```json
"-v", "D:\\data:/data:ro",
"-e", "ZEEK_PATH_MAPS=C:\\Users=/Users,C:/Users=/Users,D:\\data=/data,D:/data=/data"
```

## 原理

核心思路是将宿主机用户目录以**同路径或可预测路径**方式挂载到容器内：

| 系统 | 用户文件位置 | Docker 挂载 | 需要 PATH_MAPS |
|------|-------------|-------------|----------------|
| macOS | `/Users/` | `-v /Users:/Users:ro` | 否 |
| Linux | `/home/` | `-v /home:/home:ro` | 否 |
| Windows | `C:\Users\` | `-v C:\Users:/Users:ro` | 是（路径格式转换） |

- 只读挂载（`:ro`）确保容器无法修改宿主机文件
- `/outputs` 挂载为可写，用于存储分析产物
- macOS/Linux 不需要 `ZEEK_PATH_MAPS`，路径在容器内外完全一致
- Windows 需要 path map 做 `C:\` → `/` 的前缀转换

## Client-Specific Notes

### Trae

在 Trae 的 MCP 设置中配置。参考 `examples/mcp/trae.json`。

### Claude Desktop / Claude Code

在 Claude 的 MCP 配置文件中添加。参考 `examples/mcp/claude-desktop.json`。

### Cursor / VS Code / Kiro

在 `.cursor/mcp.json` 或工作区 MCP 设置中配置。参考 `examples/mcp/cursor.json`。

### Codex

参考 `examples/mcp/codex.json`。

## Usage

配置完成后，agent 可以直接分析任意位置的 pcap 文件：

```text
Analyze /Users/alice/Downloads/suspicious.pcap with Zeek MCP
```

```text
Run threat detection on /Users/alice/research/attack_sample.pcapng
```

```text
Generate Zeek logs for /home/bob/captures/network_dump.pcap
```

Windows 用户：

```text
Analyze C:\Users\alice\Downloads\capture.pcap with Zeek MCP
```

无需手动拷贝文件到指定目录。

## Output Artifacts

执行工具在 `/outputs` 挂载下创建产物：

```text
/outputs/runs/<run_id>/
  logs/          # Zeek JSON logs (conn.log, dns.log, etc.)
  extracted/     # Extracted files from pcap
  reports/       # Generated reports
  manifest.json  # Run metadata and artifact index
```

使用 `get_run_manifest` 和 `list_runs` 访问历史分析结果。

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

如果宿主机已安装 Zeek，可以直接运行 `zeek` 二进制。此模式下任意文件系统路径均可访问，零配置：

```bash
./build.sh -s
```

```json
{
  "mcpServers": {
    "zeek": {
      "command": "/path/to/zeek",
      "args": [
        "--base-dir", "/path/to/zeek_project",
        "--scripts-dir", "/path/to/zeek_project/scripts"
      ]
    }
  }
}
```

启用自定义脚本执行（仅在可信环境中使用）：

```json
{
  "env": {
    "ZEEK_ENABLE_CUSTOM_SCRIPT": "true"
  }
}
```

## Legacy Configuration (Fixed Directory)

如果需要限制 pcap 访问范围到特定目录，使用显式路径映射：

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

此模式下只有映射目录内的文件可访问，agent 必须使用 `/pcaps/sample.pcap` 这样的容器内路径。
