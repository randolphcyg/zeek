# Security Policy

## Supported Versions

Security fixes are handled on the latest released version of Zeek MCP.

## Reporting A Vulnerability

Please report security issues privately to the project maintainers before public disclosure. Include:

- Affected Zeek MCP version or image tag.
- Reproduction steps.
- Whether custom script execution was enabled.
- Relevant configuration, with secrets and sensitive pcap contents removed.

## Runtime Security Notes

- Docker is the recommended runtime because it pins Zeek 8.0.8 and limits file access to explicitly mounted directories.
- Do not mount an entire home directory unless you intentionally want agents to access it.
- Keep `ZEEK_ENABLE_CUSTOM_SCRIPT=false` unless running in a sandbox.
- Analysis artifacts can contain sensitive traffic metadata and extracted files. Store `/outputs` in an appropriate location and use cleanup controls when needed.
