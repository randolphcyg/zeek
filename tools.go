package main

import (
	"github.com/mark3labs/mcp-go/mcp"
)

func buildTools() []mcp.Tool {
	tools := []mcp.Tool{
		{
			Name:        "list_scripts",
			Description: "List bundled Zeek scripts and metadata. Supports detection, extraction, and utility script discovery.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"type": map[string]interface{}{
						"type":        "string",
						"description": "Filter by script type: detection, extraction, or utility.",
					},
					"category": map[string]interface{}{
						"type":        "string",
						"description": "Filter by category, such as web_attack, brute_force, dos, anomaly, intel, or file_extraction.",
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Filter by script name or ScriptID using case-insensitive partial matching.",
					},
					"enabled_only": map[string]interface{}{
						"type":        "boolean",
						"description": "Return only enabled and valid scripts. Defaults to false.",
					},
				},
			},
		},
		{
			Name:        "inspect_capture",
			Description: "Inspect a pcap file and return capture metadata, observed protocols, and suggested analysis scripts. When tshark/capinfos is available, protocol metadata is richer; without them, falls back to Zeek-driven inspection.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path obtained from list_scripts or a valid intake directory path.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
		{
			Name:        "detect_threats",
			Description: "Run bundled Zeek detection scripts against a pcap and return normalized alerts, evidence, IOCs, and execution statistics. If pcap_path fails, call list_scripts and retry with a returned path. Set extract_files=true to also run file extraction scripts.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path obtained from list_scripts or a valid intake directory path.",
					},
					"scripts": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "string",
						},
						"description": "Detection script names or ScriptIDs. Empty or omitted means run all enabled detection scripts.",
					},
					"extract_files": map[string]interface{}{
						"type":        "boolean",
						"description": "Also run extraction scripts and return extracted file metadata. Defaults to false.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Writable output root. Defaults to /outputs when available.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
		{
			Name:        "extract_files",
			Description: "Extract files detected by Zeek's File Analysis framework from a pcap using bundled extraction scripts.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path obtained from list_scripts or a valid intake directory path.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Writable output root. Defaults to /outputs when available.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
		{
			Name:        "get_script",
			Description: "Return metadata and optional source code for one bundled Zeek script.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"script_name": map[string]interface{}{
						"type":        "string",
						"description": "Script name or ScriptID.",
					},
					"include_source": map[string]interface{}{
						"type":        "boolean",
						"description": "Include the full Zeek script source. Defaults to false.",
					},
				},
				Required: []string{"script_name"},
			},
		},
		{
			Name:        "health_check",
			Description: "Return Zeek MCP health, server version, Zeek availability, and loaded script counts.",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]interface{}{},
			},
		},
		{
			Name:        "validate_script",
			Description: "Validate Zeek script syntax with zeek --parse-only. Accepts a registered script, a script path, or direct script content.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"script_name": map[string]interface{}{
						"type":        "string",
						"description": "Registered script name or ScriptID.",
					},
					"script_path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to an unregistered Zeek script.",
					},
					"script_content": map[string]interface{}{
						"type":        "string",
						"description": "Zeek script content to validate.",
					},
				},
			},
		},
		{
			Name:        "generate_logs",
			Description: "Run Zeek on a pcap and return compact JSON summaries for selected Zeek logs.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path obtained from list_scripts or a valid intake directory path.",
					},
					"logs": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "string",
						},
						"description": "Log names to summarize, such as conn, dns, http, ssl, x509, files, ssh, smtp, smb, rdp, tunnel, weird, notice, or analyzer. When omitted, summarizes all available log types.",
					},
					"max_records": map[string]interface{}{
						"type":        "number",
						"description": "Maximum records to include per log summary. Defaults to 20.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Writable output root. Defaults to /outputs when available.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
		{
			Name:        "match_intel",
			Description: "Run Zeek Intel framework matching for supplied indicators or an Intel TSV file and return normalized hits.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path obtained from list_scripts or a valid intake directory path.",
					},
					"indicators": map[string]interface{}{
						"type":        "object",
						"description": "Indicator map with optional keys: ips (string array of IP addresses), domains (string array of domain names), urls (string array of URLs), hashes (string array of file hashes). At least one indicator or intel_file is required.",
					},
					"intel_file": map[string]interface{}{
						"type":        "string",
						"description": "Optional path to a Zeek Intel TSV file.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Writable output root. Defaults to /outputs when available.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
		{
			Name:        "run_signature",
			Description: "Validate and run Zeek signature content or a signature file against a pcap. Signature syntax is validated by Zeek's built-in signature framework at runtime.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path obtained from list_scripts or a valid intake directory path.",
					},
					"signature_content": map[string]interface{}{
						"type":        "string",
						"description": "Zeek signature content to execute.",
					},
					"signature_path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to a Zeek signature file.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Writable output root. Defaults to /outputs when available.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
		{
			Name:        "get_run_manifest",
			Description: "Read an analysis run artifact manifest by run_id or manifest_path so downstream agents can continue analysis.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"run_id": map[string]interface{}{
						"type":        "string",
						"description": "Analysis run identifier returned by a Zeek MCP execution tool.",
					},
					"manifest_path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to manifest.json. Host paths can be translated through configured path maps.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Writable output root. Defaults to /outputs when available.",
					},
				},
			},
		},
		{
			Name:        "list_runs",
			Description: "List recent analysis runs from the configured output directory.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"limit": map[string]interface{}{
						"type":        "number",
						"description": "Maximum runs to return. Defaults to 20.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Writable output root. Defaults to /outputs when available.",
					},
				},
			},
		},
		{
			Name:        "cleanup_runs",
			Description: "WARNING: Destructive operation. Preview or delete old analysis run artifacts from the configured output directory. Always preview with dry_run=true first. Deletion requires dry_run=false and confirm=true.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"older_than_days": map[string]interface{}{
						"type":        "number",
						"description": "Select runs created at least this many days ago. Defaults to 0, which disables age-based selection.",
					},
					"max_total_bytes": map[string]interface{}{
						"type":        "number",
						"description": "Delete oldest runs until total artifact bytes are at or below this limit. Defaults to 0, which disables size-based selection.",
					},
					"dry_run": map[string]interface{}{
						"type":        "boolean",
						"description": "Preview cleanup without deleting. Defaults to true.",
					},
					"confirm": map[string]interface{}{
						"type":        "boolean",
						"description": "Required for deletion when dry_run is false.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Writable output root. Defaults to /outputs when available.",
					},
				},
			},
		},
		{
			Name:        "list_pcaps",
			Description: "List PCAP files from configured intake directories. Returned path values are directly usable as pcap_path in Zeek tools.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"directory": map[string]interface{}{
						"type":        "string",
						"description": "Optional mounted intake directory to list. Defaults to configured non-output path map directories.",
					},
				},
			},
		},
		{
			Name:        "triage_pcap",
			Description: "Composite workflow tool: inspect capture metadata, run all enabled detection scripts, and return a unified triage summary with manifest references. Recommended single-call tool for routine pcap analysis.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path returned by list_pcaps or a path under a configured path map.",
					},
					"scripts": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Optional detection script names or ScriptIDs. Omit to run all enabled detection scripts.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Writable output root. Defaults to /outputs when available.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
	}

	if envBool("ZEEK_ENABLE_CUSTOM_SCRIPT", false) {
		tools = append(tools, mcp.Tool{
			Name:        "run_custom_script",
			Description: "Validate and run an Agent-generated Zeek script against a pcap. WARNING: Only enabled when ZEEK_ENABLE_CUSTOM_SCRIPT=true. Use only in sandboxed environments.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path obtained from list_scripts or a valid intake directory path.",
					},
					"script_content": map[string]interface{}{
						"type":        "string",
						"description": "Zeek script content to validate and execute.",
					},
					"timeout_seconds": map[string]interface{}{
						"type":        "number",
						"description": "Optional execution timeout in seconds. The server default is used when omitted.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Writable output root. Defaults to /outputs when available.",
					},
				},
				Required: []string{"pcap_path", "script_content"},
			},
		})
	}

	return tools
}