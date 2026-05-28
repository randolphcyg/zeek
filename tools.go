package main

import "github.com/mark3labs/mcp-go/mcp"

func buildTools() []mcp.Tool {
	return []mcp.Tool{
		{
			Name:        "zeek_list_detection_scripts",
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
			Name:        "zeek_inspect_capture",
			Description: "Inspect a pcap file and return capture metadata, observed protocols, and suggested Zeek detection scripts.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the pcap file.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
		{
			Name:        "zeek_detect_threats",
			Description: "Run bundled Zeek detection scripts against a pcap and return normalized alerts, evidence, IOCs, and execution statistics. If pcap_path fails, call zeek_list_pcaps and retry with a returned path.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the pcap file.",
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
						"description": "Optional directory for extracted files when extract_files is true. Host paths can be translated through configured path maps.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
		{
			Name:        "zeek_extract_files",
			Description: "Extract suspicious files from a pcap using bundled Zeek file-analysis extraction scripts.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the pcap file.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Optional directory for extracted files. Host paths can be translated through configured path maps.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
		{
			Name:        "zeek_get_detection_script",
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
			Name:        "zeek_health_check",
			Description: "Return Zeek MCP health, server version, Zeek availability, and loaded script counts.",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]interface{}{},
			},
		},
		{
			Name:        "zeek_validate_script",
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
			Name:        "zeek_get_version",
			Description: "Return the installed Zeek version and Zeek MCP build metadata.",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]interface{}{},
			},
		},
		{
			Name:        "zeek_reload_scripts",
			Description: "Rescan the scripts directory and reload bundled Zeek script metadata without restarting the MCP server.",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]interface{}{},
			},
		},
		{
			Name:        "zeek_run_custom_script",
			Description: "Validate and run an Agent-generated Zeek script against a pcap. Disabled unless ZEEK_MCP_ENABLE_CUSTOM_SCRIPT=true.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the pcap file.",
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
						"description": "Optional output root. The server creates runs/<run_id>/ under this directory.",
					},
				},
				Required: []string{"pcap_path", "script_content"},
			},
		},
		{
			Name:        "zeek_generate_logs",
			Description: "Run Zeek on a pcap and return compact JSON summaries for selected Zeek logs.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the pcap file.",
					},
					"logs": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "string",
						},
						"description": "Log names to summarize, such as conn, dns, http, ssl, x509, files, ssh, smtp, smb, rdp, tunnel, weird, notice, or analyzer.",
					},
					"max_records": map[string]interface{}{
						"type":        "number",
						"description": "Maximum records to include per log summary. Defaults to 20.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Optional output root. The server creates runs/<run_id>/ under this directory.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
		{
			Name:        "zeek_match_intel",
			Description: "Run Zeek Intel framework matching for supplied indicators or an Intel TSV file and return normalized hits.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the pcap file.",
					},
					"indicators": map[string]interface{}{
						"type":        "object",
						"description": "Indicator lists keyed by ips, domains, urls, or hashes.",
					},
					"intel_file": map[string]interface{}{
						"type":        "string",
						"description": "Optional path to a Zeek Intel TSV file.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Optional output root. The server creates runs/<run_id>/ under this directory.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
		{
			Name:        "zeek_run_signature",
			Description: "Validate and run Zeek signature content or a signature file against a pcap.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the pcap file.",
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
						"description": "Optional output root. The server creates runs/<run_id>/ under this directory.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
		{
			Name:        "zeek_get_run_manifest",
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
						"description": "Optional output root used to resolve run_id when not using the default /outputs mount.",
					},
				},
			},
		},
		{
			Name:        "zeek_list_runs",
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
						"description": "Optional output root to list. Defaults to /outputs when mounted.",
					},
				},
			},
		},
		{
			Name:        "zeek_cleanup_runs",
			Description: "Preview or delete old analysis run artifacts from the configured output directory. Deletion requires dry_run=false and confirm=true.",
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
						"description": "Optional output root to clean. Defaults to /outputs when mounted.",
					},
				},
			},
		},
		{
			Name:        "zeek_list_pcaps",
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
			Name:        "zeek_triage_pcap",
			Description: "High-success workflow tool: inspect one pcap, run bundled detections, and return a compact triage summary plus manifest references.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path returned by zeek_list_pcaps or a path under a configured path map.",
					},
					"scripts": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Optional detection script names or ScriptIDs. Omit to run all enabled detection scripts.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "Optional output root. Defaults to /outputs when writable.",
					},
				},
				Required: []string{"pcap_path"},
			},
		},
	}
}
