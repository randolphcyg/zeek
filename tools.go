package main

import (
	"github.com/mark3labs/mcp-go/mcp"
)

func buildTools() []mcp.Tool {
	tools := []mcp.Tool{
		{
			Name:        "triage_pcap",
			Description: "Composite workflow tool: inspect capture metadata, run all enabled detection scripts, and return a unified triage summary with manifest references. Set extract_files=true to also run file extraction scripts. Recommended single-call tool for routine pcap analysis.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path to a pcap file. Use the zeek://pcaps resource to discover available files.",
					},
					"scripts": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Optional detection script names or ScriptIDs. Omit to run all enabled detection scripts.",
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
			Name:        "summarize_logs",
			Description: "Run Zeek on a pcap and return compact JSON summaries for selected Zeek logs.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path to a pcap file. Use the zeek://pcaps resource to discover available files.",
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
			Name:        "hunt_intel",
			Description: "Run Zeek Intel framework matching for supplied indicators or an Intel TSV file and return normalized hits.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path to a pcap file. Use the zeek://pcaps resource to discover available files.",
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
			Name:        "hunt_signature",
			Description: "Validate and run Zeek signature content or a signature file against a pcap. Signature syntax is validated by Zeek's built-in signature framework at runtime.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path to a pcap file. Use the zeek://pcaps resource to discover available files.",
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
			Name:        "extract_files",
			Description: "Extract files detected by Zeek's File Analysis framework from a pcap using bundled extraction scripts.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path to a pcap file. Use the zeek://pcaps resource to discover available files.",
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
						"description": "Path to a pcap file. Use the zeek://pcaps resource to discover available files.",
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