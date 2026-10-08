package main

import (
	"github.com/mark3labs/mcp-go/mcp"
)

func buildTools() []mcp.Tool {
	tools := []mcp.Tool{
		{
			Name:        "analyze_pcap",
			Description: "Run one reusable Zeek analysis pass. baseline produces protocol logs and Community ID without custom detections; standard runs protocol-relevant detections; full runs every enabled detection.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"pcap_path": map[string]interface{}{
						"type":        "string",
						"description": "Path to a pcap file. Use the zeek://pcaps resource to discover available files.",
					},
					"profile": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"baseline", "standard", "full"},
						"default":     "baseline",
						"description": "Analysis profile. baseline is the deterministic preflight pass.",
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
			Name:        "query_logs",
			Description: "Query persisted JSON logs from an existing analyze_pcap run. This never reparses the PCAP.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"run_id": map[string]interface{}{
						"type":        "string",
						"description": "Run identifier returned by analyze_pcap.",
					},
					"log": map[string]interface{}{
						"type":        "string",
						"description": "Persisted Zeek log name, for example conn, dns, http, ssl, notice, weird.",
					},
					"select": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Optional field projection.",
					},
					"predicates": map[string]interface{}{
						"type":        "object",
						"description": "Optional exact-match field predicates.",
					},
					"aggregate": map[string]interface{}{
						"type":    "string",
						"enum":    []string{"none", "count"},
						"default": "none",
					},
					"limit": map[string]interface{}{
						"type":    "integer",
						"minimum": 1,
						"maximum": 500,
						"default": 100,
					},
					"cursor": map[string]interface{}{
						"type":        "string",
						"description": "Opaque cursor returned by the previous query.",
					},
					"output_dir": map[string]interface{}{
						"type":        "string",
						"description": "The output root used by analyze_pcap.",
					},
				},
				Required: []string{"run_id", "log"},
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
