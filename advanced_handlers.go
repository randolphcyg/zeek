package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

func (h *Handler) handleRunCustomScript(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if !strings.EqualFold(os.Getenv("ZEEK_MCP_ENABLE_CUSTOM_SCRIPT"), "true") {
		return errorResult("zeek_run_custom_script is disabled; set ZEEK_MCP_ENABLE_CUSTOM_SCRIPT=true to enable it"), nil
	}

	args := getArgs(request)
	pcapPath, _ := args["pcap_path"].(string)
	scriptContent, _ := args["script_content"].(string)
	if pcapPath == "" {
		return errorResult("pcap_path is required"), nil
	}
	pcapResolution, err := h.paths.ResolveExisting("pcap_path", pcapPath)
	if err != nil {
		return pathErrorResult(err), nil
	}
	if scriptContent == "" {
		return errorResult("script_content is required"), nil
	}

	timeout := time.Duration(0)
	if raw, ok := args["timeout_seconds"].(float64); ok && raw > 0 {
		timeout = time.Duration(raw) * time.Second
	}

	artifactRun, err := h.prepareArtifactRun(args)
	if err != nil {
		return outputErrorResult(err), nil
	}

	result := h.executor.RunCustomScript(ctx, pcapResolution.Resolved, scriptContent, timeout, artifactRun)
	result.PcapPath = pcapPath
	result.RequestedPath = pcapResolution.Requested
	result.ResolvedPath = pcapResolution.Resolved
	h.finalizeArtifactRun(ctx, result, artifactRun)
	return textResult(FormatResultJSON(result)), nil
}

func (h *Handler) handleGenerateLogs(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)
	pcapPath, _ := args["pcap_path"].(string)
	if pcapPath == "" {
		return errorResult("pcap_path is required"), nil
	}
	pcapResolution, err := h.paths.ResolveExisting("pcap_path", pcapPath)
	if err != nil {
		return pathErrorResult(err), nil
	}

	logs := stringSliceArg(args["logs"])
	maxRecords := 20
	if raw, ok := args["max_records"].(float64); ok && raw > 0 {
		maxRecords = int(raw)
	}

	artifactRun, err := h.prepareArtifactRun(args)
	if err != nil {
		return outputErrorResult(err), nil
	}

	result := h.executor.GenerateLogs(ctx, pcapResolution.Resolved, logs, maxRecords, artifactRun)
	result.PcapPath = pcapPath
	result.RequestedPath = pcapResolution.Requested
	result.ResolvedPath = pcapResolution.Resolved
	h.finalizeArtifactRun(ctx, result, artifactRun)
	return textResult(FormatResultJSON(result)), nil
}

func (h *Handler) handleRunIntelMatch(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)
	pcapPath, _ := args["pcap_path"].(string)
	if pcapPath == "" {
		return errorResult("pcap_path is required"), nil
	}
	pcapResolution, err := h.paths.ResolveExisting("pcap_path", pcapPath)
	if err != nil {
		return pathErrorResult(err), nil
	}

	intelFile, _ := args["intel_file"].(string)
	var cleanupIntel func()
	if intelFile != "" {
		intelResolution, err := h.paths.ResolveExisting("intel_file", intelFile)
		if err != nil {
			return pathErrorResult(err), nil
		}
		intelFile = intelResolution.Resolved
	} else {
		content := buildIntelTSV(args["indicators"])
		if content == "" {
			return errorResult("indicators or intel_file is required"), nil
		}
		var err error
		intelFile, cleanupIntel, err = writeTempFile("zeek_mcp_intel_*.tsv", content)
		if err != nil {
			return errorResult(fmt.Sprintf("failed to create Intel file: %s", err.Error())), nil
		}
		defer cleanupIntel()
	}

	scriptContent := fmt.Sprintf(`@load base/frameworks/intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

redef Intel::read_files += { "%s" };
`, escapeZeekString(intelFile))

	scriptPath, cleanupScript, err := writeTempFile("zeek_mcp_intel_*.zeek", scriptContent)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to create Intel script: %s", err.Error())), nil
	}
	defer cleanupScript()

	artifactRun, err := h.prepareArtifactRun(args)
	if err != nil {
		return outputErrorResult(err), nil
	}

	result := h.executor.RunScriptsWithLogSummary(ctx, "zeek_run_intel_match", pcapResolution.Resolved, []string{scriptPath}, []string{"intel", "notice", "conn", "dns", "http", "files"}, 50, artifactRun)
	result.PcapPath = pcapPath
	result.RequestedPath = pcapResolution.Requested
	result.ResolvedPath = pcapResolution.Resolved
	h.finalizeArtifactRun(ctx, result, artifactRun)
	return textResult(FormatResultJSON(result)), nil
}

func (h *Handler) handleRunSignature(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)
	pcapPath, _ := args["pcap_path"].(string)
	if pcapPath == "" {
		return errorResult("pcap_path is required"), nil
	}
	pcapResolution, err := h.paths.ResolveExisting("pcap_path", pcapPath)
	if err != nil {
		return pathErrorResult(err), nil
	}

	signaturePath, _ := args["signature_path"].(string)
	signatureContent, _ := args["signature_content"].(string)
	var cleanup func()
	if signaturePath == "" && signatureContent != "" {
		var err error
		signaturePath, cleanup, err = writeTempFile("zeek_mcp_signature_*.sig", signatureContent)
		if err != nil {
			return errorResult(fmt.Sprintf("failed to create signature file: %s", err.Error())), nil
		}
		defer cleanup()
	}
	if signaturePath == "" {
		return errorResult("signature_content or signature_path is required"), nil
	}
	if !filepath.IsAbs(signaturePath) {
		abs, err := filepath.Abs(signaturePath)
		if err == nil {
			signaturePath = abs
		}
	}
	signatureResolution, err := h.paths.ResolveExisting("signature_path", signaturePath)
	if err != nil {
		return pathErrorResult(err), nil
	}

	artifactRun, err := h.prepareArtifactRun(args)
	if err != nil {
		return outputErrorResult(err), nil
	}

	result := h.executor.RunSignature(ctx, pcapResolution.Resolved, signatureResolution.Resolved, artifactRun)
	result.PcapPath = pcapPath
	result.RequestedPath = pcapResolution.Requested
	result.ResolvedPath = pcapResolution.Resolved
	h.finalizeArtifactRun(ctx, result, artifactRun)
	return textResult(FormatResultJSON(result)), nil
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: text},
		},
	}
}

func stringSliceArg(raw interface{}) []string {
	values, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	var result []string
	for _, value := range values {
		if text, ok := value.(string); ok && text != "" {
			result = append(result, text)
		}
	}
	return result
}

func buildIntelTSV(raw interface{}) string {
	indicators, ok := raw.(map[string]interface{})
	if !ok {
		return ""
	}

	var lines []string
	lines = append(lines, "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc")
	addIntelLines := func(key, intelType string) {
		for _, value := range stringSliceArg(indicators[key]) {
			lines = append(lines, fmt.Sprintf("%s\t%s\tzeek_mcp\tuser supplied indicator", value, intelType))
		}
	}
	addIntelLines("ips", "Intel::ADDR")
	addIntelLines("domains", "Intel::DOMAIN")
	addIntelLines("urls", "Intel::URL")
	addIntelLines("hashes", "Intel::FILE_HASH")

	if len(lines) == 1 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func escapeZeekString(value string) string {
	encoded, _ := json.Marshal(value)
	return strings.Trim(string(encoded), `"`)
}
