package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestToolNamesBreakingChange(t *testing.T) {
	tools := buildTools()
	seen := map[string]bool{}
	for _, tool := range tools {
		seen[tool.Name] = true
	}
	for _, name := range []string{
		"zeek_health_check",
		"zeek_inspect_capture",
		"zeek_detect_threats",
		"zeek_get_run_manifest",
		"zeek_list_runs",
		"zeek_cleanup_runs",
		"zeek_list_pcaps",
		"zeek_triage_pcap",
	} {
		if !seen[name] {
			t.Fatalf("expected tool %s to be registered", name)
		}
	}
	for _, old := range []string{
		"zeek_health",
		"zeek_inspect_pcap",
		"zeek_run_detection",
		"zeek_get_artifact_manifest",
		"zeek_list_analysis_runs",
		"zeek_cleanup_analysis_runs",
		"zeek_run_intel_match",
	} {
		if seen[old] {
			t.Fatalf("old tool %s should not be registered", old)
		}
	}
}

func TestErrorEnvelope(t *testing.T) {
	result := errorResult("pcap_path is required")
	if !result.IsError {
		t.Fatal("errorResult should set IsError")
	}
	body := parseToolResult(t, result)
	if body["ok"] != false {
		t.Fatalf("ok = %v, want false", body["ok"])
	}
	if body["error_code"] != "MISSING_REQUIRED_PARAM" {
		t.Fatalf("error_code = %v, want MISSING_REQUIRED_PARAM", body["error_code"])
	}
	if _, ok := body["suggestion"].(string); !ok {
		t.Fatal("suggestion should be present")
	}
}

func TestListPcapsReturnsToolReadyPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sample.pcap"), []byte("pcap"), 0644); err != nil {
		t.Fatalf("write pcap: %v", err)
	}
	handler := &Handler{
		paths: NewPathResolver([]PathMap{{HostPrefix: dir, ContainerPrefix: dir}}),
	}
	result, err := handler.handleListPcaps(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleListPcaps: %v", err)
	}
	body := parseToolResult(t, result)
	pcaps := body["pcaps"].([]interface{})
	if len(pcaps) != 1 {
		t.Fatalf("pcaps len = %d, want 1", len(pcaps))
	}
	pcap := pcaps[0].(map[string]interface{})
	if pcap["path"] != filepath.Join(dir, "sample.pcap") {
		t.Fatalf("path = %v, want tool-ready path", pcap["path"])
	}
}

func TestTriagePcapPathErrorIsActionable(t *testing.T) {
	dir := t.TempDir()
	handler := &Handler{
		paths: NewPathResolver([]PathMap{{HostPrefix: dir, ContainerPrefix: dir}}),
	}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: map[string]interface{}{"pcap_path": filepath.Join(dir, "missing.pcap")}}}
	result, err := handler.handleTriagePcap(context.Background(), req)
	if err != nil {
		t.Fatalf("handleTriagePcap: %v", err)
	}
	body := parseToolResult(t, result)
	if body["error_code"] != "INVALID_PATH" {
		t.Fatalf("error_code = %v, want INVALID_PATH", body["error_code"])
	}
	if body["next_tool"] != "zeek_list_pcaps" {
		t.Fatalf("next_tool = %v, want zeek_list_pcaps", body["next_tool"])
	}
}

func TestDispatchAddsTraceAndCallLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "calls.jsonl")
	original := os.Getenv("MCP_CALL_LOG_PATH")
	os.Setenv("MCP_CALL_LOG_PATH", logPath)
	defer os.Setenv("MCP_CALL_LOG_PATH", original)

	handler := &Handler{}
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "missing_tool"}}
	result, err := handler.dispatchTool(context.Background(), req)
	if err != nil {
		t.Fatalf("dispatchTool: %v", err)
	}
	body := parseToolResult(t, result)
	if body["trace_id"] == "" {
		t.Fatal("expected trace_id in error payload")
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read call log: %v", err)
	}
	if !strings.Contains(string(data), `"tool_name":"missing_tool"`) {
		t.Fatalf("call log missing tool name: %s", data)
	}
}

func parseToolResult(t *testing.T, result *mcp.CallToolResult) map[string]interface{} {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("missing content")
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want TextContent", result.Content[0])
	}
	var body map[string]interface{}
	if err := json.Unmarshal([]byte(text.Text), &body); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return body
}
