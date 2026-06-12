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
		"health_check",
		"inspect_capture",
		"detect_threats",
		"get_run_manifest",
		"list_runs",
		"cleanup_runs",
		"list_pcaps",
		"triage_pcap",
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
	if body["next_tool"] != "list_pcaps" {
		t.Fatalf("next_tool = %v, want list_pcaps", body["next_tool"])
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

func TestStripZeekComments(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no comments",
			input:    "event zeek_init() { print \"ok\"; }",
			expected: "event zeek_init() { print \"ok\"; }",
		},
		{
			name:     "full line comment",
			input:    "# ScriptID: test\nevent zeek_init() { }",
			expected: "event zeek_init() { }",
		},
		{
			name:     "trailing comment",
			input:    "print \"hello\"; # this is a comment",
			expected: "print \"hello\";",
		},
		{
			name:     "multiple lines with comments",
			input:    "# header\nredef X = 1;\n# another comment\nredef Y = 2;",
			expected: "redef X = 1;\nredef Y = 2;",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleaned := stripZeekComments(tt.input)
			if cleaned != tt.expected {
				t.Errorf("got:\n%q\nwant:\n%q", cleaned, tt.expected)
			}
		})
	}
}

func TestStripZeekComments_bypassingComment(t *testing.T) {
	// Comment with blocked pattern should be removed and not detected
	input := "# system() is bad\nevent zeek_init() { }"
	cleaned := stripZeekComments(input)
	expected := "event zeek_init() { }"
	if cleaned != expected {
		t.Errorf("got %q, want %q", cleaned, expected)
	}
	// Now blocked pattern should not be found in cleaned output
	if strings.Contains(strings.ToLower(cleaned), "system(") {
		t.Error("blocked pattern should not be present after stripping comments")
	}
}

func TestPathResolver(t *testing.T) {
	maps := []PathMap{
		{HostPrefix: "/Users", ContainerPrefix: "/Users"},
		{HostPrefix: "C:\\Users", ContainerPrefix: "/Users"},
	}
	resolver := NewPathResolver(maps)
	if len(resolver.Mappings()) != 2 {
		t.Errorf("got %d mappings, want 2", len(resolver.Mappings()))
	}
}

func TestPathHasPrefix(t *testing.T) {
	tests := []struct {
		path  string
		prefix string
		want  bool
	}{
		{"/Users/alice/file.pcap", "/Users", true},
		{"/Usersalice/file.pcap", "/Users", false},
		{"/pcaps/file.pcap", "/pcaps", true},
		{"/file.pcap", "/", true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := pathHasPrefix(tt.path, tt.prefix)
			if got != tt.want {
				t.Errorf("pathHasPrefix(%q, %q) = %v, want %v", tt.path, tt.prefix, got, tt.want)
			}
		})
	}
}

func TestEnvBool(t *testing.T) {
	tests := []struct {
		val  string
		def  bool
		want bool
	}{
		{"true", false, true},
		{"TRUE", false, true},
		{"false", true, false},
		{"", true, true},
		{"1", false, true},
		{"yes", false, true},
		{"", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.val, func(t *testing.T) {
			key := "ZEEK_TEST_ENV_BOOL"
			if tt.val != "" {
				os.Setenv(key, tt.val)
			} else {
				os.Unsetenv(key)
			}
			defer os.Unsetenv(key)
			got := envBool(key, tt.def)
			if got != tt.want {
				t.Errorf("envBool(%q, %q, %v) = %v, want %v", key, tt.val, tt.def, got, tt.want)
			}
		})
	}
}
