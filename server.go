package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var (
	Version       = "1.0.0"
	BuildTime     = "unknown"
	GitCommit     = "unknown"
	TargetZeekLTS = "8.0.8"
)

type MCPServer struct {
	server   *server.MCPServer
	registry *ScriptRegistry
	executor *Executor
	cache    *ResultCache
	baseDir  string
	paths    *PathResolver
}

func NewMCPServer(baseDir, scriptsDir string, pathMaps []PathMap) *MCPServer {
	registry := NewScriptRegistry(scriptsDir)
	if err := registry.Scan(); err != nil {
		log.Printf("WARN: failed to scan scripts: %v", err)
	}

	executor := NewExecutor(ExecutorConfig{
		Timeout: 120 * time.Second,
	})

	handler := &Handler{
		registry: registry,
		executor: executor,
		cache:    NewResultCache(),
		baseDir:  baseDir,
		paths:    NewPathResolver(pathMaps),
	}
	handler.cleanupArtifactsOnStart()

	s := server.NewMCPServer(
		"zeek_mcp",
		Version,
		server.WithToolCapabilities(true),
		server.WithLogging(),
	)

	tools := buildTools()
	for _, tool := range tools {
		s.AddTool(tool, handler.dispatchTool)
	}
	handler.registerResources(s)

	return &MCPServer{
		server:   s,
		registry: registry,
		executor: executor,
		cache:    handler.cache,
		baseDir:  baseDir,
		paths:    handler.paths,
	}
}

func (h *Handler) dispatchTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	start := time.Now()
	traceID := newTraceID("zeek")
	result, err := h.dispatchToolInner(ctx, request)
	status := "success"
	errorCode := ""
	if err != nil {
		status = "exception"
		errorCode = "INTERNAL_EXCEPTION"
		result = envelopeResult(request.Params.Name, traceID, errorCode, err.Error(), false)
		err = nil
	}
	if result != nil {
		if result.Meta == nil {
			result.Meta = &mcp.Meta{AdditionalFields: map[string]any{}}
		}
		if result.Meta.AdditionalFields == nil {
			result.Meta.AdditionalFields = map[string]any{}
		}
		result.Meta.AdditionalFields["trace_id"] = traceID
		if result.IsError {
			attachTraceToErrorResult(result, request.Params.Name, traceID)
			status = "semantic_failure"
			errorCode = errorCodeFromResult(result)
		}
	}
	writeToolCallLog(request.Params.Name, traceID, getArgs(request), status, errorCode, result, time.Since(start))
	return result, nil
}

func (h *Handler) dispatchToolInner(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	switch request.Params.Name {
	case "zeek_list_detection_scripts":
		return h.handleListScripts(ctx, request)
	case "zeek_inspect_capture":
		return h.handleGetPcapInfo(ctx, request)
	case "zeek_detect_threats":
		return h.handleRunDetection(ctx, request)
	case "zeek_extract_files":
		return h.handleExtractFiles(ctx, request)
	case "zeek_get_detection_script":
		return h.handleGetScriptDetail(ctx, request)
	case "zeek_health_check":
		return h.handleHealthCheck(ctx, request)
	case "zeek_validate_script":
		return h.handleSyntaxCheck(ctx, request)
	case "zeek_get_version":
		return h.handleZeekVersion(ctx, request)
	case "zeek_reload_scripts":
		return h.handleReloadScripts(ctx, request)
	case "zeek_run_custom_script":
		return h.handleRunCustomScript(ctx, request)
	case "zeek_generate_logs":
		return h.handleGenerateLogs(ctx, request)
	case "zeek_match_intel":
		return h.handleRunIntelMatch(ctx, request)
	case "zeek_run_signature":
		return h.handleRunSignature(ctx, request)
	case "zeek_get_run_manifest":
		return h.handleGetArtifactManifest(ctx, request)
	case "zeek_list_runs":
		return h.handleListAnalysisRuns(ctx, request)
	case "zeek_cleanup_runs":
		return h.handleCleanupAnalysisRuns(ctx, request)
	case "zeek_list_pcaps":
		return h.handleListPcaps(ctx, request)
	case "zeek_triage_pcap":
		return h.handleTriagePcap(ctx, request)
	default:
		return errorResult(fmt.Sprintf("unknown tool: %s", request.Params.Name)), nil
	}
}

func newTraceID(prefix string) string {
	if v := os.Getenv("MCP_TRACE_ID"); v != "" {
		return v
	}
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), os.Getpid())
}

func writeToolCallLog(toolName, traceID string, input any, status, errorCode string, result *mcp.CallToolResult, duration time.Duration) {
	path := os.Getenv("MCP_CALL_LOG_PATH")
	if path == "" {
		return
	}
	record := map[string]any{
		"timestamp":        time.Now().UTC().Format(time.RFC3339Nano),
		"trace_id":         traceID,
		"tool_name":        toolName,
		"normalized_input": input,
		"status":           status,
		"error_code":       errorCode,
		"duration_ms":      duration.Milliseconds(),
		"output_bytes":     resultTextBytes(result),
		"artifact_paths":   []string{},
	}
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}

func (ms *MCPServer) Run() error {
	log.Printf("INFO: Zeek MCP Server v%s starting", Version)
	log.Printf("INFO: Scripts loaded: %d", len(ms.registry.ListScripts(ListScriptsRequest{})))
	log.Printf("INFO: Path maps configured: %d", len(ms.paths.Mappings()))
	log.Printf("INFO: Git commit: %s, Build time: %s", GitCommit, BuildTime)

	return server.ServeStdio(ms.server)
}

func (h *Handler) cleanupArtifactsOnStart() {
	if !envBool("ZEEK_MCP_ARTIFACT_CLEANUP_ON_START", false) {
		return
	}
	root, err := h.resolveOutputRoot(map[string]interface{}{})
	if err != nil {
		log.Printf("WARN: artifact cleanup on start skipped: %v", err)
		return
	}
	retentionDays := envInt("ZEEK_MCP_ARTIFACT_RETENTION_DAYS", 0)
	maxBytes := int64(envInt("ZEEK_MCP_ARTIFACT_MAX_BYTES", 0))
	if retentionDays <= 0 && maxBytes <= 0 {
		log.Printf("INFO: artifact cleanup on start skipped: no TTL or max bytes configured")
		return
	}
	result := cleanupAnalysisRuns(root, retentionDays, maxBytes, false, true)
	log.Printf("INFO: artifact cleanup on start completed: candidates=%d deleted=%d deleted_bytes=%d", result.CandidateRuns, result.DeletedRuns, result.DeletedBytes)
}
