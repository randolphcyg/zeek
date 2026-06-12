package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
		baseDir:  baseDir,
		paths:    NewPathResolver(pathMaps),
	}
	handler.cleanupArtifactsOnStart()

	s := server.NewMCPServer(
		"zeek",
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
	case "list_scripts":
		return h.handleListScripts(ctx, request)
	case "inspect_capture":
		return h.handleGetPcapInfo(ctx, request)
	case "detect_threats":
		return h.handleRunDetection(ctx, request)
	case "extract_files":
		return h.handleExtractFiles(ctx, request)
	case "get_script":
		return h.handleGetScriptDetail(ctx, request)
	case "health_check":
		return h.handleHealthCheck(ctx, request)
	case "validate_script":
		return h.handleSyntaxCheck(ctx, request)
	case "run_custom_script":
		return h.handleRunCustomScript(ctx, request)
	case "generate_logs":
		return h.handleGenerateLogs(ctx, request)
	case "match_intel":
		return h.handleRunIntelMatch(ctx, request)
	case "run_signature":
		return h.handleRunSignature(ctx, request)
	case "get_run_manifest":
		return h.handleGetArtifactManifest(ctx, request)
	case "list_runs":
		return h.handleListAnalysisRuns(ctx, request)
	case "cleanup_runs":
		return h.handleCleanupAnalysisRuns(ctx, request)
	case "list_pcaps":
		return h.handleListPcaps(ctx, request)
	case "triage_pcap":
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

func (ms *MCPServer) logStartup(transport string) {
	log.Printf("INFO: Zeek MCP Server v%s starting", Version)
	log.Printf("INFO: Transport: %s", transport)
	log.Printf("INFO: Scripts loaded: %d", len(ms.registry.ListScripts(ListScriptsRequest{})))
	log.Printf("INFO: Path maps configured: %d", len(ms.paths.Mappings()))
	log.Printf("INFO: Git commit: %s, Build time: %s", GitCommit, BuildTime)
}

func (ms *MCPServer) Run() error {
	return ms.RunStdio()
}

func (ms *MCPServer) RunStdio() error {
	ms.logStartup("stdio")
	return server.ServeStdio(ms.server)
}

func (ms *MCPServer) RunHTTP(addr, endpoint, tlsCert, tlsKey string) error {
	ms.logStartup("streamable_http")
	if endpoint == "" {
		endpoint = "/mcp"
	}
	httpServer := server.NewStreamableHTTPServer(
		ms.server,
		server.WithEndpointPath(endpoint),
	)
	mux := http.NewServeMux()
	mux.Handle(endpoint, httpServer)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"zeek"}`))
	})

	useTLS := tlsCert != "" && tlsKey != ""
	if useTLS {
		log.Printf("INFO: HTTPS MCP endpoint listening on %s%s", addr, endpoint)
	} else {
		log.Printf("INFO: HTTP MCP endpoint listening on %s%s", addr, endpoint)
	}

	if useTLS {
		return http.ListenAndServeTLS(addr, tlsCert, tlsKey, mux)
	}
	return http.ListenAndServe(addr, mux)
}

func (h *Handler) cleanupArtifactsOnStart() {
	if !envBool("ZEEK_ARTIFACT_CLEANUP_ON_START", false) {
		return
	}
	root, err := h.resolveOutputRoot(map[string]interface{}{})
	if err != nil {
		log.Printf("WARN: artifact cleanup on start skipped: %v", err)
		return
	}
	retentionDays := envInt("ZEEK_ARTIFACT_RETENTION_DAYS", 0)
	maxBytes := int64(envInt("ZEEK_ARTIFACT_MAX_BYTES", 0))
	if retentionDays <= 0 && maxBytes <= 0 {
		log.Printf("INFO: artifact cleanup on start skipped: no TTL or max bytes configured")
		return
	}
	result := cleanupAnalysisRuns(root, retentionDays, maxBytes, false, true)
	log.Printf("INFO: artifact cleanup on start completed: candidates=%d deleted=%d deleted_bytes=%d", result.CandidateRuns, result.DeletedRuns, result.DeletedBytes)
}
