package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var (
	Version       = "2.0.0"
	BuildTime     = "unknown"
	GitCommit     = "unknown"
	TargetZeekLTS = "9.0.0"
)

type MCPServer struct {
	server    *server.MCPServer
	handler   *Handler
	registry  *ScriptRegistry
	executor  *Executor
	baseDir   string
	paths     *PathResolver
	startTime time.Time
}

func NewMCPServer(baseDir, scriptsDir string, pathMaps []PathMap) *MCPServer {
	registry := NewScriptRegistry(scriptsDir)
	if err := registry.Scan(); err != nil {
		slog.Warn("failed to scan scripts", "error", err)
	}

	executor := NewExecutor(ExecutorConfig{})

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

	handler.mcpServer = s

	tools := buildTools()
	for _, tool := range tools {
		s.AddTool(tool, handler.dispatchTool)
	}
	handler.registerResources(s)

	return &MCPServer{
		server:    s,
		handler:   handler,
		registry:  registry,
		executor:  executor,
		baseDir:   baseDir,
		paths:     handler.paths,
		startTime: time.Now(),
	}
}

func (h *Handler) dispatchTool(ctx context.Context, request mcp.CallToolRequest) (result *mcp.CallToolResult, err error) {
	start := time.Now()
	traceID := newTraceID("zeek")

	// Panic recovery: prevent a single panicking handler from crashing the server.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in tool handler",
				"tool", request.Params.Name,
				"trace_id", traceID,
				"panic", r,
				"stack", string(debug.Stack()),
			)
			result = envelopeResult(request.Params.Name, traceID, "INTERNAL_PANIC",
				fmt.Sprintf("internal panic: %v", r), false)
			err = nil
		}
	}()

	// Extract progress token for long-running operations
	if request.Params.Meta != nil && request.Params.Meta.ProgressToken != nil {
		ctx = withProgressToken(ctx, request.Params.Meta.ProgressToken)
	}

	result, err = h.dispatchToolInner(ctx, request)
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
	case "analyze_pcap":
		return h.handleAnalyzePcapV2(ctx, request)
	case "query_logs":
		return h.handleQueryLogsV2(ctx, request)
	case "hunt_intel":
		return h.handleHuntIntel(ctx, request)
	case "extract_files":
		return h.handleExtractFiles(ctx, request)
	case "validate_script":
		return h.handleSyntaxCheck(ctx, request)
	case "run_custom_script":
		return h.handleRunCustomScript(ctx, request)
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
	attrs := []any{
		"version", Version,
		"transport", transport,
		"scripts_loaded", len(ms.registry.ListScripts(ListScriptsRequest{})),
		"path_maps", len(ms.paths.Mappings()),
		"git_commit", GitCommit,
		"build_time", BuildTime,
		"target_zeek_lts", TargetZeekLTS,
	}
	if zeekVersion, err := getZeekVersion(context.Background(), ms.executor.config.ZeekBinary); err != nil {
		slog.Warn("zeek runtime version unavailable", "error", err)
		attrs = append(attrs, "zeek_compatibility", "unknown")
	} else {
		compat, warnings := zeekCompatibility(zeekVersion)
		attrs = append(attrs, "zeek_runtime_version", zeekVersion, "zeek_compatibility", compat)
		for _, warning := range warnings {
			slog.Warn(warning)
		}
	}
	slog.Info("Zeek MCP Server starting", attrs...)
}

func (ms *MCPServer) Run() error {
	return ms.RunStdio()
}

func (ms *MCPServer) RunStdio() error {
	ms.logStartup("stdio")
	return server.ServeStdio(ms.server)
}

func (ms *MCPServer) Shutdown() {
	slog.Info("Zeek MCP Server shutting down")
}

func (ms *MCPServer) RunHTTP(addr, endpoint, tlsCert, tlsKey string) error {
	ms.logStartup("streamable_http")
	if endpoint == "" {
		endpoint = "/mcp"
	}

	authToken := strings.TrimSpace(os.Getenv("ZEEK_AUTH_TOKEN"))

	httpServer := server.NewStreamableHTTPServer(
		ms.server,
		server.WithEndpointPath(endpoint),
	)

	mux := http.NewServeMux()
	mux.Handle(endpoint, httpServer)
	mux.HandleFunc("/healthz", ms.healthzHandler())

	var handler http.Handler = mux

	// Bearer token authentication middleware
	if authToken != "" {
		handler = authMiddleware(authToken)(mux)
		slog.Info("bearer token authentication enabled")
	}

	useTLS := tlsCert != "" && tlsKey != ""
	if useTLS {
		slog.Info("HTTPS MCP endpoint listening", "addr", addr, "endpoint", endpoint)
	} else {
		slog.Info("HTTP MCP endpoint listening", "addr", addr, "endpoint", endpoint)
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}
	if useTLS {
		return srv.ListenAndServeTLS(tlsCert, tlsKey)
	}
	return srv.ListenAndServe()
}

func (ms *MCPServer) healthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		uptime := time.Since(ms.startTime).String()
		scriptCount := len(ms.registry.ListScripts(ListScriptsRequest{}))
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "ok",
			"service":        "zeek",
			"version":        Version,
			"uptime":         uptime,
			"scripts_loaded": scriptCount,
			"tools":          len(buildTools()),
		})
	}
}

// authMiddleware returns an HTTP middleware that validates Bearer token authentication.
func authMiddleware(expectedToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Allow health check without auth
			if r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "missing or invalid Authorization header",
				})
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")
			if token != expectedToken {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "invalid bearer token",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (h *Handler) cleanupArtifactsOnStart() {
	if !envBool("ZEEK_ARTIFACT_CLEANUP_ON_START", false) {
		return
	}
	root, err := h.resolveOutputRoot(map[string]interface{}{})
	if err != nil {
		slog.Warn("artifact cleanup on start skipped", "error", err)
		return
	}
	retentionDays := envInt("ZEEK_ARTIFACT_RETENTION_DAYS", 0)
	maxBytes := int64(envInt("ZEEK_ARTIFACT_MAX_BYTES", 0))
	if retentionDays <= 0 && maxBytes <= 0 {
		slog.Info("artifact cleanup on start skipped: no TTL or max bytes configured")
		return
	}
	result := cleanupAnalysisRuns(root, retentionDays, maxBytes, false, true)
	slog.Info("artifact cleanup on start completed",
		"candidates", result.CandidateRuns,
		"deleted", result.DeletedRuns,
		"deleted_bytes", result.DeletedBytes,
	)
}
