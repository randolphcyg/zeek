package main

import (
	"context"
	"fmt"
	"log"
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
	switch request.Params.Name {
	case "zeek_list_detection_scripts":
		return h.handleListScripts(ctx, request)
	case "zeek_inspect_pcap":
		return h.handleGetPcapInfo(ctx, request)
	case "zeek_run_detection":
		return h.handleRunDetection(ctx, request)
	case "zeek_extract_files":
		return h.handleExtractFiles(ctx, request)
	case "zeek_get_detection_script":
		return h.handleGetScriptDetail(ctx, request)
	case "zeek_health":
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
	case "zeek_run_intel_match":
		return h.handleRunIntelMatch(ctx, request)
	case "zeek_run_signature":
		return h.handleRunSignature(ctx, request)
	case "zeek_get_artifact_manifest":
		return h.handleGetArtifactManifest(ctx, request)
	case "zeek_list_analysis_runs":
		return h.handleListAnalysisRuns(ctx, request)
	case "zeek_cleanup_analysis_runs":
		return h.handleCleanupAnalysisRuns(ctx, request)
	default:
		return errorResult(fmt.Sprintf("unknown tool: %s", request.Params.Name)), nil
	}
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
