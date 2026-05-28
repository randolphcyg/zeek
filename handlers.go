package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

type Handler struct {
	registry *ScriptRegistry
	executor *Executor
	cache    *ResultCache
	baseDir  string
	paths    *PathResolver
}

func getArgs(request mcp.CallToolRequest) map[string]interface{} {
	if args, ok := request.Params.Arguments.(map[string]interface{}); ok {
		return args
	}
	return map[string]interface{}{}
}

func (h *Handler) handleListScripts(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)

	req := ListScriptsRequest{}
	if cat, ok := args["category"].(string); ok {
		req.Category = cat
	}
	if typ, ok := args["type"].(string); ok {
		req.Type = typ
	}
	if name, ok := args["name"].(string); ok {
		req.Name = name
	}
	if enabledOnly, ok := args["enabled_only"].(bool); ok {
		req.EnabledOnly = enabledOnly
	}

	scripts := h.registry.ListScripts(req)

	type scriptItem struct {
		Name        string   `json:"name"`
		ScriptID    string   `json:"script_id"`
		Type        string   `json:"type"`
		Category    string   `json:"category"`
		Description string   `json:"description"`
		Signature   string   `json:"signature"`
		NoticeTypes []string `json:"notice_types,omitempty"`
		Size        string   `json:"size"`
		Checksum    string   `json:"checksum"`
		UpdatedAt   string   `json:"updated_at"`
		Enabled     bool     `json:"enabled"`
		Valid       bool     `json:"valid"`
		Error       string   `json:"error,omitempty"`
	}

	var items []scriptItem
	for _, s := range scripts {
		items = append(items, scriptItem{
			Name:        s.Name,
			ScriptID:    s.ScriptID,
			Type:        s.Type,
			Category:    s.Category,
			Description: s.Description,
			Signature:   s.Signature,
			NoticeTypes: s.NoticeTypes,
			Size:        s.Size,
			Checksum:    s.Checksum,
			UpdatedAt:   s.UpdatedAt,
			Enabled:     s.Enabled,
			Valid:       s.Valid,
			Error:       s.Error,
		})
	}

	result := map[string]interface{}{
		"tool":    "zeek_list_detection_scripts",
		"total":   len(items),
		"scripts": items,
	}

	text, _ := json.MarshalIndent(result, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
	}, nil
}

func (h *Handler) handleGetPcapInfo(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)
	pcapPath, ok := args["pcap_path"].(string)
	if !ok || pcapPath == "" {
		return errorResult("pcap_path is required"), nil
	}
	pcapResolution, err := h.paths.ResolveExisting("pcap_path", pcapPath)
	if err != nil {
		return pathErrorResult(err), nil
	}

	info, err := GetPcapInfoForInspection(pcapResolution.Resolved)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to get pcap info: %s", err.Error())), nil
	}

	suggestion := h.generateScriptSuggestions(info)

	resp := map[string]interface{}{
		"tool":              "zeek_inspect_pcap",
		"pcap_path":         pcapPath,
		"requested_path":    pcapResolution.Requested,
		"resolved_path":     pcapResolution.Resolved,
		"path_mapped":       pcapResolution.Mapped,
		"file_size":         info.FileSize,
		"packet_count":      info.PacketCount,
		"duration_sec":      info.Duration,
		"duration_known":    info.DurationKnown,
		"protocols":         info.Protocols,
		"top_talkers":       info.TopTalkers,
		"services":          info.Services,
		"analyzable":        info.Analyzable,
		"analysis_status":   info.AnalysisStatus,
		"warnings":          info.Warnings,
		"suggested_scripts": suggestion,
	}

	text, _ := json.MarshalIndent(resp, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
	}, nil
}

func (h *Handler) generateScriptSuggestions(info *PcapInfo) []string {
	if len(info.Protocols) == 0 || !info.Analyzable {
		return []string{}
	}

	protocolMap := map[string][]string{
		"ssh":    {"detect_ssh_bruteforce", "detect_ssh_file_transfer"},
		"http":   {"detect_http_webshell", "detect_http_brute_force", "detect_http_cmd_injection", "detect_http_flood", "detect_http_suspicious_ua"},
		"dns":    {"detect_dns_flood"},
		"tcp":    {"detect_syn_flood", "detect_anomalous_traffic"},
		"smb":    {"detect_file_tampering", "detect_bulk_download"},
		"ftp":    {"detect_bulk_download", "detect_file_tampering"},
		"modbus": {"detect_anomalous_traffic"},
		"mqtt":   {"detect_anomalous_traffic"},
	}

	seen := make(map[string]bool)
	var suggestions []string
	for _, proto := range info.Protocols {
		if scripts, ok := protocolMap[strings.ToLower(proto)]; ok {
			for _, s := range scripts {
				if !seen[s] {
					suggestions = append(suggestions, s)
					seen[s] = true
				}
			}
		}
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions, "detect_anomalous_traffic")
	}

	return suggestions
}

func (h *Handler) handleRunDetection(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)
	pcapPath, ok := args["pcap_path"].(string)
	if !ok || pcapPath == "" {
		return errorResult("pcap_path is required"), nil
	}
	pcapResolution, err := h.paths.ResolveExisting("pcap_path", pcapPath)
	if err != nil {
		return pathErrorResult(err), nil
	}

	var scriptNames []string
	if scriptsRaw, ok := args["scripts"].([]interface{}); ok {
		for _, s := range scriptsRaw {
			if name, ok := s.(string); ok {
				scriptNames = append(scriptNames, name)
			}
		}
	}

	extractFiles := false
	if ef, ok := args["extract_files"].(bool); ok {
		extractFiles = ef
	}

	scriptPaths := h.registry.GetScriptPaths(scriptNames, ScriptTypeDetection)
	if len(scriptNames) > 0 && len(scriptPaths) == 0 {
		return errorResult("no matching enabled detection scripts found"), nil
	}
	cacheScripts := append([]string{}, scriptNames...)
	if len(cacheScripts) == 0 {
		cacheScripts = []string{"__all_detection_scripts"}
	}

	if extractFiles {
		extractionPaths := h.registry.GetScriptPaths(nil, ScriptTypeExtraction)
		scriptPaths = append(scriptPaths, extractionPaths...)
		cacheScripts = append(cacheScripts, "__extract_files")
	}

	_ = cacheScripts

	artifactRun, err := h.prepareArtifactRun(args)
	if err != nil {
		return outputErrorResult(err), nil
	}
	extractDir := ""
	if extractFiles {
		extractDir = artifactRun.ExtractedDir
	}

	result := h.executor.RunDetection(ctx, pcapResolution.Resolved, scriptPaths, extractDir, artifactRun)
	result.PcapPath = pcapPath
	result.RequestedPath = pcapResolution.Requested
	result.ResolvedPath = pcapResolution.Resolved
	h.finalizeArtifactRun(ctx, result, artifactRun)

	text := FormatResultJSON(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: text},
		},
	}, nil
}

func (h *Handler) handleExtractFiles(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)
	pcapPath, ok := args["pcap_path"].(string)
	if !ok || pcapPath == "" {
		return errorResult("pcap_path is required"), nil
	}
	pcapResolution, err := h.paths.ResolveExisting("pcap_path", pcapPath)
	if err != nil {
		return pathErrorResult(err), nil
	}

	extractScriptPaths := h.registry.GetScriptPaths(nil, ScriptTypeExtraction)
	if len(extractScriptPaths) == 0 {
		return errorResult("no enabled extraction scripts found"), nil
	}

	artifactRun, err := h.prepareArtifactRun(args)
	if err != nil {
		return outputErrorResult(err), nil
	}
	extractDir := artifactRun.ExtractedDir

	result := h.executor.RunDetection(ctx, pcapResolution.Resolved, extractScriptPaths, extractDir, artifactRun)
	result.Tool = "zeek_extract_files"
	result.PcapPath = pcapPath
	result.RequestedPath = pcapResolution.Requested
	result.ResolvedPath = pcapResolution.Resolved
	h.finalizeArtifactRun(ctx, result, artifactRun)

	text := FormatResultJSON(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: text},
		},
	}, nil
}

func (h *Handler) handleGetScriptDetail(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)
	scriptName, ok := args["script_name"].(string)
	if !ok || scriptName == "" {
		return errorResult("script_name is required"), nil
	}

	meta := h.registry.GetScript(scriptName)
	if meta == nil {
		return errorResult(fmt.Sprintf("script not found: %s", scriptName)), nil
	}

	resp := map[string]interface{}{
		"tool":         "zeek_get_detection_script",
		"name":         meta.Name,
		"script_id":    meta.ScriptID,
		"type":         meta.Type,
		"category":     meta.Category,
		"description":  meta.Description,
		"signature":    meta.Signature,
		"notice_types": meta.NoticeTypes,
		"file_path":    meta.FilePath,
		"size":         meta.Size,
		"checksum":     meta.Checksum,
		"updated_at":   meta.UpdatedAt,
		"enabled":      meta.Enabled,
		"valid":        meta.Valid,
	}
	if meta.Error != "" {
		resp["error"] = meta.Error
	}
	if includeSource, _ := args["include_source"].(bool); includeSource {
		if data, err := os.ReadFile(meta.FilePath); err == nil {
			resp["source"] = string(data)
		}
	}

	text, _ := json.MarshalIndent(resp, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
	}, nil
}

func (h *Handler) handleHealthCheck(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	runtimeVersion, zeekErr := getZeekVersion(ctx)
	zeekOk := zeekErr == nil
	compatibility, versionWarnings := zeekCompatibility(runtimeVersion)

	resp := map[string]interface{}{
		"tool":               "zeek_health",
		"status":             "healthy",
		"version":            Version,
		"target_zeek_lts":    TargetZeekLTS,
		"runtime_zeek":       runtimeVersion,
		"zeek_compatibility": compatibility,
		"warnings":           versionWarnings,
		"zeek_ok":            zeekOk,
		"scripts_loaded":     len(h.registry.ListScripts(ListScriptsRequest{})),
		"detection_scripts":  len(h.registry.ListScripts(ListScriptsRequest{Type: ScriptTypeDetection})),
		"extraction_scripts": len(h.registry.ListScripts(ListScriptsRequest{Type: ScriptTypeExtraction})),
		"utility_scripts":    len(h.registry.ListScripts(ListScriptsRequest{Type: ScriptTypeUtility})),
		"path_maps":          h.paths.Mappings(),
	}

	text, _ := json.MarshalIndent(resp, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
	}, nil
}

func (h *Handler) handleSyntaxCheck(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)

	scriptName, _ := args["script_name"].(string)
	scriptPath, _ := args["script_path"].(string)
	scriptContent, _ := args["script_content"].(string)

	if scriptName == "" && scriptPath == "" && scriptContent == "" {
		return validationErrorResult("script_name, script_path, or script_content is required"), nil
	}

	var inputPath string
	var cleanup func()

	if scriptContent != "" {
		tmpFile, err := os.CreateTemp("", "zeek_syntax_*.zeek")
		if err != nil {
			return errorResult(fmt.Sprintf("failed to create temp file: %s", err.Error())), nil
		}
		if _, err := tmpFile.WriteString(scriptContent); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return errorResult(fmt.Sprintf("failed to write temp file: %s", err.Error())), nil
		}
		tmpFile.Close()
		inputPath = tmpFile.Name()
		cleanup = func() { os.Remove(inputPath) }
	} else if scriptName != "" {
		meta := h.registry.GetScript(scriptName)
		if meta == nil {
			return errorResult(fmt.Sprintf("script not found: %s", scriptName)), nil
		}
		inputPath = meta.FilePath
	} else {
		resolution, err := h.paths.ResolveExisting("script_path", scriptPath)
		if err != nil {
			return pathErrorResult(err), nil
		}
		inputPath = resolution.Resolved
	}

	if cleanup != nil {
		defer cleanup()
	}

	cmd := exec.CommandContext(ctx, "zeek", "--parse-only", inputPath)
	output, err := cmd.CombinedOutput()

	if err != nil {
		errMsg := strings.TrimSpace(string(output))
		return errorResult(errMsg), nil
	}

	resp := map[string]interface{}{
		"tool":  "zeek_validate_script",
		"valid": true,
	}
	if inputPath != "" {
		resp["script_path"] = inputPath
	}

	text, _ := json.MarshalIndent(resp, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
	}, nil
}

func (h *Handler) handleZeekVersion(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	runtimeVersion, err := getZeekVersion(ctx)
	compatibility, warnings := zeekCompatibility(runtimeVersion)

	resp := map[string]interface{}{
		"tool":               "zeek_get_version",
		"mcp_version":        Version,
		"target_zeek_lts":    TargetZeekLTS,
		"zeek_compatibility": compatibility,
		"warnings":           warnings,
	}
	if err != nil {
		resp["error"] = fmt.Sprintf("failed to get zeek version: %s", err.Error())
	} else {
		resp["version"] = runtimeVersion
	}

	text, _ := json.MarshalIndent(resp, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
	}, nil
}

func getZeekVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "zeek", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func zeekCompatibility(runtimeVersion string) (string, []string) {
	if runtimeVersion == "" {
		return "unknown", []string{"Zeek runtime version is unavailable"}
	}
	targetPrefix := "zeek version " + strings.TrimSuffix(TargetZeekLTS, ".8")
	if strings.Contains(runtimeVersion, "zeek version "+TargetZeekLTS) {
		return "target_lts", nil
	}
	if strings.Contains(runtimeVersion, targetPrefix) {
		return "same_lts_line", nil
	}
	return "runtime_differs_from_target_lts", []string{
		fmt.Sprintf("This project targets Zeek %s LTS; runtime reports %q. Validate release builds in the Zeek %s container.", TargetZeekLTS, runtimeVersion, TargetZeekLTS),
	}
}

func (h *Handler) handleReloadScripts(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	result, err := h.registry.Reload()
	if err != nil {
		return errorResult(fmt.Sprintf("reload failed: %s", err.Error())), nil
	}

	resp := map[string]interface{}{
		"tool":    "zeek_reload_scripts",
		"status":  "reloaded",
		"total":   result.Total,
		"valid":   result.Valid,
		"invalid": result.Invalid,
	}

	text, _ := json.MarshalIndent(resp, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
	}, nil
}

func (h *Handler) prepareArtifactRun(args map[string]interface{}) (*ArtifactRun, error) {
	outputRoot, err := h.resolveOutputRoot(args)
	if err != nil {
		return nil, err
	}
	return prepareArtifactRun(outputRoot)
}

func (h *Handler) resolveOutputRoot(args map[string]interface{}) (string, error) {
	if outputDir, _ := args["output_dir"].(string); outputDir != "" {
		outputResolution, err := h.paths.ResolveWritable("output_dir", outputDir)
		if err != nil {
			return "", err
		}
		return outputResolution.Resolved, nil
	}
	if dirWritable("/outputs") {
		return "/outputs", nil
	}
	return "", fmt.Errorf("output_dir_unavailable: configure a writable output mount such as /outputs or pass output_dir under a configured path map")
}

func dirWritable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	tmp, err := os.CreateTemp(dir, ".zeek_mcp_write_test_*")
	if err != nil {
		return false
	}
	name := tmp.Name()
	_ = tmp.Close()
	_ = os.Remove(name)
	return true
}

func (h *Handler) finalizeArtifactRun(ctx context.Context, result *ExecutionResult, artifactRun *ArtifactRun) {
	if artifactRun == nil {
		return
	}
	result.RunID = artifactRun.RunID
	result.RunDir = artifactRun.RunDir
	result.OutputDir = artifactRun.Root
	result.ManifestPath = artifactRun.ManifestPath
	result.Artifacts = buildArtifacts(artifactRun, result.Tool)
	artifactBytes := artifactBytes(result.Artifacts)
	retention := retentionInfo(artifactRun.CreatedAt)

	zeekVersion, _ := getZeekVersion(ctx)
	manifest := ArtifactManifest{
		RunID:             artifactRun.RunID,
		CreatedAt:         artifactRun.CreatedAt,
		Tool:              result.Tool,
		RequestedPcapPath: result.RequestedPath,
		ResolvedPcapPath:  result.ResolvedPath,
		ZeekVersion:       zeekVersion,
		Status:            result.Status,
		Artifacts:         result.Artifacts,
		ArtifactBytes:     artifactBytes,
		Retention:         retention,
		FindingsSummary: FindingsSummary{
			Alerts:         len(result.Alerts),
			ExtractedFiles: len(result.Files),
			Logs:           len(result.LogPaths),
			Errors:         len(result.Errors),
		},
	}
	if err := writeArtifactManifest(artifactRun.ManifestPath, manifest); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("failed to write artifact manifest: %s", err.Error()))
	}
}

func (h *Handler) handleGetArtifactManifest(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)
	manifestPath, _ := args["manifest_path"].(string)
	runID, _ := args["run_id"].(string)
	if manifestPath == "" && runID == "" {
		return errorResult("run_id or manifest_path is required"), nil
	}
	if manifestPath == "" {
		root, err := h.resolveOutputRoot(args)
		if err != nil {
			return outputErrorResult(err), nil
		}
		manifestPath = filepath.Join(root, "runs", runID, "manifest.json")
	}
	resolution, err := h.paths.ResolveExisting("manifest_path", manifestPath)
	if err != nil {
		if _, statErr := os.Stat(manifestPath); statErr == nil {
			resolution = PathResolution{Requested: manifestPath, Resolved: manifestPath}
		} else {
			return pathErrorResult(err), nil
		}
	}
	manifest, err := readArtifactManifest(resolution.Resolved)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read artifact manifest: %s", err.Error())), nil
	}
	resp := map[string]interface{}{
		"tool":           "zeek_get_artifact_manifest",
		"requested_path": resolution.Requested,
		"resolved_path":  resolution.Resolved,
		"manifest":       manifest,
	}
	text, _ := json.MarshalIndent(resp, "", "  ")
	return textResult(string(text)), nil
}

func (h *Handler) handleListAnalysisRuns(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)
	limit := 20
	if raw, ok := args["limit"].(float64); ok && raw > 0 {
		limit = int(raw)
	}
	root, err := h.resolveOutputRoot(args)
	if err != nil {
		return outputErrorResult(err), nil
	}
	runsRoot := filepath.Join(root, "runs")
	entries, err := os.ReadDir(runsRoot)
	if err != nil {
		resp := map[string]interface{}{
			"tool":        "zeek_list_analysis_runs",
			"output_dir":  root,
			"total":       0,
			"total_bytes": int64(0),
			"runs":        []AnalysisRunSummary{},
		}
		text, _ := json.MarshalIndent(resp, "", "  ")
		return textResult(string(text)), nil
	}

	var summaries []AnalysisRunSummary
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(runsRoot, entry.Name(), "manifest.json")
		manifest, err := readArtifactManifest(manifestPath)
		if err != nil {
			continue
		}
		summaries = append(summaries, AnalysisRunSummary{
			RunID:             manifest.RunID,
			CreatedAt:         manifest.CreatedAt,
			Tool:              manifest.Tool,
			Status:            manifest.Status,
			ManifestPath:      manifestPath,
			RequestedPcapPath: manifest.RequestedPcapPath,
			ResolvedPcapPath:  manifest.ResolvedPcapPath,
			ArtifactCount:     len(manifest.Artifacts),
			ArtifactBytes:     manifestArtifactBytes(manifest, filepath.Dir(manifestPath)),
			FindingsSummary:   manifest.FindingsSummary,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].CreatedAt > summaries[j].CreatedAt
	})
	if limit > 0 && len(summaries) > limit {
		summaries = summaries[:limit]
	}
	resp := map[string]interface{}{
		"tool":        "zeek_list_analysis_runs",
		"output_dir":  root,
		"total":       len(summaries),
		"total_bytes": totalAnalysisRunBytes(summaries),
		"runs":        summaries,
	}
	text, _ := json.MarshalIndent(resp, "", "  ")
	return textResult(string(text)), nil
}

func (h *Handler) handleCleanupAnalysisRuns(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)
	root, err := h.resolveOutputRoot(args)
	if err != nil {
		return outputErrorResult(err), nil
	}

	olderThanDays := intArg(args, "older_than_days", 0)
	maxTotalBytes := int64Arg(args, "max_total_bytes", 0)
	dryRun := boolArg(args, "dry_run", true)
	confirm := boolArg(args, "confirm", false)
	if !dryRun && !confirm {
		return errorResult("confirm=true is required when dry_run=false"), nil
	}

	result := cleanupAnalysisRuns(root, olderThanDays, maxTotalBytes, dryRun, confirm)
	text, _ := json.MarshalIndent(result, "", "  ")
	return textResult(string(text)), nil
}

func retentionInfo(createdAt string) RetentionInfo {
	info := RetentionInfo{CreatedAt: createdAt}
	retentionDays := envInt("ZEEK_MCP_ARTIFACT_RETENTION_DAYS", 0)
	if retentionDays <= 0 {
		return info
	}
	created, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return info
	}
	expiresAt := created.Add(time.Duration(retentionDays) * 24 * time.Hour)
	info.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	info.CleanupEligible = time.Now().UTC().After(expiresAt)
	return info
}

func manifestArtifactBytes(manifest *ArtifactManifest, runDir string) int64 {
	if manifest.ArtifactBytes > 0 {
		return manifest.ArtifactBytes
	}
	if len(manifest.Artifacts) > 0 {
		return artifactBytes(manifest.Artifacts)
	}
	return runDirSize(runDir)
}

func totalAnalysisRunBytes(summaries []AnalysisRunSummary) int64 {
	var total int64
	for _, summary := range summaries {
		total += summary.ArtifactBytes
	}
	return total
}

func cleanupAnalysisRuns(outputRoot string, olderThanDays int, maxTotalBytes int64, dryRun bool, confirm bool) CleanupResult {
	runsRoot := filepath.Join(outputRoot, "runs")
	result := CleanupResult{
		Tool:          "zeek_cleanup_analysis_runs",
		OutputDir:     outputRoot,
		DryRun:        dryRun,
		Confirmed:     confirm,
		OlderThanDays: olderThanDays,
		MaxTotalBytes: maxTotalBytes,
		Candidates:    []CleanupCandidate{},
	}

	runs := loadRunCleanupCandidates(runsRoot)
	result.TotalRuns = len(runs)
	for _, run := range runs {
		result.TotalBytesBefore += run.ArtifactBytes
	}

	candidateByRunID := make(map[string]CleanupCandidate)
	if olderThanDays > 0 {
		cutoff := time.Now().UTC().Add(-time.Duration(olderThanDays) * 24 * time.Hour)
		for _, run := range runs {
			created, err := time.Parse(time.RFC3339, run.CreatedAt)
			if err != nil || created.After(cutoff) {
				continue
			}
			run.Reason = fmt.Sprintf("older_than_%d_days", olderThanDays)
			candidateByRunID[run.RunID] = run
		}
	}

	if maxTotalBytes > 0 && result.TotalBytesBefore > maxTotalBytes {
		sort.Slice(runs, func(i, j int) bool {
			return runs[i].CreatedAt < runs[j].CreatedAt
		})
		projected := result.TotalBytesBefore
		for _, run := range runs {
			if projected <= maxTotalBytes {
				break
			}
			if existing, ok := candidateByRunID[run.RunID]; ok {
				existing.Reason = existing.Reason + ",max_total_bytes"
				candidateByRunID[run.RunID] = existing
			} else {
				run.Reason = "max_total_bytes"
				candidateByRunID[run.RunID] = run
			}
			projected -= run.ArtifactBytes
		}
	}

	for _, candidate := range candidateByRunID {
		result.Candidates = append(result.Candidates, candidate)
	}
	sort.Slice(result.Candidates, func(i, j int) bool {
		return result.Candidates[i].CreatedAt < result.Candidates[j].CreatedAt
	})
	result.CandidateRuns = len(result.Candidates)
	for i := range result.Candidates {
		result.BytesToDelete += result.Candidates[i].ArtifactBytes
		if dryRun {
			continue
		}
		if err := os.RemoveAll(result.Candidates[i].RunDir); err != nil {
			result.Candidates[i].Error = err.Error()
			continue
		}
		result.Candidates[i].Deleted = true
		result.DeletedRuns++
		result.DeletedBytes += result.Candidates[i].ArtifactBytes
	}
	result.TotalBytesAfter = result.TotalBytesBefore - result.DeletedBytes
	return result
}

func loadRunCleanupCandidates(runsRoot string) []CleanupCandidate {
	entries, err := os.ReadDir(runsRoot)
	if err != nil {
		return nil
	}
	var runs []CleanupCandidate
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		runDir := filepath.Join(runsRoot, entry.Name())
		manifestPath := filepath.Join(runDir, "manifest.json")
		manifest, err := readArtifactManifest(manifestPath)
		if err != nil {
			continue
		}
		runs = append(runs, CleanupCandidate{
			RunID:         manifest.RunID,
			ManifestPath:  manifestPath,
			RunDir:        runDir,
			CreatedAt:     manifest.CreatedAt,
			ArtifactBytes: manifestArtifactBytes(manifest, runDir),
		})
	}
	return runs
}

func intArg(args map[string]interface{}, key string, fallback int) int {
	if raw, ok := args[key].(float64); ok {
		return int(raw)
	}
	return fallback
}

func int64Arg(args map[string]interface{}, key string, fallback int64) int64 {
	if raw, ok := args[key].(float64); ok {
		return int64(raw)
	}
	return fallback
}

func boolArg(args map[string]interface{}, key string, fallback bool) bool {
	if raw, ok := args[key].(bool); ok {
		return raw
	}
	return fallback
}

func envInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	return strings.EqualFold(raw, "true") || raw == "1" || strings.EqualFold(raw, "yes")
}

func errorResult(msg string) *mcp.CallToolResult {
	payload := map[string]interface{}{
		"status": "error",
		"error":  msg,
		"errors": []map[string]string{
			{
				"error_type": "request_error",
				"message":    msg,
			},
		},
	}
	text, _ := json.Marshal(payload)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
		IsError: true,
	}
}

func pathErrorResult(err error) *mcp.CallToolResult {
	pathErr, ok := err.(*PathResolutionError)
	if !ok {
		return errorResult(err.Error())
	}
	payload := map[string]interface{}{
		"status":                  "error",
		"error":                   pathErr.Error(),
		"message":                 pathErr.Error(),
		"error_type":              "path_not_mounted",
		"requested_path":          pathErr.Path,
		"resolved_path":           pathErr.Resolved,
		"field":                   pathErr.Field,
		"path_maps":               pathErr.Mappings,
		"recommended_intake_dirs": recommendedIntakeDirs(pathErr.Mappings),
		"example_paths":           pathExamples(pathErr.Mappings),
		"errors": []map[string]string{
			{
				"error_type": "path_not_mounted",
				"message":    pathErr.Error(),
			},
		},
	}
	text, _ := json.MarshalIndent(payload, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
		IsError: true,
	}
}

func outputErrorResult(err error) *mcp.CallToolResult {
	msg := err.Error()
	payload := map[string]interface{}{
		"status":     "error",
		"error":      msg,
		"message":    msg,
		"error_type": "output_dir_unavailable",
		"errors": []map[string]string{
			{
				"error_type": "output_dir_unavailable",
				"message":    msg,
			},
		},
	}
	text, _ := json.MarshalIndent(payload, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
		IsError: true,
	}
}

func pathExamples(maps []PathMap) []string {
	var examples []string
	for _, m := range maps {
		if strings.Contains(strings.ToLower(m.ContainerPrefix), "output") {
			continue
		}
		examples = append(examples, filepath.Join(m.HostPrefix, "sample.pcap"))
		examples = append(examples, filepath.Join(m.ContainerPrefix, "sample.pcap"))
		if len(examples) >= 4 {
			break
		}
	}
	return examples
}

func recommendedIntakeDirs(maps []PathMap) []string {
	seen := make(map[string]bool)
	var dirs []string
	for _, m := range maps {
		if strings.Contains(strings.ToLower(m.ContainerPrefix), "output") {
			continue
		}
		for _, dir := range []string{m.HostPrefix, m.ContainerPrefix} {
			if dir != "" && !seen[dir] {
				dirs = append(dirs, dir)
				seen[dir] = true
			}
		}
	}
	return dirs
}

func validationErrorResult(msg string) *mcp.CallToolResult {
	payload := map[string]interface{}{
		"tool":   "zeek_validate_script",
		"status": "error",
		"valid":  false,
		"error":  msg,
		"errors": []map[string]string{
			{
				"script":     "input",
				"error_type": "missing_input",
				"message":    msg,
			},
		},
	}
	text, _ := json.MarshalIndent(payload, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
		IsError: true,
	}
}
