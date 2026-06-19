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
	"github.com/mark3labs/mcp-go/server"
)

type Handler struct {
	registry  *ScriptRegistry
	executor  *Executor
	baseDir   string
	paths     *PathResolver
	mcpServer *server.MCPServer
}

func getArgs(request mcp.CallToolRequest) map[string]interface{} {
	if args, ok := request.Params.Arguments.(map[string]interface{}); ok {
		return args
	}
	return map[string]interface{}{}
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
	result.Tool = "extract_files"
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

func (h *Handler) handleSyntaxCheck(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)

	scriptName, _ := args["script_name"].(string)
	scriptPath, _ := args["script_path"].(string)
	scriptContent, _ := args["script_content"].(string)

	if scriptName == "" && scriptPath == "" && scriptContent == "" {
		return validationErrorResult("script_name, script_path, or script_content is required"), nil
	}

	if scriptContent != "" {
		if errMsg := validateInputSize(scriptContent, "script_content"); errMsg != "" {
			return errorResult(errMsg), nil
		}
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
		"tool":  "validate_script",
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
	// Fallback: use <baseDir>/outputs when no explicit output mount exists
	// (e.g. running locally without Docker). Similar to epan's
	// default of using GOWIRESHARK_OUTPUT_DIR or os.TempDir().
	if h.baseDir != "" {
		localOutputs := filepath.Join(h.baseDir, "outputs")
		if err := os.MkdirAll(localOutputs, 0755); err == nil {
			return localOutputs, nil
		}
	}
	return "", fmt.Errorf("output_dir_unavailable: configure a writable output mount such as /outputs or pass output_dir under a configured path map")
}

func dirWritable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	tmp, err := os.CreateTemp(dir, ".zeek_write_test_*")
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

func (h *Handler) handleTriagePcap(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(request)
	pcapPath, _ := args["pcap_path"].(string)
	if pcapPath == "" {
		return errorResult("pcap_path is required"), nil
	}
	pcapResolution, err := h.paths.ResolveExisting("pcap_path", pcapPath)
	if err != nil {
		return pathErrorResult(err), nil
	}

	info, infoErr := GetPcapInfo(pcapResolution.Resolved)
	var suggested []string
	if infoErr == nil {
		suggested = h.generateScriptSuggestions(info)
	}
	scriptNames := stringSliceArg(args["scripts"])
	scriptPaths := h.registry.GetScriptPaths(scriptNames, ScriptTypeDetection)
	if len(scriptNames) > 0 && len(scriptPaths) == 0 {
		return errorResult("no matching enabled detection scripts found"), nil
	}
	if len(scriptPaths) == 0 {
		scriptPaths = h.registry.GetScriptPaths(nil, ScriptTypeDetection)
	}

	extractFiles := false
	if ef, ok := args["extract_files"].(bool); ok {
		extractFiles = ef
	}
	if extractFiles {
		extractionPaths := h.registry.GetScriptPaths(nil, ScriptTypeExtraction)
		scriptPaths = append(scriptPaths, extractionPaths...)
	}

	artifactRun, err := h.prepareArtifactRun(args)
	if err != nil {
		return outputErrorResult(err), nil
	}
	extractDir := ""
	if extractFiles {
		extractDir = artifactRun.ExtractedDir
	}

	totalScripts := len(scriptPaths)
	h.sendProgress(ctx, 0.15, floatPtr(1.0), formatProgressMessage("start", 0, totalScripts, 0))
	h.sendProgress(ctx, 0.3, floatPtr(1.0), formatProgressMessage("zeek", 0, totalScripts, 0))

	result := h.executor.RunDetection(ctx, pcapResolution.Resolved, scriptPaths, extractDir, artifactRun)
	result.Tool = "triage_pcap"
	result.PcapPath = pcapPath
	result.RequestedPath = pcapResolution.Requested
	result.ResolvedPath = pcapResolution.Resolved
	h.finalizeArtifactRun(ctx, result, artifactRun)

	alertCount := len(result.Alerts)
	h.sendProgress(ctx, 0.7, floatPtr(1.0), formatProgressMessage("parse", 0, totalScripts, alertCount))
	if extractFiles && len(result.Files) > 0 {
		h.sendProgress(ctx, 0.85, floatPtr(1.0), formatProgressMessage("extract", 0, totalScripts, alertCount))
	}
	h.sendProgress(ctx, 1.0, floatPtr(1.0), formatProgressMessage("complete", 0, totalScripts, alertCount))

	resp := map[string]interface{}{
		"tool":              "triage_pcap",
		"pcap_path":         pcapPath,
		"requested_path":    pcapResolution.Requested,
		"resolved_path":     pcapResolution.Resolved,
		"path_mapped":       pcapResolution.Mapped,
		"status":            result.Status,
		"alerts":            result.Alerts,
		"alert_count":       len(result.Alerts),
		"total_scripts":     totalScripts,
		"extracted_files":   result.Files,
		"extracted_count":   len(result.Files),
		"errors":            result.Errors,
		"warnings":          result.Warnings,
		"run_id":            result.RunID,
		"manifest_path":     result.ManifestPath,
		"artifacts":         result.Artifacts,
		"suggested_scripts": suggested,
		"recommended_next":  []string{"summarize_logs", "hunt_intel"},
	}
	if infoErr != nil {
		resp["inspect_error"] = infoErr.Error()
	} else {
		resp["capture"] = map[string]interface{}{
			"file_size":       info.FileSize,
			"packet_count":    info.PacketCount,
			"duration_sec":    info.Duration,
			"duration_known":  info.DurationKnown,
			"protocols":       info.Protocols,
			"top_talkers":     info.TopTalkers,
			"services":        info.Services,
			"analyzable":      info.Analyzable,
			"analysis_status": info.AnalysisStatus,
			"warnings":        info.Warnings,
		}
	}
	text, _ := json.MarshalIndent(resp, "", "  ")
	return textResult(string(text)), nil
}

func listPcaps(dir string) []map[string]interface{} {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var pcaps []map[string]interface{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".pcap" && ext != ".pcapng" && ext != ".cap" {
			continue
		}
		info, _ := entry.Info()
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		pcaps = append(pcaps, map[string]interface{}{
			"name": name,
			"path": filepath.Join(dir, name),
			"size": size,
		})
	}
	sort.Slice(pcaps, func(i, j int) bool {
		return pcaps[i]["name"].(string) < pcaps[j]["name"].(string)
	})
	return pcaps
}

func retentionInfo(createdAt string) RetentionInfo {
	info := RetentionInfo{CreatedAt: createdAt}
	retentionDays := envInt("ZEEK_ARTIFACT_RETENTION_DAYS", 0)
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
		Tool:          "artifact_cleanup",
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

func floatPtr(v float64) *float64 {
	return &v
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
	return envelopeResult("", "", errorCodeForMessage(msg), msg, false)
}

func pathErrorResult(err error) *mcp.CallToolResult {
	pathErr, ok := err.(*PathResolutionError)
	if !ok {
		return errorResult(err.Error())
	}
	payload := errorEnvelope("", "", "INVALID_PATH", pathErr.Error(), false)
	payload["requested_path"] = pathErr.Path
	payload["resolved_path"] = pathErr.Resolved
	payload["field"] = pathErr.Field
	payload["path_maps"] = pathErr.Mappings
	payload["recommended_intake_dirs"] = recommendedIntakeDirs(pathErr.Mappings)
	payload["example_paths"] = pathExamples(pathErr.Mappings)
	text, _ := json.MarshalIndent(payload, "", "  ")
	return &mcp.CallToolResult{
		Result: mcp.Result{Meta: &mcp.Meta{AdditionalFields: map[string]any{"error_code": "INVALID_PATH"}}},
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
		StructuredContent: payload,
		IsError:           true,
	}
}

func outputErrorResult(err error) *mcp.CallToolResult {
	msg := err.Error()
	return envelopeResult("", "", "OUTPUT_DIR_UNAVAILABLE", msg, false)
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
	payload := errorEnvelope("validate_script", "", "MISSING_REQUIRED_PARAM", msg, false)
	payload["valid"] = false
	text, _ := json.MarshalIndent(payload, "", "  ")
	return &mcp.CallToolResult{
		Result: mcp.Result{Meta: &mcp.Meta{AdditionalFields: map[string]any{"error_code": "MISSING_REQUIRED_PARAM"}}},
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(text)},
		},
		StructuredContent: payload,
		IsError:           true,
	}
}

func errorEnvelope(toolName, traceID, code, message string, retryable bool) map[string]interface{} {
	payload := map[string]interface{}{
		"ok":            false,
		"status":        "semantic_failure",
		"error_code":    code,
		"error_message": message,
		"suggestion":    suggestionForError(code),
		"retryable":     retryable,
		"retry_with":    map[string]interface{}{},
	}
	if toolName != "" {
		payload["tool"] = toolName
	}
	if traceID != "" {
		payload["trace_id"] = traceID
	}
	if next := nextToolForError(code); next != "" {
		payload["next_tool"] = next
	}
	return payload
}

func envelopeResult(toolName, traceID, code, message string, retryable bool) *mcp.CallToolResult {
	payload := errorEnvelope(toolName, traceID, code, message, retryable)
	text, _ := json.MarshalIndent(payload, "", "  ")
	metaFields := map[string]any{"error_code": code}
	if traceID != "" {
		metaFields["trace_id"] = traceID
	}
	return &mcp.CallToolResult{
		Result:            mcp.Result{Meta: &mcp.Meta{AdditionalFields: metaFields}},
		Content:           []mcp.Content{mcp.TextContent{Type: "text", Text: string(text)}},
		StructuredContent: payload,
		IsError:           true,
	}
}

func errorCodeForMessage(msg string) string {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "pcap_path is required"), strings.Contains(lower, "required"):
		return "MISSING_REQUIRED_PARAM"
	case strings.Contains(lower, "path"), strings.Contains(lower, "mount"):
		return "INVALID_PATH"
	case strings.Contains(lower, "disabled"):
		return "DISABLED"
	default:
		return "TOOL_ERROR"
	}
}

func suggestionForError(code string) string {
	switch code {
	case "INVALID_PATH":
		return "Check the pcap_path is accessible under a configured path map. Use the zeek://pcaps resource to discover available files."
	case "MISSING_REQUIRED_PARAM":
		return "Check the tool input schema and provide the required field before retrying."
	case "OUTPUT_DIR_UNAVAILABLE":
		return "Mount /outputs or pass output_dir under a configured writable path map."
	case "DISABLED":
		return "Enable the feature explicitly in the MCP environment before retrying."
	default:
		return "Inspect error_message and retry with corrected parameters."
	}
}

func nextToolForError(code string) string {
	switch code {
	case "INVALID_PATH":
		return ""
	case "OUTPUT_DIR_UNAVAILABLE":
		return ""
	default:
		return ""
	}
}

func errorCodeFromResult(result *mcp.CallToolResult) string {
	if result == nil || result.Meta == nil || result.Meta.AdditionalFields == nil {
		return "TOOL_ERROR"
	}
	if code, ok := result.Meta.AdditionalFields["error_code"].(string); ok && code != "" {
		return code
	}
	return "TOOL_ERROR"
}

func attachTraceToErrorResult(result *mcp.CallToolResult, toolName, traceID string) {
	if result == nil || !result.IsError || len(result.Content) == 0 {
		return
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		return
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(text.Text), &payload); err != nil {
		return
	}
	if _, ok := payload["tool"]; !ok && toolName != "" {
		payload["tool"] = toolName
	}
	payload["trace_id"] = traceID
	updated, _ := json.MarshalIndent(payload, "", "  ")
	result.Content[0] = mcp.TextContent{Type: "text", Text: string(updated)}
	result.StructuredContent = payload
}

func resultTextBytes(result *mcp.CallToolResult) int {
	if result == nil {
		return 0
	}
	total := 0
	for _, content := range result.Content {
		if text, ok := content.(mcp.TextContent); ok {
			total += len(text.Text)
		}
	}
	return total
}
