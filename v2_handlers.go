package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

const toolSchemaVersionV2 = "2.0"

var safeRunID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var safeLogName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type DetectionCoverageV2 struct {
	ScriptID string `json:"script_id"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
}

type ToolResultV2 struct {
	SchemaVersion string      `json:"schema_version"`
	Status        string      `json:"status"`
	Engine        string      `json:"engine"`
	RunID         string      `json:"run_id,omitempty"`
	DurationMs    int64       `json:"duration_ms"`
	Data          interface{} `json:"data"`
	Artifacts     []Artifact  `json:"artifacts"`
	Warnings      []string    `json:"warnings"`
	Errors        interface{} `json:"errors"`
	Truncated     bool        `json:"truncated"`
	NextCursor    string      `json:"next_cursor,omitempty"`
}

func (h *Handler) handleAnalyzePcapV2(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	started := time.Now()
	args := getArgs(request)
	pcapPath, _ := args["pcap_path"].(string)
	if pcapPath == "" {
		return errorResult("pcap_path is required"), nil
	}
	resolved, err := h.paths.ResolveExisting("pcap_path", pcapPath)
	if err != nil {
		return pathErrorResult(err), nil
	}
	profile, _ := args["profile"].(string)
	if profile == "" {
		profile = "baseline"
	}
	if profile != "baseline" && profile != "standard" && profile != "full" {
		return validationErrorResult("profile must be baseline, standard, or full"), nil
	}

	info, infoErr := GetPcapInfo(resolved.Resolved)
	allDetectionPaths := h.registry.GetScriptPaths(nil, ScriptTypeDetection)
	var scriptPaths []string
	if profile == "standard" && infoErr == nil {
		scriptPaths = h.registry.GetScriptPaths(h.generateScriptSuggestions(info), ScriptTypeDetection)
	} else if profile == "full" {
		scriptPaths = allDetectionPaths
	}
	extractFiles, _ := args["extract_files"].(bool)
	if extractFiles {
		scriptPaths = append(scriptPaths, h.registry.GetScriptPaths(nil, ScriptTypeExtraction)...)
	}

	run, err := h.prepareArtifactRun(args)
	if err != nil {
		return outputErrorResult(err), nil
	}
	extractDir := ""
	if extractFiles {
		extractDir = run.ExtractedDir
	}
	result := h.executor.RunDetection(ctx, resolved.Resolved, scriptPaths, extractDir, run)
	result.Tool = "analyze_pcap"
	result.PcapPath = pcapPath
	result.RequestedPath = resolved.Requested
	result.ResolvedPath = resolved.Resolved
	h.finalizeArtifactRun(ctx, result, run)

	matchedScripts := map[string]bool{}
	for _, alert := range result.Alerts {
		matchedScripts[alert.Script] = true
		matchedScripts[alert.Rule] = true
	}
	selectedScripts := make(map[string]bool, len(scriptPaths))
	for _, path := range scriptPaths {
		selectedScripts[path] = true
	}
	stagingFailed := map[string]string{}
	for _, execErr := range result.Errors {
		if execErr.ErrorType == "staging_failed" {
			stagingFailed[strings.TrimSuffix(execErr.Script, filepath.Ext(execErr.Script))] = execErr.Message
		}
	}
	coverage := make([]DetectionCoverageV2, 0, len(allDetectionPaths))
	for _, path := range allDetectionPaths {
		id := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		status := "not_applicable"
		reason := fmt.Sprintf("not selected by %s profile", profile)
		if selectedScripts[path] {
			status = "no_match"
			reason = ""
		}
		if selectedScripts[path] && matchedScripts[id] {
			status = "matched"
		}
		if selectedScripts[path] && result.Status != "completed" {
			status = "error"
			reason = result.Status
		}
		if msg, failed := stagingFailed[id]; failed && selectedScripts[path] {
			status = "error"
			reason = "staging_failed: " + msg
		}
		coverage = append(coverage, DetectionCoverageV2{ScriptID: id, Status: status, Reason: reason})
	}

	data := map[string]interface{}{
		"profile":         profile,
		"alerts":          result.Alerts,
		"extracted_files": result.Files,
		"log_paths":       result.LogPaths,
		"coverage":        coverage,
	}
	if infoErr != nil {
		result.Warnings = append(result.Warnings, "capture metadata unavailable: "+infoErr.Error())
	} else {
		data["capture"] = map[string]interface{}{
			"file_size": info.FileSize, "packet_count": info.PacketCount,
			"duration_sec": info.Duration, "duration_known": info.DurationKnown,
			"sampled": info.Sampled,
			"protocols": info.Protocols, "top_talkers": info.TopTalkers,
			"services": info.Services, "analyzable": info.Analyzable,
			"analysis_status": info.AnalysisStatus, "warnings": info.Warnings,
		}
	}
	truncated := infoErr == nil && info.Sampled
	envelope := ToolResultV2{
		SchemaVersion: toolSchemaVersionV2, Status: result.Status, Engine: "zeek",
		RunID: result.RunID, DurationMs: time.Since(started).Milliseconds(),
		Data: data, Artifacts: result.Artifacts, Warnings: nonNilStrings(result.Warnings),
		Errors: result.Errors, Truncated: truncated,
	}
	return v2TextResult(envelope), nil
}

func (h *Handler) handleQueryLogsV2(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_ = ctx
	started := time.Now()
	args := getArgs(request)
	runID, _ := args["run_id"].(string)
	logName, _ := args["log"].(string)
	if !safeRunID.MatchString(runID) || !safeLogName.MatchString(logName) {
		return validationErrorResult("run_id and log must contain only letters, numbers, underscore, or hyphen"), nil
	}
	root, err := h.resolveOutputRoot(args)
	if err != nil {
		return outputErrorResult(err), nil
	}
	logPath := filepath.Join(root, "runs", runID, "logs", logName+".log")
	if _, err := os.Stat(logPath); err != nil {
		return errorResult(fmt.Sprintf("persisted log not found for run_id=%s log=%s", runID, logName)), nil
	}
	limit := numberArg(args["limit"], 100)
	if limit < 1 {
		limit = 1
	}
	if limit > 500 {
		limit = 500
	}
	offset := 0
	if cursor, _ := args["cursor"].(string); cursor != "" {
		parsed, parseErr := strconv.Atoi(cursor)
		if parseErr != nil || parsed < 0 {
			return validationErrorResult("cursor is invalid"), nil
		}
		offset = parsed
	}
	selectFields := stringSliceArg(args["select"])
	predicates, _ := args["predicates"].(map[string]interface{})
	aggregate, _ := args["aggregate"].(string)

	records, total, hasMore, err := queryJSONLog(logPath, selectFields, predicates, offset, limit)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	data := map[string]interface{}{"log": logName, "records": records, "matched": total}
	if aggregate == "count" {
		data = map[string]interface{}{"log": logName, "count": total}
		hasMore = false
	}
	next := ""
	if hasMore {
		next = strconv.Itoa(offset + len(records))
	}
	envelope := ToolResultV2{
		SchemaVersion: toolSchemaVersionV2, Status: "completed", Engine: "zeek",
		RunID: runID, DurationMs: time.Since(started).Milliseconds(), Data: data,
		Artifacts: []Artifact{}, Warnings: []string{}, Errors: []interface{}{},
		Truncated: hasMore, NextCursor: next,
	}
	return v2TextResult(envelope), nil
}

func queryJSONLog(path string, selected []string, predicates map[string]interface{}, offset, limit int) ([]map[string]interface{}, int, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, false, err
	}
	defer file.Close()
	records := make([]map[string]interface{}, 0, limit)
	matched := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var record map[string]interface{}
		if err := json.Unmarshal([]byte(line), &record); err != nil || !matchesPredicates(record, predicates) {
			continue
		}
		if matched >= offset && len(records) < limit {
			if len(selected) > 0 {
				projected := make(map[string]interface{}, len(selected))
				for _, field := range selected {
					if value, ok := record[field]; ok {
						projected[field] = value
					}
				}
				record = projected
			}
			records = append(records, record)
		}
		matched++
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, false, err
	}
	return records, matched, matched > offset+len(records), nil
}

func matchesPredicates(record map[string]interface{}, predicates map[string]interface{}) bool {
	for key, expected := range predicates {
		actual, ok := record[key]
		if !ok || fmt.Sprint(actual) != fmt.Sprint(expected) {
			return false
		}
	}
	return true
}

func numberArg(raw interface{}, fallback int) int {
	switch value := raw.(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		return fallback
	}
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func v2TextResult(value interface{}) *mcp.CallToolResult {
	data, _ := json.MarshalIndent(value, "", "  ")
	return textResult(string(data))
}
