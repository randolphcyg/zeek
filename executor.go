package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ExecutorConfig struct {
	ZeekBinary string
	Timeout    time.Duration
}

type ExecutionResult struct {
	SchemaVersion   string                `json:"schema_version"`
	Engine          string                `json:"engine"`
	Tool            string                `json:"tool,omitempty"`
	PcapPath        string                `json:"pcap_path,omitempty"`
	RequestedPath   string                `json:"requested_path,omitempty"`
	ResolvedPath    string                `json:"resolved_path,omitempty"`
	RunID           string                `json:"run_id,omitempty"`
	RunDir          string                `json:"run_dir,omitempty"`
	OutputDir       string                `json:"output_dir,omitempty"`
	ManifestPath    string                `json:"manifest_path,omitempty"`
	Artifacts       []Artifact            `json:"artifacts,omitempty"`
	Status          string                `json:"status"`
	Alerts          []StandardAlert       `json:"alerts"`
	Files           []ExtractedFile       `json:"extracted_files,omitempty"`
	LogSummaries    map[string]LogSummary `json:"log_summaries,omitempty"`
	LogPaths        map[string]string     `json:"log_paths,omitempty"`
	WorkDirRetained bool                  `json:"work_dir_retained,omitempty"`
	Warnings        []string              `json:"warnings,omitempty"`
	Statistics      ExecutionStats        `json:"statistics"`
	Errors          []ExecutionError      `json:"errors"`
	DurationMs      int64                 `json:"duration_ms"`
}

type ExecutionStats struct {
	TotalScriptsRun  int `json:"total_scripts_run"`
	ScriptsWithError int `json:"scripts_with_errors"`
	TotalAlerts      int `json:"total_alerts"`
	TotalFiles       int `json:"total_files"`
	TotalLogs        int `json:"total_logs,omitempty"`
}

type ExecutionError struct {
	Script    string `json:"script"`
	ErrorType string `json:"error_type"`
	Message   string `json:"message"`
}

type StandardAlert struct {
	AlertID              string                 `json:"alert_id"`
	Script               string                 `json:"script"`
	Rule                 string                 `json:"rule"`
	Confidence           *float64               `json:"confidence,omitempty"`
	Severity             string                 `json:"severity"`
	Timestamp            string                 `json:"timestamp"`
	Src                  EndpointInfo           `json:"src"`
	Dst                  EndpointInfo           `json:"dst"`
	Proto                string                 `json:"proto"`
	Evidence             map[string]interface{} `json:"evidence,omitempty"`
	IOCs                 *IOCInfo               `json:"iocs,omitempty"`
	Msg                  string                 `json:"msg"`
	RuleVersion          string                 `json:"rule_version"`
	DetectionPack        string                 `json:"detection_pack"`
	DetectionPackVersion string                 `json:"detection_pack_version"`
	Category             string                 `json:"category"`
	AttackTechniques     []string               `json:"attack_techniques"`
	ScriptChecksum       string                 `json:"script_sha256"`
	FlowRef              FlowRefV2              `json:"flow_ref"`
	LogLocator           LogLocatorV2           `json:"log_locator"`
}

type FlowRefV2 struct {
	CommunityID string `json:"community_id,omitempty"`
	ZeekUID     string `json:"zeek_uid,omitempty"`
	SrcIP       string `json:"src_ip,omitempty"`
	SrcPort     int    `json:"src_port,omitempty"`
	DstIP       string `json:"dst_ip,omitempty"`
	DstPort     int    `json:"dst_port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	StartTime   string `json:"start_time,omitempty"`
}

type LogLocatorV2 struct {
	Log          string `json:"log"`
	Path         string `json:"path"`
	Line         int    `json:"line"`
	RecordSHA256 string `json:"record_sha256"`
}

type EndpointInfo struct {
	IP   string `json:"ip"`
	Port int    `json:"port,omitempty"`
}

type IOCInfo struct {
	IPs     []string `json:"ips,omitempty"`
	Domains []string `json:"domains,omitempty"`
	URLs    []string `json:"urls,omitempty"`
	Hashes  []string `json:"hashes,omitempty"`
}

type ExtractedFile struct {
	ID        string `json:"id"`
	FUID      string `json:"fuid,omitempty"`
	ZeekUID   string `json:"zeek_uid,omitempty"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	MimeType  string `json:"mime_type,omitempty"`
	Direction string `json:"direction,omitempty"`
	Integrity string `json:"integrity"`
}

type LogSummary struct {
	Path            string                   `json:"path,omitempty"`
	Records         int                      `json:"records"`
	Sample          []map[string]interface{} `json:"sample"`
	FieldsSeen      []string                 `json:"fields_seen,omitempty"`
	SampleTruncated bool                     `json:"sample_truncated,omitempty"`
	ReadError       string                   `json:"read_error,omitempty"`
}

type Executor struct {
	config ExecutorConfig
	sem    chan struct{} // Token-based semaphore limiting concurrent Zeek processes.
}

func NewExecutor(config ExecutorConfig) *Executor {
	if config.ZeekBinary == "" {
		config.ZeekBinary = envOrDefault("ZEEK_BINARY", "zeek")
	}
	if config.Timeout == 0 {
		config.Timeout = time.Duration(envInt("ZEEK_TIMEOUT_SECONDS", 120)) * time.Second
	}
	maxConcurrent := envInt("ZEEK_MAX_CONCURRENT", 4)
	if maxConcurrent <= 0 {
		maxConcurrent = 4
	}
	return &Executor{
		config: config,
		sem:    make(chan struct{}, maxConcurrent),
	}
}

// WithTimeout returns a copy of the Executor with a different timeout.
// The concurrency semaphore is shared with the parent so derived executors
// still respect ZEEK_MAX_CONCURRENT instead of blocking forever on a nil channel.
func (e *Executor) WithTimeout(timeout time.Duration) *Executor {
	return &Executor{
		config: ExecutorConfig{
			ZeekBinary: e.config.ZeekBinary,
			Timeout:    timeout,
		},
		sem: e.sem,
	}
}

func (e *Executor) RunDetection(ctx context.Context, pcapPath string, scripts []string, extractDir string, artifactRun *ArtifactRun) *ExecutionResult {
	startTime := time.Now()
	result := &ExecutionResult{
		SchemaVersion: "2.0",
		Engine:        "zeek",
		Tool:          "triage_pcap",
		PcapPath:      pcapPath,
		Status:        "completed",
		Alerts:        []StandardAlert{},
		Errors:        []ExecutionError{},
	}

	run := e.runZeek(ctx, pcapPath, scripts, extractDir, nil, nil, retainWorkDir())
	defer run.cleanup()
	e.applyRunResult(result, run, startTime, scripts, extractDir)
	result.Alerts = e.parseAlerts(run.WorkDir, scripts)
	result.Files = e.collectExtractedFiles(run.WorkDir, extractDir)
	e.persistZeekLogs(run.WorkDir, result, artifactRun)
	result.Statistics.TotalAlerts = len(result.Alerts)
	result.Statistics.TotalFiles = len(result.Files)
	return result
}

func (e *Executor) GenerateLogs(ctx context.Context, pcapPath string, logs []string, maxRecords int, artifactRun *ArtifactRun) *ExecutionResult {
	startTime := time.Now()
	result := &ExecutionResult{
		SchemaVersion: "2.0",
		Engine:        "zeek",
		Tool:          "summarize_logs",
		PcapPath:      pcapPath,
		Status:        "completed",
		Alerts:        []StandardAlert{},
		LogSummaries:  make(map[string]LogSummary),
		Errors:        []ExecutionError{},
	}

	run := e.runZeek(ctx, pcapPath, nil, "", nil, nil, retainWorkDir())
	defer run.cleanup()
	e.applyRunResult(result, run, startTime, nil, "")
	if run.WorkDir != "" {
		logDir := e.persistZeekLogs(run.WorkDir, result, artifactRun)
		if logDir == "" {
			logDir = run.WorkDir
		}
		result.LogSummaries = e.summarizeLogs(logDir, logs, maxRecords)
		result.Statistics.TotalLogs = len(result.LogSummaries)
		if run.Retained {
			result.LogPaths = e.logPaths(run.WorkDir)
		}
	}
	return result
}

func (e *Executor) RunCustomScript(ctx context.Context, pcapPath, scriptContent string, timeout time.Duration, artifactRun *ArtifactRun) *ExecutionResult {
	startTime := time.Now()
	result := &ExecutionResult{
		SchemaVersion: "2.0",
		Engine:        "zeek",
		Tool:          "run_custom_script",
		PcapPath:      pcapPath,
		Status:        "completed",
		Alerts:        []StandardAlert{},
		Errors:        []ExecutionError{},
	}

	if problems := validateCustomScriptSafety(scriptContent); len(problems) > 0 {
		result.Status = "error"
		for _, problem := range problems {
			result.Errors = append(result.Errors, ExecutionError{Script: "custom", ErrorType: "safety_check_failed", Message: problem})
		}
		result.DurationMs = time.Since(startTime).Milliseconds()
		return result
	}

	scriptPath, cleanup, err := writeTempFile("zeek_custom_*.zeek", scriptContent)
	if err != nil {
		result.Status = "error"
		result.Errors = append(result.Errors, ExecutionError{Script: "custom", ErrorType: "temp_file_error", Message: err.Error()})
		result.DurationMs = time.Since(startTime).Milliseconds()
		return result
	}
	defer cleanup()

	if errMsg := e.parseOnly(ctx, scriptPath); errMsg != "" {
		result.Status = "error"
		result.Errors = append(result.Errors, ExecutionError{Script: "custom", ErrorType: "syntax_error", Message: errMsg})
		result.DurationMs = time.Since(startTime).Milliseconds()
		return result
	}

	if timeout <= 0 {
		timeout = e.config.Timeout
	}
	customExecutor := e.WithTimeout(timeout)
	run := customExecutor.runZeek(ctx, pcapPath, []string{scriptPath}, "", nil, nil, retainWorkDir())
	defer run.cleanup()
	customExecutor.applyRunResult(result, run, startTime, []string{scriptPath}, "")
	result.Alerts = customExecutor.parseAlerts(run.WorkDir, []string{scriptPath})
	logDir := customExecutor.persistZeekLogs(run.WorkDir, result, artifactRun)
	if logDir == "" {
		logDir = run.WorkDir
	}
	result.LogSummaries = customExecutor.summarizeLogs(logDir, defaultLogNames(), envInt("ZEEK_MAX_LOG_RECORDS", 10))
	result.Statistics.TotalAlerts = len(result.Alerts)
	result.Statistics.TotalLogs = len(result.LogSummaries)
	return result
}

func (e *Executor) RunSignature(ctx context.Context, pcapPath, signaturePath string, artifactRun *ArtifactRun) *ExecutionResult {
	startTime := time.Now()
	result := &ExecutionResult{
		SchemaVersion: "2.0",
		Engine:        "zeek",
		Tool:          "hunt_signature",
		PcapPath:      pcapPath,
		Status:        "completed",
		Alerts:        []StandardAlert{},
		LogSummaries:  make(map[string]LogSummary),
		Errors:        []ExecutionError{},
	}

	if signaturePath == "" {
		result.Status = "error"
		result.Errors = append(result.Errors, ExecutionError{Script: "signature", ErrorType: "missing_signature", Message: "signature_content or signature_path is required"})
		result.DurationMs = time.Since(startTime).Milliseconds()
		return result
	}

	run := e.runZeek(ctx, pcapPath, nil, "", []string{"-s", signaturePath}, nil, retainWorkDir())
	defer run.cleanup()
	e.applyRunResult(result, run, startTime, nil, "")
	logDir := e.persistZeekLogs(run.WorkDir, result, artifactRun)
	if logDir == "" {
		logDir = run.WorkDir
	}
	result.LogSummaries = e.summarizeLogs(logDir, []string{"signatures", "notice", "conn"}, 20)
	result.Statistics.TotalLogs = len(result.LogSummaries)
	if run.Retained {
		result.LogPaths = e.logPaths(run.WorkDir)
	}
	return result
}

func (e *Executor) RunScriptsWithLogSummary(ctx context.Context, tool, pcapPath string, scripts []string, logNames []string, maxRecords int, artifactRun *ArtifactRun) *ExecutionResult {
	startTime := time.Now()
	result := &ExecutionResult{
		SchemaVersion: "2.0",
		Engine:        "zeek",
		Tool:          tool,
		PcapPath:      pcapPath,
		Status:        "completed",
		Alerts:        []StandardAlert{},
		LogSummaries:  make(map[string]LogSummary),
		Errors:        []ExecutionError{},
	}

	run := e.runZeek(ctx, pcapPath, scripts, "", nil, nil, retainWorkDir())
	defer run.cleanup()
	e.applyRunResult(result, run, startTime, scripts, "")
	result.Alerts = e.parseAlerts(run.WorkDir, scripts)
	logDir := e.persistZeekLogs(run.WorkDir, result, artifactRun)
	if logDir == "" {
		logDir = run.WorkDir
	}
	result.LogSummaries = e.summarizeLogs(logDir, logNames, maxRecords)
	result.Statistics.TotalAlerts = len(result.Alerts)
	result.Statistics.TotalLogs = len(result.LogSummaries)
	if run.Retained {
		result.LogPaths = e.logPaths(run.WorkDir)
	}
	return result
}

type zeekRun struct {
	WorkDir       string
	Stderr        string
	Err           error
	Timeout       bool
	Retained      bool
	Cleanup       func()
	Skipped       bool
	Warnings      []string
	StagingErrors []ExecutionError
}

func (run zeekRun) cleanup() {
	if run.Cleanup != nil {
		run.Cleanup()
	}
}

func (e *Executor) runZeek(ctx context.Context, pcapPath string, scripts []string, extractDir string, extraArgs []string, extraEnv []string, retain bool) zeekRun {
	run := zeekRun{Retained: retain}

	if _, err := os.Stat(pcapPath); err != nil {
		run.Err = fmt.Errorf("pcap file not found: %s", pcapPath)
		return run
	}

	workDir, err := os.MkdirTemp("", "zeek_")
	if err != nil {
		run.Err = err
		return run
	}
	run.WorkDir = workDir
	if !retain {
		run.Cleanup = func() { _ = os.RemoveAll(workDir) }
	} else {
		run.Cleanup = func() {}
	}

	localScriptPaths, stagingErrors := e.copyLocalScripts(workDir, scripts)
	run.StagingErrors = stagingErrors
	args := []string{"-C", "-r", pcapPath}
	args = append(args, extraArgs...)
	args = append(args, localScriptPaths...)

	if extractDir != "" {
		if err := os.MkdirAll(extractDir, 0755); err != nil {
			run.Err = err
			return run
		}
	}

	localZeekCfg := filepath.Join(workDir, "local.zeek")
	e.writeLocalConfig(localZeekCfg, extractDir)
	args = append(args, localZeekCfg)

	execCtx, cancel := context.WithTimeout(ctx, e.config.Timeout)
	defer cancel()

	// Acquire semaphore to limit concurrent Zeek processes.
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	case <-execCtx.Done():
		run.Err = fmt.Errorf("zeek execution throttled: %w", execCtx.Err())
		return run
	}

	cmd := exec.CommandContext(execCtx, e.config.ZeekBinary, args...)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("EXTRACTED_FILE_PATH=%s", extractDir),
		"ZEEK_LOG_JSON=true",
	)
	cmd.Env = append(cmd.Env, extraEnv...)

	var stderr strings.Builder
	cmd.Stderr = &stderr
	run.Err = cmd.Run()
	run.Stderr = stderr.String()
	run.Timeout = execCtx.Err() == context.DeadlineExceeded
	return run
}

func (e *Executor) applyRunResult(result *ExecutionResult, run zeekRun, startTime time.Time, scripts []string, extractDir string) {
	result.WorkDirRetained = run.Retained
	result.Warnings = append(result.Warnings, run.Warnings...)
	result.Errors = append(result.Errors, run.StagingErrors...)
	result.Statistics.TotalScriptsRun = len(scripts) - len(run.StagingErrors)
	if result.Statistics.TotalScriptsRun < 0 {
		result.Statistics.TotalScriptsRun = 0
	}
	if run.Retained && run.WorkDir != "" {
		result.LogPaths = e.logPaths(run.WorkDir)
	}

	if run.Skipped {
		result.Status = "completed"
		result.DurationMs = time.Since(startTime).Milliseconds()
		return
	}

	if run.Err != nil {
		if strings.Contains(run.Err.Error(), "pcap file not found") {
			result.Status = "error"
			result.Errors = append(result.Errors, ExecutionError{Script: "system", ErrorType: "file_not_found", Message: run.Err.Error()})
		} else if run.Timeout {
			result.Status = "timeout"
			result.Errors = append(result.Errors, ExecutionError{Script: "system", ErrorType: "timeout", Message: fmt.Sprintf("execution timed out after %v", e.config.Timeout)})
		} else {
			result.Status = "error"
			msg := strings.TrimSpace(fmt.Sprintf("%s: %s", run.Err.Error(), run.Stderr))
			result.Errors = append(result.Errors, ExecutionError{Script: "system", ErrorType: "execution_error", Message: msg})
		}
	}

	zeekErrors, zeekWarnings := e.parseZeekDiagnostics(run.Stderr)
	result.Errors = append(result.Errors, zeekErrors...)
	result.Warnings = append(result.Warnings, zeekWarnings...)
	result.Statistics.ScriptsWithError = len(result.Errors)
	result.DurationMs = time.Since(startTime).Milliseconds()
	if result.Status == "" {
		result.Status = "completed"
	}
	_ = extractDir
}

func (e *Executor) copyLocalScripts(workDir string, scriptPaths []string) ([]string, []ExecutionError) {
	var result []string
	var stagingErrors []ExecutionError
	for _, p := range scriptPaths {
		localPath, err := e.copyLocalScript(workDir, filepath.Base(p), filepath.Dir(p))
		if err != nil {
			stagingErrors = append(stagingErrors, ExecutionError{
				Script:    filepath.Base(p),
				ErrorType: "staging_failed",
				Message:   err.Error(),
			})
			continue
		}
		result = append(result, localPath)
	}
	return result, stagingErrors
}

func (e *Executor) copyLocalScript(workDir string, name string, srcDir string) (string, error) {
	src := filepath.Join(srcDir, name)
	if _, err := os.Stat(src); err != nil {
		return "", fmt.Errorf("script not found: %s", src)
	}

	data, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("failed to read script %s: %w", src, err)
	}

	dst := filepath.Join(workDir, name)
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return "", fmt.Errorf("failed to stage script %s: %w", src, err)
	}
	return dst, nil
}

func (e *Executor) writeLocalConfig(cfgPath, extractDir string) {
	var lines []string
	lines = append(lines, `@load policy/protocols/conn/community-id-logging`)
	lines = append(lines, `redef LogAscii::use_json = T;`)
	lines = append(lines, `redef Log::default_rotation_interval = 0 secs;`)
	if extractDir != "" {
		// Escape backslashes for Zeek string literals.
		escaped := strings.ReplaceAll(extractDir, `\`, `\\`)
		lines = append(lines, fmt.Sprintf(`redef FileExtract::prefix = "%s";`, escaped))
	}
	_ = os.WriteFile(cfgPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func (e *Executor) parseOnly(ctx context.Context, inputPath string) string {
	parseCtx, cancel := context.WithTimeout(ctx, time.Duration(envInt("ZEEK_PARSE_TIMEOUT_SECONDS", 30))*time.Second)
	defer cancel()
	cmd := exec.CommandContext(parseCtx, e.config.ZeekBinary, "--parse-only", inputPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(output))
	}
	return ""
}

func (e *Executor) parseAlerts(workDir string, scriptPaths []string) []StandardAlert {
	alerts := []StandardAlert{}
	if workDir == "" {
		return alerts
	}

	entries, err := os.ReadDir(workDir)
	if err != nil {
		return alerts
	}

	metadata := make([]*ScriptMeta, 0, len(scriptPaths))
	for _, path := range scriptPaths {
		if meta, _ := parseScriptMeta(path, ScriptTypeDetection); meta != nil {
			metadata = append(metadata, meta)
		}
	}
	flows := readConnFlowRefs(filepath.Join(workDir, "conn.log"))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "notice") && strings.HasSuffix(entry.Name(), ".log") {
			alerts = append(alerts, e.parseNoticeLog(filepath.Join(workDir, entry.Name()), metadata, flows)...)
		}
	}

	return alerts
}

func (e *Executor) parseNoticeLog(logPath string, metadata []*ScriptMeta, flows map[string]FlowRefV2) []StandardAlert {
	var alerts []StandardAlert

	f, err := os.Open(logPath)
	if err != nil {
		return alerts
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		alert := StandardAlert{
			Evidence:         make(map[string]interface{}),
			Severity:         "unknown",
			AttackTechniques: []string{},
			LogLocator: LogLocatorV2{
				Log: "notice", Path: logPath, Line: lineNumber,
				RecordSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(line))),
			},
		}

		if v, ok := entry["uid"].(string); ok {
			alert.FlowRef = flows[v]
			alert.FlowRef.ZeekUID = v
		}
		if v, ok := entry["note"].(string); ok {
			alert.Rule = v
			alert.Script = strings.Split(v, "::")[0]
		}
		if v, ok := entry["msg"].(string); ok {
			alert.Msg = v
		}
		if v, ok := entry["sub"].(string); ok {
			alert.Evidence["detail"] = v
		}
		if v, ok := entry["ts"].(float64); ok {
			alert.Timestamp = fmt.Sprintf("%.6f", v)
		}

		if v, ok := entry["id.orig_h"].(string); ok && v != "" {
			alert.Src.IP = v
			alert.Evidence["src_ip"] = v
		} else if v, ok := entry["src"].(string); ok && v != "" {
			alert.Src.IP = v
			alert.Evidence["src_ip"] = v
		}
		if v, ok := entry["id.resp_h"].(string); ok && v != "" {
			alert.Dst.IP = v
			alert.Evidence["dst_ip"] = v
		} else if v, ok := entry["dst"].(string); ok && v != "" {
			alert.Dst.IP = v
			alert.Evidence["dst_ip"] = v
		}
		if v, ok := entry["id.orig_p"].(float64); ok && int(v) > 0 {
			alert.Src.Port = int(v)
		} else if p := noticePort(entry["src_p"]); p > 0 {
			alert.Src.Port = p
		}
		if v, ok := entry["id.resp_p"].(float64); ok && int(v) > 0 {
			alert.Dst.Port = int(v)
		} else if p := noticePort(entry["dst_p"]); p > 0 {
			alert.Dst.Port = p
		}
		if v, ok := entry["proto"].(string); ok && v != "" {
			alert.Proto = v
		} else if alert.Proto == "" {
			if proto, ok := noticePortProto(entry["src_p"]); ok {
				alert.Proto = proto
			}
		}
		if alert.FlowRef.SrcIP == "" {
			alert.FlowRef.SrcIP = alert.Src.IP
			alert.FlowRef.SrcPort = alert.Src.Port
			alert.FlowRef.DstIP = alert.Dst.IP
			alert.FlowRef.DstPort = alert.Dst.Port
			alert.FlowRef.Protocol = alert.Proto
			alert.FlowRef.StartTime = alert.Timestamp
		}

		if alert.Src.IP != "" {
			alert.IOCs = &IOCInfo{IPs: []string{alert.Src.IP}}
			if alert.Dst.IP != "" {
				alert.IOCs.IPs = append(alert.IOCs.IPs, alert.Dst.IP)
			}
		}

		for _, meta := range metadata {
			if containsString(meta.NoticeTypes, alert.Rule) {
				alert.Script = meta.Name
				alert.RuleVersion = meta.RuleVersion
				alert.DetectionPack = meta.DetectionPack
				alert.DetectionPackVersion = meta.PackVersion
				alert.Category = meta.Category
				alert.Severity = meta.Severity
				alert.Confidence = meta.Confidence
				alert.AttackTechniques = append([]string{}, meta.AttackTechniques...)
				alert.ScriptChecksum = meta.Checksum
				break
			}
		}
		alert.AlertID = stableAlertID(alert)
		alerts = append(alerts, alert)
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("failed to read notice log completely; remaining records were skipped", "path", logPath, "error", err)
	}

	return alerts
}

// noticePort extracts the numeric port from Zeek notice port fields, which are
// rendered as "<port>/<proto>" strings in JSON logs (e.g. "80/tcp").
func noticePort(value interface{}) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case string:
		port, err := strconv.Atoi(strings.SplitN(v, "/", 2)[0])
		if err != nil {
			return 0
		}
		return port
	}
	return 0
}

func noticePortProto(value interface{}) (string, bool) {
	s, ok := value.(string)
	if !ok {
		return "", false
	}
	if idx := strings.Index(s, "/"); idx >= 0 && idx+1 < len(s) {
		return s[idx+1:], true
	}
	return "", false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func stableAlertID(alert StandardAlert) string {
	raw := strings.Join([]string{
		alert.Rule, alert.FlowRef.CommunityID, alert.FlowRef.ZeekUID,
		alert.Timestamp, alert.Src.IP, alert.Dst.IP,
	}, "|")
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("za_%x", sum[:10])
}

func readConnFlowRefs(path string) map[string]FlowRefV2 {
	result := map[string]FlowRefV2{}
	file, err := os.Open(path)
	if err != nil {
		return result
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var entry map[string]interface{}
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		uid, _ := entry["uid"].(string)
		if uid == "" {
			continue
		}
		flow := FlowRefV2{ZeekUID: uid}
		flow.CommunityID, _ = entry["community_id"].(string)
		flow.SrcIP, _ = entry["id.orig_h"].(string)
		flow.DstIP, _ = entry["id.resp_h"].(string)
		flow.Protocol, _ = entry["proto"].(string)
		if value, ok := entry["id.orig_p"].(float64); ok {
			flow.SrcPort = int(value)
		}
		if value, ok := entry["id.resp_p"].(float64); ok {
			flow.DstPort = int(value)
		}
		if value, ok := entry["ts"].(float64); ok {
			flow.StartTime = fmt.Sprintf("%.6f", value)
		}
		result[uid] = flow
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("failed to read conn.log completely; flow references may be incomplete", "path", path, "error", err)
	}
	return result
}

func (e *Executor) collectExtractedFiles(workDir, extractDir string) []ExtractedFile {
	var files []ExtractedFile
	if extractDir == "" {
		return files
	}

	entries, err := os.ReadDir(extractDir)
	if err != nil {
		return files
	}

	integrityByFuid := readFilesLogIntegrity(filepath.Join(workDir, "files.log"))

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".discard") || strings.HasSuffix(name, ".too_large") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		path := filepath.Join(extractDir, name)
		fuid := strings.SplitN(name, "-", 2)[0]
		integrity, ok := integrityByFuid[fuid]
		if !ok {
			integrity = "unknown"
		}
		files = append(files, ExtractedFile{
			ID: name, FUID: fuid, Name: name, Path: path, Size: info.Size(),
			SHA256: fileSHA256(path), MimeType: detectMimeType(path), Integrity: integrity,
		})
	}

	return files
}

// readFilesLogIntegrity maps fuid -> extraction integrity derived from files.log.
// A file is "incomplete" when Zeek reported missing bytes or a timeout; files
// absent from files.log are reported as "unknown" by the caller.
func readFilesLogIntegrity(path string) map[string]string {
	result := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return result
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var entry map[string]interface{}
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		fuid, _ := entry["fuid"].(string)
		if fuid == "" {
			continue
		}
		integrity := "complete"
		if missing, ok := entry["missing_bytes"].(float64); ok && missing > 0 {
			integrity = "incomplete"
		}
		if timedOut, ok := entry["timeout"].(bool); ok && timedOut {
			integrity = "incomplete"
		}
		result[fuid] = integrity
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("failed to read files.log completely; extraction integrity may be incomplete", "path", path, "error", err)
	}
	return result
}

func (e *Executor) persistZeekLogs(workDir string, result *ExecutionResult, artifactRun *ArtifactRun) string {
	if artifactRun == nil || workDir == "" {
		return ""
	}
	logPaths, err := copyLogArtifacts(workDir, artifactRun.LogsDir)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("failed to persist Zeek logs: %s", err.Error()))
		return ""
	}
	if len(logPaths) > 0 {
		result.LogPaths = logPaths
		rewriteAlertLogLocators(result.Alerts, logPaths)
	}
	return artifactRun.LogsDir
}

// rewriteAlertLogLocators points alert evidence locators at the persisted copy
// of each log so the referenced file survives temporary work directory cleanup.
func rewriteAlertLogLocators(alerts []StandardAlert, logPaths map[string]string) {
	for i := range alerts {
		if alerts[i].LogLocator.Path == "" {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(alerts[i].LogLocator.Path), ".log")
		if persisted, ok := logPaths[name]; ok {
			alerts[i].LogLocator.Path = persisted
		}
	}
}

func (e *Executor) summarizeLogs(workDir string, requested []string, maxRecords int) map[string]LogSummary {
	if maxRecords <= 0 {
		maxRecords = 20
	}
	if len(requested) == 0 {
		requested = defaultLogNames()
	}

	allowed := make(map[string]bool)
	for _, name := range requested {
		allowed[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".log")] = true
	}

	summaries := make(map[string]LogSummary)
	entries, err := os.ReadDir(workDir)
	if err != nil {
		return summaries
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".log")
		if !allowed[name] {
			continue
		}
		summaries[name] = readLogSummary(filepath.Join(workDir, entry.Name()), maxRecords)
	}
	return summaries
}

func readLogSummary(path string, maxRecords int) LogSummary {
	summary := LogSummary{Path: path}
	f, err := os.Open(path)
	if err != nil {
		return summary
	}
	defer f.Close()

	fields := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		summary.Records++
		for key := range entry {
			fields[key] = true
		}
		if len(summary.Sample) < maxRecords {
			summary.Sample = append(summary.Sample, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		summary.ReadError = err.Error()
		slog.Warn("failed to read Zeek log completely; record count is partial", "path", path, "error", err)
	}
	summary.SampleTruncated = summary.Records > len(summary.Sample)
	for key := range fields {
		summary.FieldsSeen = append(summary.FieldsSeen, key)
	}
	sort.Strings(summary.FieldsSeen)
	return summary
}

func (e *Executor) logPaths(workDir string) map[string]string {
	paths := make(map[string]string)
	entries, err := os.ReadDir(workDir)
	if err != nil {
		return paths
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".log") {
			paths[strings.TrimSuffix(entry.Name(), ".log")] = filepath.Join(workDir, entry.Name())
		}
	}
	return paths
}

func (e *Executor) parseZeekDiagnostics(stderr string) ([]ExecutionError, []string) {
	var errs []ExecutionError
	var warnings []string
	if stderr == "" {
		return errs, warnings
	}

	lines := strings.Split(stderr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "error") || strings.Contains(line, "Error") || strings.Contains(line, "fatal") || strings.Contains(line, "Fatal") {
			errs = append(errs, ExecutionError{Script: "zeek", ErrorType: "script_error", Message: line})
		} else if strings.Contains(line, "warning") || strings.Contains(line, "Warning") {
			warnings = append(warnings, line)
		}
	}

	return errs, warnings
}

func retainWorkDir() bool {
	return strings.EqualFold(os.Getenv("ZEEK_RETAIN_WORKDIR"), "true")
}

func envOrDefault(key, fallback string) string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	return raw
}

func defaultLogNames() []string {
	return []string{"analyzer", "conn", "dns", "files", "http", "notice", "rdp", "smtp", "smb", "ssh", "ssl", "tunnel", "weird", "x509"}
}

func writeTempFile(pattern, content string) (string, func(), error) {
	tmpFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", func() {}, err
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		name := tmpFile.Name()
		_ = tmpFile.Close()
		_ = os.Remove(name)
		return "", func() {}, err
	}
	if err := tmpFile.Close(); err != nil {
		name := tmpFile.Name()
		_ = os.Remove(name)
		return "", func() {}, err
	}
	return tmpFile.Name(), func() { _ = os.Remove(tmpFile.Name()) }, nil
}

// maxInputSize returns the maximum allowed size for user-supplied content (script, signature, etc.).
func maxInputSize() int {
	limit := envInt("ZEEK_MAX_SCRIPT_SIZE", 256*1024) // 256KB default
	if limit <= 0 {
		limit = 256 * 1024
	}
	return limit
}

// validateInputSize checks that the content does not exceed the configured limit.
// Returns an error message if the content is too large, or empty string if valid.
func validateInputSize(content, fieldName string) string {
	limit := maxInputSize()
	if len(content) > limit {
		return fmt.Sprintf("%s exceeds maximum allowed size (%d bytes, got %d bytes)", fieldName, limit, len(content))
	}
	return ""
}

func validateCustomScriptSafety(scriptContent string) []string {
	// Strip comments before checking to prevent bypass via commented-out code.
	cleaned := stripZeekComments(scriptContent)
	lower := strings.ToLower(cleaned)

	blocked := map[string]string{
		"system(":                       "system command execution is not allowed",
		"exec::":                        "Exec framework usage is not allowed",
		"broker::listen":                "Broker listeners are not allowed",
		"broker::peer":                  "Broker peering is not allowed",
		"supervisor::":                  "Supervisor control scripts are not allowed",
		"cluster::":                     "Cluster control scripts are not allowed",
		"@load base/frameworks/cluster": "Cluster framework loading is not allowed",
	}

	var problems []string
	for pattern, message := range blocked {
		if strings.Contains(lower, pattern) {
			problems = append(problems, message)
		}
	}
	sort.Strings(problems)
	return problems
}

// stripZeekComments removes Zeek comments (# to end of line) from script content.
func stripZeekComments(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	for _, line := range lines {
		// Find the first # outside of a string literal (simple heuristic).
		idx := strings.Index(line, "#")
		if idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}
