package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	defaultZeekTimeout = 120 * time.Second
	defaultZeekBinary  = "zeek"
)

type ExecutorConfig struct {
	ZeekBinary string
	Timeout    time.Duration
}

type ExecutionResult struct {
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
	AlertID    string                 `json:"alert_id"`
	Script     string                 `json:"script"`
	Rule       string                 `json:"rule"`
	Confidence float64                `json:"confidence"`
	Severity   string                 `json:"severity"`
	Timestamp  string                 `json:"timestamp"`
	Src        EndpointInfo           `json:"src"`
	Dst        EndpointInfo           `json:"dst"`
	Proto      string                 `json:"proto"`
	Evidence   map[string]interface{} `json:"evidence,omitempty"`
	IOCs       *IOCInfo               `json:"iocs,omitempty"`
	Msg        string                 `json:"msg"`
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
	ID       string `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	MimeType string `json:"mime_type,omitempty"`
}

type LogSummary struct {
	Path       string                   `json:"path,omitempty"`
	Records    int                      `json:"records"`
	Sample     []map[string]interface{} `json:"sample"`
	FieldsSeen []string                 `json:"fields_seen,omitempty"`
}

type Executor struct {
	config ExecutorConfig
}

func NewExecutor(config ExecutorConfig) *Executor {
	if config.ZeekBinary == "" {
		config.ZeekBinary = defaultZeekBinary
	}
	if config.Timeout == 0 {
		config.Timeout = defaultZeekTimeout
	}
	return &Executor{config: config}
}

func (e *Executor) RunDetection(ctx context.Context, pcapPath string, scripts []string, extractDir string, artifactRun *ArtifactRun) *ExecutionResult {
	startTime := time.Now()
	result := &ExecutionResult{
		Tool:     "zeek_run_detection",
		PcapPath: pcapPath,
		Status:   "completed",
		Alerts:   []StandardAlert{},
		Errors:   []ExecutionError{},
	}

	run := e.runZeek(ctx, pcapPath, scripts, extractDir, nil, nil, retainWorkDir())
	defer run.cleanup()
	e.applyRunResult(result, run, startTime, scripts, extractDir)
	result.Alerts = e.parseAlerts(run.WorkDir, scripts)
	result.Files = e.collectExtractedFiles(extractDir)
	e.persistZeekLogs(run.WorkDir, result, artifactRun)
	result.Statistics.TotalAlerts = len(result.Alerts)
	result.Statistics.TotalFiles = len(result.Files)
	return result
}

func (e *Executor) GenerateLogs(ctx context.Context, pcapPath string, logs []string, maxRecords int, artifactRun *ArtifactRun) *ExecutionResult {
	startTime := time.Now()
	result := &ExecutionResult{
		Tool:         "zeek_generate_logs",
		PcapPath:     pcapPath,
		Status:       "completed",
		Alerts:       []StandardAlert{},
		LogSummaries: make(map[string]LogSummary),
		Errors:       []ExecutionError{},
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
		Tool:     "zeek_run_custom_script",
		PcapPath: pcapPath,
		Status:   "completed",
		Alerts:   []StandardAlert{},
		Errors:   []ExecutionError{},
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
	customExecutor := *e
	customExecutor.config.Timeout = timeout
	run := customExecutor.runZeek(ctx, pcapPath, []string{scriptPath}, "", nil, nil, retainWorkDir())
	defer run.cleanup()
	customExecutor.applyRunResult(result, run, startTime, []string{scriptPath}, "")
	result.Alerts = customExecutor.parseAlerts(run.WorkDir, []string{scriptPath})
	logDir := customExecutor.persistZeekLogs(run.WorkDir, result, artifactRun)
	if logDir == "" {
		logDir = run.WorkDir
	}
	result.LogSummaries = customExecutor.summarizeLogs(logDir, defaultLogNames(), 10)
	result.Statistics.TotalAlerts = len(result.Alerts)
	result.Statistics.TotalLogs = len(result.LogSummaries)
	return result
}

func (e *Executor) RunSignature(ctx context.Context, pcapPath, signaturePath string, artifactRun *ArtifactRun) *ExecutionResult {
	startTime := time.Now()
	result := &ExecutionResult{
		Tool:         "zeek_run_signature",
		PcapPath:     pcapPath,
		Status:       "completed",
		Alerts:       []StandardAlert{},
		LogSummaries: make(map[string]LogSummary),
		Errors:       []ExecutionError{},
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
		Tool:         tool,
		PcapPath:     pcapPath,
		Status:       "completed",
		Alerts:       []StandardAlert{},
		LogSummaries: make(map[string]LogSummary),
		Errors:       []ExecutionError{},
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
	WorkDir  string
	Stderr   string
	Err      error
	Timeout  bool
	Retained bool
	Cleanup  func()
	Skipped  bool
	Warnings []string
}

func (run zeekRun) cleanup() {
	if run.Cleanup != nil {
		run.Cleanup()
	}
}

func (e *Executor) runZeek(ctx context.Context, pcapPath string, scripts []string, extractDir string, extraArgs []string, extraEnv []string, retain bool) zeekRun {
	run := zeekRun{Retained: retain}

	info, err := GetPcapInfo(pcapPath)
	if err != nil {
		run.Err = err
		return run
	}
	if !info.Analyzable {
		run.Skipped = true
		run.Warnings = append(run.Warnings, info.Warnings...)
		run.Cleanup = func() {}
		return run
	}

	workDir, err := os.MkdirTemp("", "zeek_mcp_")
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

	localScriptPaths := e.copyLocalScripts(workDir, scripts)
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
	result.Statistics.TotalScriptsRun = len(scripts)
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

func (e *Executor) copyLocalScripts(workDir string, scriptPaths []string) []string {
	var result []string
	for _, p := range scriptPaths {
		localPath := e.copyLocalScript(workDir, filepath.Base(p), filepath.Dir(p))
		if localPath != "" {
			result = append(result, localPath)
		}
	}
	return result
}

func (e *Executor) copyLocalScript(workDir string, name string, srcDir string) string {
	src := filepath.Join(srcDir, name)
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return ""
	}

	data, err := os.ReadFile(src)
	if err != nil {
		return ""
	}

	dst := filepath.Join(workDir, name)
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return ""
	}
	return dst
}

func (e *Executor) writeLocalConfig(cfgPath, extractDir string) {
	var lines []string
	lines = append(lines, `redef LogAscii::use_json = T;`)
	lines = append(lines, `redef Log::default_rotation_interval = 0 secs;`)
	if extractDir != "" {
		lines = append(lines, fmt.Sprintf(`redef FileExtract::prefix = "%s";`, extractDir))
	}
	_ = os.WriteFile(cfgPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func (e *Executor) parseOnly(ctx context.Context, inputPath string) string {
	cmd := exec.CommandContext(ctx, e.config.ZeekBinary, "--parse-only", inputPath)
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

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "notice") && strings.HasSuffix(entry.Name(), ".log") {
			alerts = append(alerts, e.parseNoticeLog(filepath.Join(workDir, entry.Name()))...)
		}
	}

	return alerts
}

func (e *Executor) parseNoticeLog(logPath string) []StandardAlert {
	var alerts []StandardAlert

	f, err := os.Open(logPath)
	if err != nil {
		return alerts
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		alert := StandardAlert{
			Evidence:   make(map[string]interface{}),
			Confidence: 0.85,
		}

		if v, ok := entry["uid"].(string); ok {
			alert.AlertID = v
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

		if v, ok := entry["id.orig_h"].(string); ok {
			alert.Src.IP = v
			alert.Evidence["src_ip"] = v
		}
		if v, ok := entry["id.resp_h"].(string); ok {
			alert.Dst.IP = v
			alert.Evidence["dst_ip"] = v
		}
		if v, ok := entry["id.orig_p"].(float64); ok {
			alert.Src.Port = int(v)
		}
		if v, ok := entry["id.resp_p"].(float64); ok {
			alert.Dst.Port = int(v)
		}
		if v, ok := entry["proto"].(string); ok {
			alert.Proto = v
		}

		if alert.Src.IP != "" {
			alert.IOCs = &IOCInfo{IPs: []string{alert.Src.IP}}
			if alert.Dst.IP != "" {
				alert.IOCs.IPs = append(alert.IOCs.IPs, alert.Dst.IP)
			}
		}

		alert.determineConfidenceAndSeverity()
		alerts = append(alerts, alert)
	}

	return alerts
}

func (a *StandardAlert) determineConfidenceAndSeverity() {
	ruleLower := strings.ToLower(a.Rule)
	msgLower := strings.ToLower(a.Msg)

	highConfKeywords := []string{"bruteforce", "password_guessing", "exploit", "injection", "overflow", "shell", "backdoor", "ransomware", "apt", "c2", "beacon"}
	mediumConfKeywords := []string{"scan", "flood", "flooding", "anomaly", "suspicious", "abnormal", "policy", "recon"}
	lowConfKeywords := []string{"info", "notice", "dns", "connection"}

	for _, kw := range highConfKeywords {
		if strings.Contains(ruleLower, kw) || strings.Contains(msgLower, kw) {
			a.Confidence = 0.95
			a.Severity = "high"
			return
		}
	}
	for _, kw := range mediumConfKeywords {
		if strings.Contains(ruleLower, kw) || strings.Contains(msgLower, kw) {
			a.Confidence = 0.75
			a.Severity = "medium"
			return
		}
	}
	for _, kw := range lowConfKeywords {
		if strings.Contains(ruleLower, kw) || strings.Contains(msgLower, kw) {
			a.Confidence = 0.55
			a.Severity = "low"
			return
		}
	}

	a.Severity = "info"
	a.Confidence = 0.4
}

func (e *Executor) collectExtractedFiles(extractDir string) []ExtractedFile {
	var files []ExtractedFile
	if extractDir == "" {
		return files
	}

	entries, err := os.ReadDir(extractDir)
	if err != nil {
		return files
	}

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

		files = append(files, ExtractedFile{
			ID:       name,
			Name:     name,
			Path:     filepath.Join(extractDir, name),
			Size:     info.Size(),
			MimeType: detectMimeType(filepath.Join(extractDir, name)),
		})
	}

	return files
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
	}
	return artifactRun.LogsDir
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
	return strings.EqualFold(os.Getenv("ZEEK_MCP_RETAIN_WORKDIR"), "true")
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

func validateCustomScriptSafety(scriptContent string) []string {
	lower := strings.ToLower(scriptContent)
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
