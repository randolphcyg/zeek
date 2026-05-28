package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ArtifactRun struct {
	RunID        string
	Root         string
	RunDir       string
	LogsDir      string
	ExtractedDir string
	ReportsDir   string
	ManifestPath string
	CreatedAt    string
}

type Artifact struct {
	Kind         string `json:"kind"`
	Path         string `json:"path"`
	RelativePath string `json:"relative_path"`
	SHA256       string `json:"sha256,omitempty"`
	Size         int64  `json:"size"`
	MimeType     string `json:"mime_type,omitempty"`
	SourceTool   string `json:"source_tool"`
	Description  string `json:"description,omitempty"`
}

type ArtifactManifest struct {
	RunID             string          `json:"run_id"`
	CreatedAt         string          `json:"created_at"`
	Tool              string          `json:"tool"`
	RequestedPcapPath string          `json:"requested_pcap_path,omitempty"`
	ResolvedPcapPath  string          `json:"resolved_pcap_path,omitempty"`
	ZeekVersion       string          `json:"zeek_version,omitempty"`
	Status            string          `json:"status"`
	Artifacts         []Artifact      `json:"artifacts"`
	ArtifactBytes     int64           `json:"artifact_bytes"`
	Retention         RetentionInfo   `json:"retention"`
	FindingsSummary   FindingsSummary `json:"findings_summary"`
}

type RetentionInfo struct {
	CreatedAt       string `json:"created_at"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	CleanupEligible bool   `json:"cleanup_eligible"`
}

type FindingsSummary struct {
	Alerts         int `json:"alerts"`
	ExtractedFiles int `json:"extracted_files"`
	Logs           int `json:"logs"`
	Errors         int `json:"errors"`
}

type AnalysisRunSummary struct {
	RunID             string          `json:"run_id"`
	CreatedAt         string          `json:"created_at"`
	Tool              string          `json:"tool"`
	Status            string          `json:"status"`
	ManifestPath      string          `json:"manifest_path"`
	RequestedPcapPath string          `json:"requested_pcap_path,omitempty"`
	ResolvedPcapPath  string          `json:"resolved_pcap_path,omitempty"`
	ArtifactCount     int             `json:"artifact_count"`
	ArtifactBytes     int64           `json:"artifact_bytes"`
	FindingsSummary   FindingsSummary `json:"findings_summary"`
}

type CleanupCandidate struct {
	RunID         string `json:"run_id"`
	ManifestPath  string `json:"manifest_path"`
	RunDir        string `json:"run_dir"`
	CreatedAt     string `json:"created_at"`
	ArtifactBytes int64  `json:"artifact_bytes"`
	Reason        string `json:"reason"`
	Deleted       bool   `json:"deleted"`
	Error         string `json:"error,omitempty"`
}

type CleanupResult struct {
	Tool             string             `json:"tool"`
	OutputDir        string             `json:"output_dir"`
	DryRun           bool               `json:"dry_run"`
	Confirmed        bool               `json:"confirmed"`
	OlderThanDays    int                `json:"older_than_days,omitempty"`
	MaxTotalBytes    int64              `json:"max_total_bytes,omitempty"`
	TotalRuns        int                `json:"total_runs"`
	TotalBytesBefore int64              `json:"total_bytes_before"`
	TotalBytesAfter  int64              `json:"total_bytes_after"`
	CandidateRuns    int                `json:"candidate_runs"`
	DeletedRuns      int                `json:"deleted_runs"`
	BytesToDelete    int64              `json:"bytes_to_delete"`
	DeletedBytes     int64              `json:"deleted_bytes"`
	Candidates       []CleanupCandidate `json:"candidates"`
}

func prepareArtifactRun(outputRoot string) (*ArtifactRun, error) {
	runID := newRunID()
	runDir := filepath.Join(outputRoot, "runs", runID)
	run := &ArtifactRun{
		RunID:        runID,
		Root:         outputRoot,
		RunDir:       runDir,
		LogsDir:      filepath.Join(runDir, "logs"),
		ExtractedDir: filepath.Join(runDir, "extracted"),
		ReportsDir:   filepath.Join(runDir, "reports"),
		ManifestPath: filepath.Join(runDir, "manifest.json"),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	for _, dir := range []string{run.LogsDir, run.ExtractedDir, run.ReportsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}
	return run, nil
}

func newRunID() string {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("%s_%d", time.Now().UTC().Format("20060102T150405Z"), time.Now().UnixNano())
	}
	return fmt.Sprintf("%s_%s", time.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(random))
}

func copyLogArtifacts(workDir, logsDir string) (map[string]string, error) {
	paths := make(map[string]string)
	if workDir == "" || logsDir == "" {
		return paths, nil
	}
	entries, err := os.ReadDir(workDir)
	if err != nil {
		return paths, nil
	}
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return paths, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}
		src := filepath.Join(workDir, entry.Name())
		dst := filepath.Join(logsDir, entry.Name())
		if err := copyFile(src, dst); err != nil {
			return paths, err
		}
		paths[strings.TrimSuffix(entry.Name(), ".log")] = dst
	}
	return paths, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func buildArtifacts(run *ArtifactRun, tool string) []Artifact {
	if run == nil {
		return []Artifact{}
	}
	var artifacts []Artifact
	artifacts = append(artifacts, scanArtifactDir(run.LogsDir, run.RunDir, "zeek_log", tool, "Zeek JSON log")...)
	artifacts = append(artifacts, scanArtifactDir(run.ExtractedDir, run.RunDir, "extracted_file", tool, "File extracted by Zeek File Analysis")...)
	if artifacts == nil {
		return []Artifact{}
	}
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].RelativePath < artifacts[j].RelativePath
	})
	return artifacts
}

func artifactBytes(artifacts []Artifact) int64 {
	var total int64
	for _, artifact := range artifacts {
		total += artifact.Size
	}
	return total
}

func runDirSize(runDir string) int64 {
	var total int64
	_ = filepath.WalkDir(runDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func scanArtifactDir(dir, baseDir, kind, sourceTool, description string) []Artifact {
	var artifacts []Artifact
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		if filepath.Base(path) == "manifest.json" {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(baseDir, path)
		if err != nil {
			rel = path
		}
		artifacts = append(artifacts, Artifact{
			Kind:         kind,
			Path:         path,
			RelativePath: rel,
			SHA256:       fileSHA256(path),
			Size:         info.Size(),
			MimeType:     detectMimeType(path),
			SourceTool:   sourceTool,
			Description:  description,
		})
		return nil
	})
	if artifacts == nil {
		return []Artifact{}
	}
	return artifacts
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func detectMimeType(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	if n == 0 {
		return ""
	}
	return http.DetectContentType(buf[:n])
}

func writeArtifactManifest(path string, manifest ArtifactManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func readArtifactManifest(path string) (*ArtifactManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest ArtifactManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}
