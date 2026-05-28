package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ScriptTypeDetection  = "detection"
	ScriptTypeExtraction = "extraction"
	ScriptTypeUtility    = "utility"
)

type ScriptMeta struct {
	Name        string   `json:"name"`
	ScriptID    string   `json:"script_id"`
	FilePath    string   `json:"file_path"`
	NoticeTypes []string `json:"notice_types,omitempty"`
	Type        string   `json:"type"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Signature   string   `json:"signature"`
	Size        string   `json:"size"`
	Checksum    string   `json:"checksum"`
	UpdatedAt   string   `json:"updated_at"`
	Enabled     bool     `json:"enabled"`
	Valid       bool     `json:"valid"`
	Error       string   `json:"error,omitempty"`
}

type ScriptRegistry struct {
	mu         sync.RWMutex
	scriptsDir string
	scripts    map[string]*ScriptMeta
}

var (
	reScriptID          = regexp.MustCompile(`^#\s*(?:ScriptID|SCRIPT_ID)\s*:\s*(.+)$`)
	reNoticeTypes       = regexp.MustCompile(`^#\s*NoticeTypes\s*:\s*(.+)$`)
	reType              = regexp.MustCompile(`^#\s*Type\s*:\s*(.+)$`)
	reCategory          = regexp.MustCompile(`^#\s*Category\s*:\s*(.+)$`)
	reDescription       = regexp.MustCompile(`^#\s*Description\s*:\s*(.+)$`)
	reSignature         = regexp.MustCompile(`^#\s*Signature\s*:\s*(.+)$`)
	reEnabled           = regexp.MustCompile(`^#\s*Enabled\s*:\s*(.+)$`)
	reLegacyType        = regexp.MustCompile(`^#\s*行为类型[：:]\s*(.+)$`)
	reLegacyCategory    = regexp.MustCompile(`^#\s*行为分类[：:]\s*(.+)$`)
	reLegacyDescription = regexp.MustCompile(`^#\s*行为描述[：:]\s*(.+)$`)
	reLegacySignature   = regexp.MustCompile(`^#\s*攻击特征[：:]\s*(.+)$`)
)

func NewScriptRegistry(scriptsDir string) *ScriptRegistry {
	return &ScriptRegistry{
		scriptsDir: scriptsDir,
		scripts:    make(map[string]*ScriptMeta),
	}
}

func (sr *ScriptRegistry) Scan() error {
	_, err := sr.Reload()
	return err
}

func (sr *ScriptRegistry) Reload() (reloadResult, error) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	sr.scripts = make(map[string]*ScriptMeta)

	if _, err := os.Stat(sr.scriptsDir); os.IsNotExist(err) {
		return reloadResult{}, nil
	}

	total, valid, invalid := 0, 0, 0
	err := filepath.WalkDir(sr.scriptsDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".zeek") {
			return nil
		}

		total++
		meta, err := parseScriptMeta(path, sr.inferTypeFromPath(path))
		if err != nil {
			invalid++
		} else {
			valid++
		}
		sr.scripts[meta.ScriptID] = meta
		return nil
	})
	if err != nil {
		return reloadResult{}, fmt.Errorf("failed to scan scripts dir: %w", err)
	}

	return reloadResult{
		Total:   total,
		Valid:   valid,
		Invalid: invalid,
	}, nil
}

func (sr *ScriptRegistry) inferTypeFromPath(filePath string) string {
	rel, err := filepath.Rel(sr.scriptsDir, filePath)
	if err != nil {
		return ScriptTypeDetection
	}
	first := strings.ToLower(strings.Split(filepath.ToSlash(rel), "/")[0])
	switch first {
	case "detections":
		return ScriptTypeDetection
	case "extraction":
		return ScriptTypeExtraction
	case "utilities":
		return ScriptTypeUtility
	default:
		return ScriptTypeDetection
	}
}

type reloadResult struct {
	Total   int `json:"total"`
	Valid   int `json:"valid"`
	Invalid int `json:"invalid"`
}

func parseScriptMeta(filePath string, inferredType string) (*ScriptMeta, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return &ScriptMeta{
			Name:    strings.TrimSuffix(filepath.Base(filePath), ".zeek"),
			Type:    inferredType,
			Enabled: false,
			Valid:   false,
			Error:   err.Error(),
		}, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)

	meta := &ScriptMeta{
		Name:      strings.TrimSuffix(filepath.Base(filePath), ".zeek"),
		FilePath:  filePath,
		Type:      inferredType,
		Category:  inferredType,
		Size:      humanSize(stat.Size()),
		Checksum:  hex.EncodeToString(hash[:]),
		UpdatedAt: stat.ModTime().Format(time.RFC3339),
		Enabled:   true,
		Valid:     true,
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if m := reScriptID.FindStringSubmatch(line); m != nil {
			meta.ScriptID = strings.TrimSpace(m[1])
		}
		if m := reNoticeTypes.FindStringSubmatch(line); m != nil {
			meta.NoticeTypes = splitCSV(m[1])
		}
		if m := reType.FindStringSubmatch(line); m != nil {
			meta.Type = normalizeScriptType(m[1], inferredType)
		}
		if m := reCategory.FindStringSubmatch(line); m != nil {
			meta.Category = strings.TrimSpace(m[1])
		}
		if m := reDescription.FindStringSubmatch(line); m != nil {
			meta.Description = strings.TrimSpace(m[1])
		}
		if m := reSignature.FindStringSubmatch(line); m != nil {
			meta.Signature = strings.TrimSpace(m[1])
		}
		if m := reEnabled.FindStringSubmatch(line); m != nil {
			meta.Enabled = parseBoolDefault(m[1], true)
		}

		if meta.Type == inferredType {
			if m := reLegacyType.FindStringSubmatch(line); m != nil {
				meta.Type = inferredType
			}
		}
		if meta.Category == inferredType {
			if m := reLegacyCategory.FindStringSubmatch(line); m != nil {
				meta.Category = strings.TrimSpace(m[1])
			}
		}
		if meta.Description == "" {
			if m := reLegacyDescription.FindStringSubmatch(line); m != nil {
				meta.Description = strings.TrimSpace(m[1])
			}
		}
		if meta.Signature == "" {
			if m := reLegacySignature.FindStringSubmatch(line); m != nil {
				meta.Signature = strings.TrimSpace(m[1])
			}
		}
	}
	if err := scanner.Err(); err != nil {
		meta.Valid = false
		meta.Error = err.Error()
		return meta, err
	}

	if meta.ScriptID == "" {
		meta.ScriptID = meta.Name
	}
	if meta.Description == "" {
		meta.Description = fmt.Sprintf("%s Zeek script", titleScriptType(meta.Type))
	}

	return meta, nil
}

func normalizeScriptType(raw string, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case ScriptTypeDetection, "detect":
		return ScriptTypeDetection
	case ScriptTypeExtraction, "extract":
		return ScriptTypeExtraction
	case ScriptTypeUtility, "util":
		return ScriptTypeUtility
	default:
		return fallback
	}
}

func splitCSV(raw string) []string {
	var result []string
	for _, item := range strings.Split(strings.TrimSpace(raw), ",") {
		if value := strings.TrimSpace(item); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func parseBoolDefault(raw string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "yes", "1", "enabled":
		return true
	case "false", "no", "0", "disabled":
		return false
	default:
		return fallback
	}
}

func titleScriptType(scriptType string) string {
	if scriptType == "" {
		return "Unknown"
	}
	return strings.ToUpper(scriptType[:1]) + scriptType[1:]
}

type ListScriptsRequest struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Type        string `json:"type"`
	EnabledOnly bool   `json:"enabled_only"`
}

func (sr *ScriptRegistry) ListScripts(req ListScriptsRequest) []*ScriptMeta {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	var result []*ScriptMeta
	nameLower := strings.ToLower(strings.TrimSpace(req.Name))
	categoryLower := strings.ToLower(strings.TrimSpace(req.Category))
	typeLower := strings.ToLower(strings.TrimSpace(req.Type))

	for _, meta := range sr.scripts {
		if req.EnabledOnly && (!meta.Enabled || !meta.Valid) {
			continue
		}
		if typeLower != "" && strings.ToLower(meta.Type) != typeLower {
			continue
		}
		if nameLower != "" {
			if !strings.Contains(strings.ToLower(meta.Name), nameLower) &&
				!strings.Contains(strings.ToLower(meta.ScriptID), nameLower) {
				continue
			}
		}
		if categoryLower != "" {
			if !strings.Contains(strings.ToLower(meta.Category), categoryLower) {
				continue
			}
		}
		result = append(result, meta)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		return result[i].Name < result[j].Name
	})

	return result
}

func (sr *ScriptRegistry) GetScript(nameOrID string) *ScriptMeta {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return sr.getScriptLocked(nameOrID)
}

func (sr *ScriptRegistry) getScriptLocked(nameOrID string) *ScriptMeta {
	if meta, ok := sr.scripts[nameOrID]; ok {
		return meta
	}
	for _, meta := range sr.scripts {
		if meta.Name == nameOrID || strings.EqualFold(meta.ScriptID, nameOrID) || strings.EqualFold(meta.Name, nameOrID) {
			return meta
		}
	}
	return nil
}

func (sr *ScriptRegistry) GetScriptPaths(names []string, scriptType string) []string {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	typeLower := strings.ToLower(strings.TrimSpace(scriptType))
	if len(names) == 0 {
		var all []string
		for _, meta := range sr.scripts {
			if meta.Valid && meta.Enabled && (typeLower == "" || meta.Type == typeLower) {
				all = append(all, meta.FilePath)
			}
		}
		sort.Strings(all)
		return all
	}

	seen := make(map[string]bool)
	var paths []string
	for _, name := range names {
		meta := sr.getScriptLocked(name)
		if meta == nil || !meta.Valid || !meta.Enabled {
			continue
		}
		if typeLower != "" && meta.Type != typeLower {
			continue
		}
		if !seen[meta.FilePath] {
			paths = append(paths, meta.FilePath)
			seen[meta.FilePath] = true
		}
	}
	return paths
}

func humanSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
