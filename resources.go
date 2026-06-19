package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func (h *Handler) registerResources(s *server.MCPServer) {
	s.AddResource(
		mcp.NewResource("zeek://pcaps", "Available PCAPs",
			mcp.WithMIMEType("application/json"),
			mcp.WithResourceDescription("PCAP files from configured intake directories. Returned path values are directly usable as pcap_path.")),
		func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			var pcaps []map[string]interface{}
			for _, dir := range h.paths.RecommendedIntakeDirs() {
				pcaps = append(pcaps, listPcaps(dir)...)
			}
			return jsonResource("zeek://pcaps", map[string]interface{}{"pcaps": pcaps}), nil
		},
	)

	s.AddResource(
		mcp.NewResource("zeek://scripts/detections", "Detection Scripts",
			mcp.WithMIMEType("application/json"),
			mcp.WithResourceDescription("Enabled Zeek detection scripts that can be passed to triage_pcap.")),
		func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			resp := map[string]interface{}{
				"scripts": h.registry.ListScripts(ListScriptsRequest{Type: ScriptTypeDetection, EnabledOnly: true}),
			}
			return jsonResource("zeek://scripts/detections", resp), nil
		},
	)

	s.AddResourceTemplate(
		mcp.NewResourceTemplate("zeek://scripts/{id}", "Script Detail",
			mcp.WithTemplateMIMEType("application/json"),
			mcp.WithTemplateDescription("Metadata and source for a bundled Zeek script. Replace {id} with a script name or ScriptID.")),
		func (ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			scriptName := strings.TrimPrefix(request.Params.URI, "zeek://scripts/")
			if scriptName == "" || scriptName == request.Params.URI {
				return nil, fmt.Errorf("script id is required")
			}
			meta := h.registry.GetScript(scriptName)
			if meta == nil {
				return nil, fmt.Errorf("script not found: %s", scriptName)
			}
			resp := map[string]interface{}{
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
			if data, err := os.ReadFile(meta.FilePath); err == nil {
				resp["source"] = string(data)
			}
			return jsonResource(fmt.Sprintf("zeek://scripts/%s", scriptName), resp), nil
		},
	)

	s.AddResource(
		mcp.NewResource("zeek://runs", "Analysis Runs",
			mcp.WithMIMEType("application/json"),
			mcp.WithResourceDescription("Recent analysis run manifests from the configured output directory.")),
		func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			root, err := h.resolveOutputRoot(map[string]interface{}{})
			if err != nil {
				return jsonResource("zeek://runs", map[string]interface{}{"runs": []AnalysisRunSummary{}, "error": err.Error()}), nil
			}
			var runs []AnalysisRunSummary
			for _, candidate := range loadRunCleanupCandidates(filepath.Join(root, "runs")) {
				runs = append(runs, AnalysisRunSummary{
					RunID:         candidate.RunID,
					CreatedAt:     candidate.CreatedAt,
					ManifestPath:  candidate.ManifestPath,
					ArtifactBytes: candidate.ArtifactBytes,
				})
			}
			return jsonResource("zeek://runs", map[string]interface{}{"runs": runs, "output_dir": root}), nil
		},
	)
}

func jsonResource(uri string, value any) []mcp.ResourceContents {
	data, _ := json.MarshalIndent(value, "", "  ")
	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      uri,
			MIMEType: "application/json",
			Text:     string(data),
		},
	}
}
