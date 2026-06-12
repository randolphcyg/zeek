package main

import (
	"context"
	"encoding/json"
	"path/filepath"

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
			mcp.WithResourceDescription("Enabled Zeek detection scripts that can be passed to detect_threats.")),
		func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			resp := map[string]interface{}{
				"scripts": h.registry.ListScripts(ListScriptsRequest{Type: ScriptTypeDetection, EnabledOnly: true}),
			}
			return jsonResource("zeek://scripts/detections", resp), nil
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
