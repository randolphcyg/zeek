package main

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

type progressKey struct{}

func withProgressToken(ctx context.Context, token mcp.ProgressToken) context.Context {
	if token == nil {
		return ctx
	}
	return context.WithValue(ctx, progressKey{}, token)
}

func getProgressToken(ctx context.Context) mcp.ProgressToken {
	token, _ := ctx.Value(progressKey{}).(mcp.ProgressToken)
	return token
}

// sendProgress sends an MCP progress notification to the client that initiated the request.
// total is optional (nil means unknown). progress should be between 0.0 and 1.0.
func (h *Handler) sendProgress(ctx context.Context, progress float64, total *float64, message string) {
	if h.mcpServer == nil {
		return
	}
	token := getProgressToken(ctx)
	if token == nil {
		return
	}
	params := map[string]any{
		"progressToken": token,
		"progress":      progress,
	}
	if total != nil {
		params["total"] = *total
	}
	if message != "" {
		params["message"] = message
	}
	_ = h.mcpServer.SendNotificationToClient(ctx, "notifications/progress", params)
}

// formatProgressMessage creates a human-readable progress message for triage_pcap.
func formatProgressMessage(phase string, completed, total int, alerts int) string {
	switch phase {
	case "start":
		return fmt.Sprintf("Starting pcap analysis with %d detection scripts...", total)
	case "zeek":
		return fmt.Sprintf("Zeek running %d detection scripts...", total)
	case "parse":
		return fmt.Sprintf("Parsing results: found %d alerts so far...", alerts)
	case "extract":
		return "Collecting extracted files..."
	case "complete":
		if alerts > 0 {
			return fmt.Sprintf("Analysis complete: %d alerts detected from %d scripts.", alerts, total)
		}
		return fmt.Sprintf("Analysis complete: %d scripts executed, no alerts detected.", total)
	default:
		return phase
	}
}