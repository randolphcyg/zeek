package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

var cliCommands = map[string]bool{
	"analyze_pcap": true, "query_logs": true, "hunt_intel": true,
	"extract_files": true, "validate_script": true, "run_custom_script": true,
}

func isCLICommand(name string) bool { return cliCommands[name] }

// runCLI deliberately dispatches through the same Handler used by MCP. This
// keeps validation, schemas, execution, artifacts, and ToolResultV2 semantics
// identical across transports.
func runCLI(command string, argv []string) int {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	argsJSON := fs.String("args-json", "", "complete JSON object containing tool arguments")
	pcapPath := fs.String("pcap-path", "", "PCAP path")
	profile := fs.String("profile", "", "analysis profile: baseline, standard, or full")
	runID := fs.String("run-id", "", "persisted run identifier")
	logName := fs.String("log", "", "Zeek log name")
	outputDir := fs.String("output-dir", "", "artifact output root")
	cursor := fs.String("cursor", "", "pagination cursor")
	aggregate := fs.String("aggregate", "", "query aggregation")
	selectFields := fs.String("select", "", "comma-separated selected log fields")
	predicatesJSON := fs.String("predicates-json", "", "JSON object of equality predicates")
	limit := fs.Int("limit", 0, "result limit")
	extractFiles := fs.Bool("extract-files", false, "extract transferred files")
	if err := fs.Parse(argv); err != nil {
		return 2
	}

	args := map[string]interface{}{}
	if *argsJSON != "" {
		if err := json.Unmarshal([]byte(*argsJSON), &args); err != nil {
			fmt.Fprintf(os.Stderr, "invalid --args-json: %v\n", err)
			return 2
		}
	}
	setStringArg(args, "pcap_path", *pcapPath)
	setStringArg(args, "profile", *profile)
	setStringArg(args, "run_id", *runID)
	setStringArg(args, "log", *logName)
	setStringArg(args, "output_dir", *outputDir)
	setStringArg(args, "cursor", *cursor)
	setStringArg(args, "aggregate", *aggregate)
	if *selectFields != "" {
		args["select"] = strings.Split(*selectFields, ",")
	}
	if *predicatesJSON != "" {
		var predicates map[string]interface{}
		if err := json.Unmarshal([]byte(*predicatesJSON), &predicates); err != nil {
			fmt.Fprintf(os.Stderr, "invalid --predicates-json: %v\n", err)
			return 2
		}
		args["predicates"] = predicates
	}
	if *limit > 0 {
		args["limit"] = *limit
	}
	if *extractFiles {
		args["extract_files"] = true
	}

	baseDir := os.Getenv("ZEEK_BASE_DIR")
	if baseDir == "" {
		baseDir, _ = os.Getwd()
	}
	scriptsDir := os.Getenv("ZEEK_SCRIPTS_DIR")
	if scriptsDir == "" {
		scriptsDir = filepath.Join(baseDir, "scripts")
	}
	pathMaps, err := ParsePathMaps(nil, os.Getenv("ZEEK_PATH_MAPS"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ms := NewMCPServer(baseDir, scriptsDir, pathMaps)
	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: command, Arguments: args},
	}
	result, err := ms.handler.dispatchTool(context.Background(), req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	semanticError := result.IsError
	for _, content := range result.Content {
		if text, ok := content.(mcp.TextContent); ok {
			fmt.Println(text.Text)
			var envelope map[string]interface{}
			if json.Unmarshal([]byte(text.Text), &envelope) == nil {
				switch envelope["status"] {
				case "error", "timeout", "unavailable":
					semanticError = true
				}
			}
		}
	}
	if semanticError {
		return 1
	}
	return 0
}

func setStringArg(args map[string]interface{}, key, value string) {
	if strings.TrimSpace(value) != "" {
		args[key] = value
	}
}

// Kept as a small helper for shell wrappers that need a JSON integer.
func cliInteger(value string) (int, error) {
	return strconv.Atoi(value)
}
