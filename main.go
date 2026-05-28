package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type pathMapFlags []string

func (p *pathMapFlags) String() string {
	return fmt.Sprint([]string(*p))
}

func (p *pathMapFlags) Set(value string) error {
	*p = append(*p, value)
	return nil
}

func main() {
	baseDir := flag.String("base-dir", "", "base directory for scripts and pcaps")
	scriptsDir := flag.String("scripts-dir", "", "Zeek scripts directory (default: <base-dir>/scripts)")
	showVersion := flag.Bool("version", false, "show version and exit")
	var pathMaps pathMapFlags
	flag.Var(&pathMaps, "path-map", "map a host path prefix to a container path prefix, formatted as host_prefix=container_prefix; may be repeated")
	flag.Parse()

	if *showVersion {
		fmt.Printf("zeek_mcp %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Git Commit: %s\n", GitCommit)
		os.Exit(0)
	}

	if *baseDir == "" {
		dir, _ := os.Getwd()
		*baseDir = dir
	}

	if *scriptsDir == "" {
		*scriptsDir = filepath.Join(*baseDir, "scripts")
	}

	absScriptsDir, _ := filepath.Abs(*scriptsDir)
	parsedPathMaps, err := ParsePathMaps([]string(pathMaps), os.Getenv("ZEEK_MCP_PATH_MAPS"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}

	ms := NewMCPServer(*baseDir, absScriptsDir, parsedPathMaps)
	if err := ms.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
}
