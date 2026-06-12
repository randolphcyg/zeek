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
	transport := flag.String("transport", "stdio", "MCP transport: stdio or http")
	listen := flag.String("listen", ":8001", "HTTP listen address when --transport=http")
	endpoint := flag.String("endpoint", "/mcp", "HTTP MCP endpoint path when --transport=http")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file for HTTPS")
	tlsKey := flag.String("tls-key", "", "TLS private key file for HTTPS")
	showVersion := flag.Bool("version", false, "show version and exit")
	var pathMaps pathMapFlags
	flag.Var(&pathMaps, "path-map", "map a host path prefix to a container path prefix, formatted as host_prefix=container_prefix; may be repeated")
	flag.Parse()

	if *showVersion {
		fmt.Printf("zeek %s\n", Version)
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
	parsedPathMaps, err := ParsePathMaps([]string(pathMaps), os.Getenv("ZEEK_PATH_MAPS"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}

	ms := NewMCPServer(*baseDir, absScriptsDir, parsedPathMaps)
	var runErr error
	switch *transport {
	case "stdio":
		runErr = ms.RunStdio()
	case "http", "streamable_http":
		runErr = ms.RunHTTP(*listen, *endpoint, *tlsCert, *tlsKey)
	default:
		runErr = fmt.Errorf("unsupported transport %q; expected stdio or http", *transport)
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", runErr)
		os.Exit(1)
	}
}
