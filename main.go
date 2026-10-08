package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
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
	if len(os.Args) > 1 && isCLICommand(os.Args[1]) {
		os.Exit(runCLI(os.Args[1], os.Args[2:]))
	}
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

	// Configure structured JSON logging
	logLevel := slog.LevelInfo
	if strings.ToLower(os.Getenv("ZEEK_LOG_LEVEL")) == "debug" {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

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

	// Graceful shutdown: listen for SIGTERM/SIGINT
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var runErr error
	switch *transport {
	case "stdio":
		// stdio runs synchronously; shutdown after return
		runErr = ms.RunStdio()
	case "http", "streamable_http":
		// Run HTTP server in background, wait for signal
		errCh := make(chan error, 1)
		go func() {
			errCh <- ms.RunHTTP(*listen, *endpoint, *tlsCert, *tlsKey)
		}()

		select {
		case runErr = <-errCh:
			// Server exited on its own
		case <-ctx.Done():
			slog.Info("received shutdown signal, draining...")
			ms.Shutdown()
			// Give in-flight requests time to complete
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			<-shutdownCtx.Done()
			runErr = nil
		}
	default:
		runErr = fmt.Errorf("unsupported transport %q; expected stdio or http", *transport)
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", runErr)
		os.Exit(1)
	}
}
