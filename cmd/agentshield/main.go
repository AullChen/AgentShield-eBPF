package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/agentshield/agentshield-ebpf/internal/config"
	"github.com/agentshield/agentshield-ebpf/internal/envcheck"
	"github.com/agentshield/agentshield-ebpf/internal/logging"
	"github.com/agentshield/agentshield-ebpf/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return 2
	}

	cfg := config.Default()
	common := flag.NewFlagSet("agentshield", flag.ContinueOnError)
	common.SetOutput(os.Stderr)
	common.StringVar(&cfg.ConfigPath, "config", cfg.ConfigPath, "path to the AgentShield config file")
	common.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug, info, warn, or error")

	command := args[0]
	switch command {
	case "diagnose":
		if err := common.Parse(args[1:]); err != nil {
			return 2
		}
		return runDiagnose(context.Background(), cfg)
	case "version":
		if err := common.Parse(args[1:]); err != nil {
			return 2
		}
		return runVersion(os.Stdout)
	case "health":
		if err := common.Parse(args[1:]); err != nil {
			return 2
		}
		return runHealth(context.Background(), cfg)
	case "-h", "--help", "help":
		printUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", command)
		printUsage(os.Stderr)
		return 2
	}
}

func runVersion(out *os.File) int {
	fmt.Fprintln(out, version.String())
	return 0
}

func runHealth(ctx context.Context, cfg config.Config) int {
	logger, err := logging.New(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid logger configuration: %v\n", err)
		return 2
	}

	status := map[string]string{
		"service": version.ServiceName,
		"status":  "ok",
		"version": version.Version,
	}

	payload, err := json.Marshal(status)
	if err != nil {
		logger.ErrorContext(ctx, "failed to encode health response", slog.Any("error", err))
		return 1
	}

	logger.InfoContext(ctx, "health check completed", slog.String("status", "ok"))
	fmt.Println(string(payload))
	return 0
}

func runDiagnose(ctx context.Context, cfg config.Config) int {
	logger, err := logging.New(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid logger configuration: %v\n", err)
		return 2
	}

	report := envcheck.Run(ctx)
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		logger.ErrorContext(ctx, "failed to encode diagnostics report", slog.Any("error", err))
		return 1
	}

	fmt.Println(string(payload))
	if report.HasFailures() {
		logger.WarnContext(ctx, "diagnostics completed with failures")
		return 1
	}

	logger.InfoContext(ctx, "diagnostics completed")
	return 0
}

func printUsage(out *os.File) {
	commands := []string{
		"diagnose run local environment diagnostics",
		"health   run a local control-plane health check",
		"version  print build version information",
	}

	fmt.Fprintf(out, "%s\n\n", version.ServiceName)
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  agentshield <command> [flags]")
	fmt.Fprintln(out, "\nCommands:")
	for _, command := range commands {
		parts := strings.SplitN(command, " ", 2)
		fmt.Fprintf(out, "  %-8s %s\n", parts[0], strings.TrimSpace(parts[1]))
	}
	fmt.Fprintln(out, "\nCommon flags:")
	fmt.Fprintln(out, "  --config string      path to the AgentShield config file")
	fmt.Fprintln(out, "  --log-level string   log level: debug, info, warn, or error")
}
