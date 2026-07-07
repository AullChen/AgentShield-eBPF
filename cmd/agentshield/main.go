package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"

	"github.com/agentshield/agentshield-ebpf/internal/bpfmgr"
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

	command := args[0]
	cfg := config.Default()
	switch command {
	case "audit-openat":
		flags := newFlagSet(command, &cfg)
		bpfObject := flags.String("bpf-object", "bpf/agentshield.bpf.o", "path to the compiled AgentShield BPF object")
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		return runAuditOpenAT(cfg, *bpfObject)
	case "diagnose":
		flags := newFlagSet(command, &cfg)
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		return runDiagnose(context.Background(), cfg)
	case "version":
		flags := newFlagSet(command, &cfg)
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		return runVersion(os.Stdout)
	case "health":
		flags := newFlagSet(command, &cfg)
		if err := flags.Parse(args[1:]); err != nil {
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

func newFlagSet(name string, cfg *config.Config) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&cfg.ConfigPath, "config", cfg.ConfigPath, "path to the AgentShield config file")
	flags.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug, info, warn, or error")
	return flags
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

func runAuditOpenAT(cfg config.Config, objectPath string) int {
	logger, err := logging.New(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid logger configuration: %v\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	logger.InfoContext(ctx, "starting openat audit", slog.String("bpf_object", objectPath))
	err = bpfmgr.RunOpenATAudit(ctx, bpfmgr.OpenATAuditOptions{ObjectPath: objectPath}, os.Stdout)
	if err == nil {
		return 0
	}
	if errors.Is(err, bpfmgr.ErrUnsupported) {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	logger.ErrorContext(ctx, "openat audit failed", slog.Any("error", err))
	return 1
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
		"audit-openat stream openat file-access events as JSON Lines",
		"diagnose     run local environment diagnostics",
		"health       run a local control-plane health check",
		"version      print build version information",
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
	fmt.Fprintln(out, "\nCommand flags:")
	fmt.Fprintln(out, "  audit-openat --bpf-object string   path to compiled AgentShield BPF object")
}
