package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/agentshield/agentshield-ebpf/internal/bpfmgr"
	"github.com/agentshield/agentshield-ebpf/internal/config"
	"github.com/agentshield/agentshield-ebpf/internal/envcheck"
	"github.com/agentshield/agentshield-ebpf/internal/logging"
	"github.com/agentshield/agentshield-ebpf/internal/scope"
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
	case "audit", "audit-openat":
		flags := newFlagSet(command, &cfg)
		bpfObject := flags.String("bpf-object", "bpf/agentshield.bpf.o", "path to the compiled AgentShield BPF object")
		cgroupPath := flags.String("cgroup", "", "cgroup v2 path for connect4/connect6 audit hooks")
		scopeCgroupPath := flags.String("scope-cgroup", "", "trusted exact leaf cgroup v2 path to register for audit")
		if exitCode, done := parseCommandFlags(flags, args[1:], &cfg); done {
			return exitCode
		}
		return runAudit(cfg, *bpfObject, *cgroupPath, *scopeCgroupPath)
	case "diagnose":
		flags := newFlagSet(command, &cfg)
		if exitCode, done := parseCommandFlags(flags, args[1:], &cfg); done {
			return exitCode
		}
		return runDiagnose(context.Background(), cfg)
	case "version":
		flags := newFlagSet(command, &cfg)
		if exitCode, done := parseCommandFlags(flags, args[1:], &cfg); done {
			return exitCode
		}
		return runVersion(os.Stdout)
	case "health":
		flags := newFlagSet(command, &cfg)
		if exitCode, done := parseCommandFlags(flags, args[1:], &cfg); done {
			return exitCode
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
	flags.StringVar(&cfg.ConfigPath, "config", cfg.ConfigPath, "reserved; configuration files are not supported yet")
	flags.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug, info, warn, or error")
	return flags
}

func parseCommandFlags(flags *flag.FlagSet, args []string, cfg *config.Config) (int, bool) {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true
		}
		return 2, true
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments for %s: %q\n", flags.Name(), flags.Args())
		return 2, true
	}
	if cfg.ConfigPath != "" {
		fmt.Fprintf(os.Stderr, "configuration files are not supported yet: %q\n", cfg.ConfigPath)
		return 2, true
	}
	return 0, false
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

func runAudit(cfg config.Config, objectPath, cgroupPath, scopeCgroupPath string) int {
	logger, err := logging.New(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid logger configuration: %v\n", err)
		return 2
	}

	if scopeCgroupPath == "" {
		fmt.Fprintln(os.Stderr, "audit requires --scope-cgroup with a trusted exact leaf cgroup")
		return 2
	}
	if cgroupPath != "" && cgroupPath != scopeCgroupPath {
		fmt.Fprintln(os.Stderr, "--cgroup and --scope-cgroup must identify the same exact leaf")
		return 2
	}
	resolver, err := scope.NewLinuxResolver("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize trusted cgroup resolver: %v\n", err)
		return 1
	}
	handle, err := resolver.ResolvePath(scopeCgroupPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve trusted audit scope: %v\n", err)
		return 1
	}
	defer handle.Close()
	instanceID, err := randomNonZeroUint64()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate audit instance ID: %v\n", err)
		return 1
	}
	scopeCookie, err := randomNonZeroUint64()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate audit scope cookie: %v\n", err)
		return 1
	}
	cgroupPath = handle.Path

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.InfoContext(ctx, "starting kernel audit", slog.String("bpf_object", objectPath), slog.String("network_cgroup", cgroupPath))
	err = bpfmgr.RunAudit(ctx, bpfmgr.AuditOptions{
		ObjectPath: objectPath,
		CgroupPath: cgroupPath,
		OnScopeMapReady: func(scopes bpfmgr.ScopeMap) error {
			return scopes.Put(handle.ID, scope.Value{
				InstanceID:  instanceID,
				ScopeCookie: scopeCookie,
			})
		},
		OnReady: func() {
			logger.InfoContext(ctx, "kernel audit hooks attached")
		},
		OnMalformedEvent: func(err error) {
			logger.WarnContext(ctx, "discarding malformed kernel event", slog.Any("error", err))
		},
	}, os.Stdout)
	if err == nil {
		return 0
	}
	if errors.Is(err, bpfmgr.ErrUnsupported) {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	logger.ErrorContext(ctx, "kernel audit failed", slog.Any("error", err))
	return 1
}

func randomNonZeroUint64() (uint64, error) {
	var encoded [8]byte
	for range 8 {
		if _, err := rand.Read(encoded[:]); err != nil {
			return 0, err
		}
		if value := binary.BigEndian.Uint64(encoded[:]); value != 0 {
			return value, nil
		}
	}
	return 0, errors.New("random source returned zero repeatedly")
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
	if !report.IsReady() {
		logger.WarnContext(ctx, "diagnostics did not establish readiness", slog.Bool("has_failures", report.HasFailures()))
		return 1
	}

	logger.InfoContext(ctx, "diagnostics completed")
	return 0
}

func printUsage(out *os.File) {
	commands := []string{
		"audit        stream file and process events as JSON Lines",
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
	fmt.Fprintln(out, "  --config string      reserved; configuration files are not supported yet")
	fmt.Fprintln(out, "  --log-level string   log level: debug, info, warn, or error")
	fmt.Fprintln(out, "\nCommand flags:")
	fmt.Fprintln(out, "  audit --bpf-object string   path to compiled AgentShield BPF object")
	fmt.Fprintln(out, "        --cgroup string      cgroup v2 path for connect4/connect6 audit hooks")
	fmt.Fprintln(out, "        --scope-cgroup string trusted exact leaf cgroup v2 path to audit")
}
