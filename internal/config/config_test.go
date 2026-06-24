package config

import "testing"

func TestDefaultConfig(t *testing.T) {
	t.Setenv("AGENTSHIELD_CONFIG", "")
	t.Setenv("AGENTSHIELD_LISTEN_ADDR", "")
	t.Setenv("AGENTSHIELD_LOG_LEVEL", "")

	cfg := Default()
	if cfg.ListenAddr != defaultListenAddr {
		t.Fatalf("ListenAddr = %q, want %q", cfg.ListenAddr, defaultListenAddr)
	}
	if cfg.LogLevel != defaultLogLevel {
		t.Fatalf("LogLevel = %q, want %q", cfg.LogLevel, defaultLogLevel)
	}
	if cfg.ConfigPath != "" {
		t.Fatalf("ConfigPath = %q, want empty", cfg.ConfigPath)
	}
}

func TestDefaultConfigReadsEnvironment(t *testing.T) {
	t.Setenv("AGENTSHIELD_CONFIG", "configs/agentshield.yaml")
	t.Setenv("AGENTSHIELD_LISTEN_ADDR", "127.0.0.1:9090")
	t.Setenv("AGENTSHIELD_LOG_LEVEL", "debug")

	cfg := Default()
	if cfg.ConfigPath != "configs/agentshield.yaml" {
		t.Fatalf("ConfigPath = %q", cfg.ConfigPath)
	}
	if cfg.ListenAddr != "127.0.0.1:9090" {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q", cfg.LogLevel)
	}
}
