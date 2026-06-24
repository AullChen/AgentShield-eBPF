package config

import "os"

const (
	defaultListenAddr = "127.0.0.1:8080"
	defaultLogLevel   = "info"
)

type Config struct {
	ConfigPath string
	ListenAddr string
	LogLevel   string
}

func Default() Config {
	cfg := Config{
		ListenAddr: defaultListenAddr,
		LogLevel:   defaultLogLevel,
	}

	if value := os.Getenv("AGENTSHIELD_CONFIG"); value != "" {
		cfg.ConfigPath = value
	}
	if value := os.Getenv("AGENTSHIELD_LISTEN_ADDR"); value != "" {
		cfg.ListenAddr = value
	}
	if value := os.Getenv("AGENTSHIELD_LOG_LEVEL"); value != "" {
		cfg.LogLevel = value
	}

	return cfg
}
