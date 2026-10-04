package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/agentshield/agentshield-ebpf/internal/evidence"
)

func main() {
	timeline, err := evidence.BuildSampleTimeline()
	if err != nil {
		fmt.Fprintln(os.Stderr, "build evidence sample:", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(timeline); err != nil {
		fmt.Fprintln(os.Stderr, "encode evidence sample:", err)
		os.Exit(1)
	}
}
