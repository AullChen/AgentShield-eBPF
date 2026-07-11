package bpfmgr

import "github.com/agentshield/agentshield-ebpf/internal/bpfmgr/generated"

type SourceFile = generated.SourceFile

func EmbeddedSources() []SourceFile {
	return append([]SourceFile(nil), generated.Sources...)
}
