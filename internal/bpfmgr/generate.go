package bpfmgr

//go:generate go run ../../cmd/bpfgen -out ./generated/bpf_sources.go -package generated ../../bpf/agentshield.bpf.c ../../bpf/events.h ../../bpf/maps.h
