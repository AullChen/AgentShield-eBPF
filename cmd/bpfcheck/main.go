package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

type metadataFlags map[string]string

func (values metadataFlags) String() string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values[key])
	}
	return strings.Join(parts, ",")
}

func (values metadataFlags) Set(value string) error {
	key, item, ok := strings.Cut(value, "=")
	if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(item) == "" {
		return fmt.Errorf("metadata must be a non-empty key=value pair")
	}
	values[key] = item
	return nil
}

type objectManifest struct {
	SchemaVersion int               `json:"schema_version"`
	ObjectPath    string            `json:"object_path"`
	SHA256        string            `json:"sha256"`
	Size          int               `json:"size"`
	ByteOrder     string            `json:"byte_order"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Programs      []programManifest `json:"programs"`
	Maps          []mapManifest     `json:"maps"`
}

type programManifest struct {
	Name        string `json:"name"`
	SectionName string `json:"section_name"`
	Type        string `json:"type"`
	AttachType  string `json:"attach_type"`
}

type mapManifest struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	KeySize    uint32 `json:"key_size"`
	ValueSize  uint32 `json:"value_size"`
	MaxEntries uint32 `json:"max_entries"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "bpfcheck: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	var objectPath string
	var manifestPath string
	metadata := metadataFlags{}

	flags := flag.NewFlagSet("bpfcheck", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&objectPath, "object", "", "path to the compiled BPF ELF object")
	flags.StringVar(&manifestPath, "manifest", "", "optional path to write the JSON object manifest")
	flags.Var(metadata, "metadata", "build metadata key=value; may be repeated")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if objectPath == "" {
		return fmt.Errorf("--object is required")
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %q", flags.Args())
	}

	manifest, err := inspectObject(objectPath, metadata)
	if err != nil {
		return err
	}
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	payload = append(payload, '\n')

	if manifestPath != "" {
		if err := os.WriteFile(manifestPath, payload, 0o644); err != nil {
			return fmt.Errorf("write manifest %q: %w", manifestPath, err)
		}
	}
	_, err = out.Write(payload)
	return err
}

func inspectObject(objectPath string, metadata map[string]string) (objectManifest, error) {
	contents, err := os.ReadFile(objectPath)
	if err != nil {
		return objectManifest{}, fmt.Errorf("read BPF object %q: %w", objectPath, err)
	}
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return objectManifest{}, fmt.Errorf("parse BPF ELF/spec %q: %w", objectPath, err)
	}

	for _, name := range []string{"agentshield_trace_execve", "agentshield_trace_openat"} {
		if spec.Programs[name] == nil {
			return objectManifest{}, fmt.Errorf("required BPF program %q is missing", name)
		}
	}
	if spec.Maps["agentshield_events"] == nil {
		return objectManifest{}, errors.New("required BPF map \"agentshield_events\" is missing")
	}

	hash := sha256.Sum256(contents)
	manifest := objectManifest{
		SchemaVersion: 1,
		ObjectPath:    objectPath,
		SHA256:        hex.EncodeToString(hash[:]),
		Size:          len(contents),
		ByteOrder:     fmt.Sprint(spec.ByteOrder),
		Metadata:      metadata,
	}

	programNames := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		programNames = append(programNames, name)
	}
	sort.Strings(programNames)
	for _, name := range programNames {
		program := spec.Programs[name]
		manifest.Programs = append(manifest.Programs, programManifest{
			Name:        name,
			SectionName: program.SectionName,
			Type:        program.Type.String(),
			AttachType:  program.AttachType.String(),
		})
	}

	mapNames := make([]string, 0, len(spec.Maps))
	for name := range spec.Maps {
		mapNames = append(mapNames, name)
	}
	sort.Strings(mapNames)
	for _, name := range mapNames {
		item := spec.Maps[name]
		manifest.Maps = append(manifest.Maps, mapManifest{
			Name:       name,
			Type:       item.Type.String(),
			KeySize:    item.KeySize,
			ValueSize:  item.ValueSize,
			MaxEntries: item.MaxEntries,
		})
	}

	return manifest, nil
}
