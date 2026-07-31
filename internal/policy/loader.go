package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

type Format string

const (
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
)

type LoadResult struct {
	Bundle      Bundle
	Diagnostics []Diagnostic
	Preview     CompilePreview
}

func LoadFile(filename string, limits Limits) (LoadResult, error) {
	format, err := formatFromExtension(filename)
	if err != nil {
		return LoadResult{}, err
	}
	limits = limits.withDefaults()
	file, err := os.Open(filename)
	if err != nil {
		return LoadResult{}, fmt.Errorf("open policy file %q: %w", filename, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return LoadResult{}, fmt.Errorf("stat policy file %q: %w", filename, err)
	}
	if !info.Mode().IsRegular() {
		return LoadResult{}, fmt.Errorf("policy file %q is not a regular file", filename)
	}
	if info.Size() > limits.MaxFileBytes {
		return LoadResult{}, fmt.Errorf("policy file %q is %d bytes; limit is %d", filename, info.Size(), limits.MaxFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, limits.MaxFileBytes+1))
	if err != nil {
		return LoadResult{}, fmt.Errorf("read policy file %q: %w", filename, err)
	}
	result, err := Load(data, format, limits)
	if err != nil {
		return result, fmt.Errorf("load policy file %q: %w", filename, err)
	}
	return result, nil
}

func Load(data []byte, format Format, limits Limits) (LoadResult, error) {
	limits = limits.withDefaults()
	if int64(len(data)) > limits.MaxFileBytes {
		return LoadResult{}, fmt.Errorf("policy input is %d bytes; limit is %d", len(data), limits.MaxFileBytes)
	}
	if !utf8.Valid(data) {
		return LoadResult{}, errors.New("policy input must be valid UTF-8")
	}

	var raw rawBundle
	var err error
	switch Format(strings.ToLower(string(format))) {
	case FormatJSON:
		err = decodeJSON(data, &raw)
	case FormatYAML:
		err = decodeYAML(data, &raw)
	default:
		return LoadResult{}, fmt.Errorf("policy format %q is not supported; use json or yaml", format)
	}
	if err != nil {
		return LoadResult{}, err
	}
	bundle, err := raw.bundle()
	if err != nil {
		return LoadResult{}, fmt.Errorf("validate required policy fields: %w", err)
	}
	result := LoadResult{Bundle: bundle}
	if err := validateBundleLimits(result.Bundle, limits); err != nil {
		return result, fmt.Errorf("validate policy limits: %w", err)
	}
	result.Diagnostics, err = result.Bundle.NormalizeAndValidate()
	if err != nil {
		return result, fmt.Errorf("validate policy bundle: %w", err)
	}
	result.Preview, err = PreviewCompile(result.Bundle, limits)
	if err != nil {
		return result, fmt.Errorf("compile policy preview: %w", err)
	}
	return result, nil
}

func formatFromExtension(filename string) (Format, error) {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".json":
		return FormatJSON, nil
	case ".yaml", ".yml":
		return FormatYAML, nil
	default:
		return "", fmt.Errorf("policy file %q has an unsupported extension; use .json, .yaml, or .yml", filename)
	}
}

func decodeJSON(data []byte, target any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return fmt.Errorf("decode JSON policy bundle: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode JSON policy bundle: %w", err)
	}
	if err := requireEndOfInput(decoder.Decode); err != nil {
		return fmt.Errorf("decode JSON policy bundle: %w", err)
	}
	return nil
}

func decodeYAML(data []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode YAML policy bundle: %w", err)
	}
	if err := requireEndOfInput(decoder.Decode); err != nil {
		return fmt.Errorf("decode YAML policy bundle: %w", err)
	}
	return nil
}

func requireEndOfInput(decode func(any) error) error {
	var extra any
	err := decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("multiple documents or values are not allowed")
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if err := requireEndOfInput(decoder.Decode); err != nil {
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delimiter)
	}
	_, err = decoder.Token()
	return err
}

type rawBundle struct {
	SchemaVersion int         `json:"schema_version" yaml:"schema_version"`
	Policies      []rawPolicy `json:"policies" yaml:"policies"`
}

type rawPolicy struct {
	ID              string     `json:"id" yaml:"id"`
	Name            string     `json:"name" yaml:"name"`
	Description     string     `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled         *bool      `json:"enabled" yaml:"enabled"`
	Scope           Scope      `json:"scope" yaml:"scope"`
	Decision        Decision   `json:"policy_decision" yaml:"policy_decision"`
	RequestedAction Action     `json:"requested_action" yaml:"requested_action"`
	Priority        *int       `json:"priority" yaml:"priority"`
	Severity        Severity   `json:"severity" yaml:"severity"`
	Conditions      Conditions `json:"conditions" yaml:"conditions"`
}

func (raw rawBundle) bundle() (Bundle, error) {
	bundle := Bundle{SchemaVersion: raw.SchemaVersion, Policies: make([]Policy, 0, len(raw.Policies))}
	var validationErrors []error
	for index, policy := range raw.Policies {
		if policy.Enabled == nil {
			validationErrors = append(validationErrors, fmt.Errorf("policies[%d].enabled is required", index))
		}
		if policy.Priority == nil {
			validationErrors = append(validationErrors, fmt.Errorf("policies[%d].priority is required", index))
		}
		converted := Policy{
			ID:              policy.ID,
			Name:            policy.Name,
			Description:     policy.Description,
			Scope:           policy.Scope,
			Decision:        policy.Decision,
			RequestedAction: policy.RequestedAction,
			Severity:        policy.Severity,
			Conditions:      policy.Conditions,
		}
		if policy.Enabled != nil {
			converted.Enabled = *policy.Enabled
		}
		if policy.Priority != nil {
			converted.Priority = *policy.Priority
		}
		bundle.Policies = append(bundle.Policies, converted)
	}
	return bundle, errors.Join(validationErrors...)
}
