package inspection

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

var secretField = regexp.MustCompile(`(?i)^(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|authorization|cookie|aws_secret_access_key)$`)
var credentialPattern = regexp.MustCompile(`(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_-]?key|password|secret|access[_-]?token)\s*[=:]\s*[^\s]{8,}|AKIA[A-Z0-9]{16})`)

// decodeObject rejects duplicate names, excessive nesting, invalid UTF-8 and
// trailing values. Number spellings are preserved rather than rounded.
func decodeObject(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid_json")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		if depth > 32 {
			return nil, errors.New("invalid_json")
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, errors.New("invalid_json")
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				object := map[string]any{}
				for decoder.More() {
					key, err := decoder.Token()
					if err != nil {
						return nil, errors.New("invalid_json")
					}
					name, ok := key.(string)
					if !ok {
						return nil, errors.New("invalid_json")
					}
					if _, duplicate := object[name]; duplicate {
						return nil, errors.New("invalid_json")
					}
					entry, err := value(depth + 1)
					if err != nil {
						return nil, err
					}
					object[name] = entry
				}
				if _, err := decoder.Token(); err != nil {
					return nil, errors.New("invalid_json")
				}
				return object, nil
			case '[':
				array := []any{}
				for decoder.More() {
					entry, err := value(depth + 1)
					if err != nil {
						return nil, err
					}
					array = append(array, entry)
				}
				if _, err := decoder.Token(); err != nil {
					return nil, errors.New("invalid_json")
				}
				return array, nil
			default:
				return nil, errors.New("invalid_json")
			}
		}
		return token, nil
	}
	root, err := value(0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("invalid_json")
	}
	object, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("invalid_json")
	}
	return object, nil
}

func sensitive(value any, forbidden []string) bool {
	switch value := value.(type) {
	case string:
		if credentialPattern.MatchString(value) {
			return true
		}
		for _, secret := range forbidden {
			if strings.Contains(value, secret) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if sensitive(child, forbidden) {
				return true
			}
		}
	case map[string]any:
		for key, child := range value {
			if text, ok := child.(string); ok && text != "" && secretField.MatchString(key) {
				return true
			}
			if sensitive(key, forbidden) || sensitive(child, forbidden) {
				return true
			}
		}
	}
	return false
}
