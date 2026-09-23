// Package strictdoc validates document boundaries and JSON object keys before
// a case-insensitive struct decoder reads a document.
package strictdoc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v2"
)

var (
	errCaseFold       = errors.New("keys that differ only in case name one setting")
	errKeyNotString   = errors.New("an object key is not a string")
	errSecondDocument = errors.New("the input holds more than one YAML document")
)

// RefuseSecondYAMLDocument rejects an input that carries a second YAML
// document. The YAML-to-JSON conversion reads only the first document.
func RefuseSecondYAMLDocument(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var first, second any
	if err := decoder.Decode(&first); err == nil {
		if err := decoder.Decode(&second); !errors.Is(err, io.EOF) {
			return errSecondDocument
		}
	}
	return nil
}

// RefuseCaseFoldedJSONKeys rejects keys that a JSON struct decoder would
// match to the same field case-insensitively.
func RefuseCaseFoldedJSONKeys(jsonText []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(jsonText))
	if err := walkValue(decoder, ""); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing data: %w", err)
	}
	return nil
}

func walkValue(decoder *json.Decoder, location string) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("read %s: %w", location, err)
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return walkObject(decoder, location)
	case '[':
		for i := 0; decoder.More(); i++ {
			if err := walkValue(decoder, fmt.Sprintf("%s[%d]", location, i)); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("read %s: %w", location, err)
		}
	}
	return nil
}

func walkObject(decoder *json.Decoder, location string) error {
	seen := make(map[string]string)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("read %s: %w", location, err)
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("%w: %v at %s", errKeyNotString, token, orRoot(location))
		}
		folded := strings.ToLower(key)
		if previous, duplicate := seen[folded]; duplicate {
			names := []string{previous, key}
			sort.Strings(names)
			return fmt.Errorf("%w: %q and %q at %s", errCaseFold, names[0], names[1], orRoot(location))
		}
		seen[folded] = key
		if err := walkValue(decoder, strings.TrimPrefix(location+"."+key, ".")); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("read %s: %w", location, err)
	}
	return nil
}

func orRoot(location string) string {
	if location == "" {
		return "the top level"
	}
	return location
}
