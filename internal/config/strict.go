package config

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

// refuseSecondDocument refuses an input that carries a second YAML document.
// The conversion to JSON reads the first document alone, so a second one
// would take no part in the settings or in the document digest.
func refuseSecondDocument(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var first, second any
	// A first document that does not parse leaves the decoder unusable, and
	// the strict conversion that follows reports the syntax problem.
	if err := decoder.Decode(&first); err == nil {
		if err := decoder.Decode(&second); !errors.Is(err, io.EOF) {
			return errSecondDocument
		}
	}
	return nil
}

// refuseCaseFoldedKeys walks the JSON once and refuses two keys at one
// level that are equal under case folding. The struct decoder matches field
// names case-insensitively, so "verify" and "Verify" both land on one field
// and the later one wins in silence.
func refuseCaseFoldedKeys(jsonText []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(jsonText))
	return walkValue(decoder, "")
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
		return nil
	default:
		return nil
	}
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
		if previous, dup := seen[folded]; dup {
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
