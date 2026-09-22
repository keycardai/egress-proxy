package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	errCaseFold     = errors.New("keys that differ only in case name one setting")
	errKeyNotString = errors.New("an object key is not a string")
)

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
