// Package helper stands in for a test helper under test/. Its import does
// not ship in a binary, so NOTICE leaves it out.
package helper

import "github.com/pkg/errors"

// Err is an error from the test-only module.
var Err = errors.New("fixture")
