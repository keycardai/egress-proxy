// Package baseimage reads the Debian base image that the Dockerfiles under
// images/ pin. A test that builds a Debian image takes its base from here,
// so the pin is written only in the Dockerfiles Dependabot updates.
package baseimage

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/command"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// source is the Dockerfile whose FROM is the pin, relative to the
// repository root.
const source = "images/sandbox-base/Dockerfile"

// Debian returns the image reference, tag and digest, that the FROM in
// source names. root is the repository root. It fails unless source has
// exactly one FROM.
func Debian(root string) (string, error) {
	//nolint:gosec // G304: root is the caller's repository root and source is a constant
	data, err := os.ReadFile(filepath.Join(root, source))
	if err != nil {
		return "", fmt.Errorf("read the base image pin: %w", err)
	}
	refs, err := References(data)
	if err != nil {
		return "", fmt.Errorf("%s: %w", source, err)
	}
	if len(refs) != 1 {
		return "", fmt.Errorf("%s: %w, found %d", source, errNotOne, len(refs))
	}
	return refs[0], nil
}

// References returns the image each FROM instruction of a Dockerfile
// names, in order. The Dockerfile is read with the parser docker build uses.
// A FROM with no image is an error.
func References(dockerfile []byte) ([]string, error) {
	result, err := parser.Parse(bytes.NewReader(dockerfile))
	if err != nil {
		return nil, fmt.Errorf("parse the Dockerfile: %w", err)
	}
	var refs []string
	for _, node := range result.AST.Children {
		if !strings.EqualFold(node.Value, command.From) {
			continue
		}
		if node.Next == nil {
			return nil, fmt.Errorf("line %d: %w", node.StartLine, errNoImage)
		}
		refs = append(refs, node.Next.Value)
	}
	return refs, nil
}

var (
	// errNoImage is a FROM with only flags, or nothing, after it.
	errNoImage = errors.New("a FROM does not name an image")
	// errNotOne is a pin file with no FROM or more than one.
	errNotOne = errors.New("want one FROM")
)
