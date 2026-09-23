package credential

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// maxSecretFileSize limits the size of a secret file.
const maxSecretFileSize = 1 << 20

var errSecretFile = errors.New("invalid secret file")

// CheckSecretFile rejects a path that cannot safely hold credential material.
// It rejects non-regular files, files that a group or another user can read,
// and files larger than a megabyte. kind names the file in the error.
func CheckSecretFile(kind error, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: %w", kind, err)
	}
	switch {
	case !info.Mode().IsRegular():
		return fmt.Errorf("%w %s: it is not a regular file", kind, path)
	case info.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%w %s: it has mode %#o and holds credentials, so it must be readable "+
			"by its owner alone", kind, path, info.Mode().Perm())
	case info.Size() > maxSecretFileSize:
		return fmt.Errorf("%w %s: it is larger than %d bytes", kind, path, maxSecretFileSize)
	}
	return nil
}

// ReadSecretFile reads a file that holds one secret. It applies the
// CheckSecretFile rules and removes surrounding whitespace from the contents.
// Editors often add a trailing newline.
//
// The error never includes the contents.
func ReadSecretFile(path string) (string, error) {
	if err := CheckSecretFile(errSecretFile, path); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path is a configured secret file
	if err != nil {
		return "", fmt.Errorf("%w: %w", errSecretFile, err)
	}
	secret := strings.TrimSpace(string(data))
	if err := Validate(secret); err != nil {
		return "", fmt.Errorf("%w %s: %w", errSecretFile, path, err)
	}
	return secret, nil
}
