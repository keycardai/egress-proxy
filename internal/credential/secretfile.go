package credential

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// maxSecretFileSize bounds what a secret file can hold.
const maxSecretFileSize = 1 << 20

var errSecretFile = errors.New("invalid secret file")

// CheckSecretFile refuses a path that cannot safely hold credential
// material: anything that is not a regular file, a file any group or other
// user can read, and a file larger than a megabyte. kind names the file in
// the message.
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

// ReadSecretFile reads a file holding one secret and nothing else. It
// applies the CheckSecretFile rules, then returns the contents with
// surrounding whitespace removed, because an editor leaves a trailing
// newline and a secret never ends in one.
//
// The error NEVER quotes the contents.
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
