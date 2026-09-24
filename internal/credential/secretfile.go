package credential

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// maxSecretFileSize limits the size of a secret file.
const maxSecretFileSize = 1 << 20

// maxTokenFileSize limits the size of a projected ServiceAccount token. A
// bound token from a Kubernetes 1.34 cluster is about 1 KiB, so this leaves
// room for a longer audience list and for claims a later version adds.
const maxTokenFileSize = 64 << 10

var errSecretFile = errors.New("invalid secret file")

// CheckSecretFile rejects a path that cannot safely hold credential material.
// It rejects a non-regular file, a file larger than maxSecretFileSize, and a
// file that a group or another user can read. kind names the file in the
// error.
func CheckSecretFile(kind error, path string) error {
	info, err := checkFileShape(kind, path, maxSecretFileSize)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w %s: it has mode %#o and holds credentials, so it must be readable "+
			"by its owner alone", kind, path, info.Mode().Perm())
	}
	return nil
}

// CheckTokenFile rejects a path that cannot hold a projected ServiceAccount
// token. It rejects a non-regular file and a file larger than
// maxTokenFileSize. The kubelet writes the token world-readable, so this check
// applies no permission rule. kind names the file in the error.
func CheckTokenFile(kind error, path string) error {
	_, err := checkFileShape(kind, path, maxTokenFileSize)
	return err
}

// checkFileShape rejects a non-regular file and a file larger than maxSize. A
// read of a non-regular file can block past any timeout, because os.ReadFile
// takes no context.
func checkFileShape(kind error, path string, maxSize int64) (os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", kind, err)
	}
	switch {
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("%w %s: it is not a regular file", kind, path)
	case info.Size() > maxSize:
		return nil, fmt.Errorf("%w %s: it is larger than %d bytes", kind, path, maxSize)
	}
	return info, nil
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
