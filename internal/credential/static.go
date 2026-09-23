package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/keycardai/egress-proxy/internal/strictdoc"
)

// StaticVersion is the only credential file version this build reads.
const StaticVersion = 1

// maxStaticFileSize bounds what LoadStaticFile reads.
const maxStaticFileSize = 1 << 20

// ErrUnavailable means the source holds no credential for the resource.
var ErrUnavailable = errors.New("no credential for this resource")

var errStaticFile = errors.New("invalid credential file")

// StaticFile is a Source that reads every credential from one file at
// start-up. It serves tests and development, where no authorization server
// answers. The file holds credentials in the clear, so it must be readable
// by its owner alone.
type StaticFile struct {
	path       string
	byResource map[string]string
}

// staticDocument is the credential file as written.
type staticDocument struct {
	Version     int           `json:"version"`
	Credentials []staticEntry `json:"credentials"`
}

// staticEntry is one credential and the resource it is for.
type staticEntry struct {
	Resource string `json:"resource"`
	Value    string `json:"value"`
}

// LoadStaticFile reads the credential file at path.
func LoadStaticFile(path string) (*StaticFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errStaticFile, err)
	}
	switch {
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("%w %s: it is not a regular file", errStaticFile, path)
	case info.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("%w %s: it has mode %#o and holds credentials, so it must be readable "+
			"by its owner alone", errStaticFile, path, info.Mode().Perm())
	case info.Size() > maxStaticFileSize:
		return nil, fmt.Errorf("%w %s: it is larger than %d bytes", errStaticFile, path, maxStaticFileSize)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path is credentials.static_file
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errStaticFile, err)
	}
	doc, err := parseStatic(path, data)
	if err != nil {
		return nil, err
	}
	source := &StaticFile{path: path, byResource: make(map[string]string, len(doc.Credentials))}
	for i, entry := range doc.Credentials {
		if err := entry.validate(path, i, source.byResource); err != nil {
			return nil, err
		}
		source.byResource[entry.Resource] = entry.Value
	}
	return source, nil
}

// parseStatic decodes the document and refuses unknown keys. A misspelled key
// cannot leave an endpoint without its credential.
func parseStatic(path string, data []byte) (*staticDocument, error) {
	if err := strictdoc.RefuseSecondYAMLDocument(data); err != nil {
		return nil, fmt.Errorf("%w %s: %w", errStaticFile, path, err)
	}
	jsonText, err := yaml.YAMLToJSONStrict(data)
	if err != nil {
		return nil, fmt.Errorf("%w %s: cannot decode YAML", errStaticFile, path)
	}
	if err := strictdoc.RefuseCaseFoldedJSONKeys(jsonText); err != nil {
		return nil, fmt.Errorf("%w %s: invalid object keys", errStaticFile, path)
	}
	decoder := json.NewDecoder(bytes.NewReader(jsonText))
	decoder.DisallowUnknownFields()
	var doc staticDocument
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w %s: unknown field or invalid value", errStaticFile, path)
	}
	if doc.Version != StaticVersion {
		return nil, fmt.Errorf("%w %s: version is %d, this build reads version %d",
			errStaticFile, path, doc.Version, StaticVersion)
	}
	if len(doc.Credentials) == 0 {
		return nil, fmt.Errorf("%w %s: credentials is empty", errStaticFile, path)
	}
	return &doc, nil
}

// validate refuses an entry without a resource, a repeated resource, or a
// credential the proxy cannot write. The message never quotes the value.
func (e staticEntry) validate(path string, i int, seen map[string]string) error {
	switch _, repeated := seen[e.Resource]; {
	case strings.TrimSpace(e.Resource) == "":
		return fmt.Errorf("%w %s: credentials[%d]: resource is empty", errStaticFile, path, i)
	case repeated:
		return fmt.Errorf("%w %s: credentials[%d]: resource %q repeats an earlier entry",
			errStaticFile, path, i, e.Resource)
	}
	if err := Validate(e.Value); err != nil {
		return fmt.Errorf("%w %s: credentials[%d]: resource %q: %w", errStaticFile, path, i, e.Resource, err)
	}
	return nil
}

// Credential returns the credential the file holds for the resource.
func (s *StaticFile) Credential(_ context.Context, resource string) (string, error) {
	value, ok := s.byResource[resource]
	if !ok {
		return "", ErrUnavailable
	}
	return value, nil
}

// Describe names the file and how many credentials it holds.
func (s *StaticFile) Describe() string {
	return fmt.Sprintf("a static file of %d credentials at %s, for tests and development",
		len(s.byResource), s.path)
}
