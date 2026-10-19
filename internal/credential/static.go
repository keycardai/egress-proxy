package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/keycardai/egress-proxy/internal/strictdoc"
)

// StaticVersion is the only credential file version this build reads.
const StaticVersion = 1

var errStaticFile = errors.New("invalid credential file")

// StaticFile is a Source that reads every credential from one file at
// start-up. It serves tests and development, where no authorization server
// answers. The file holds credentials in the clear, so it must be readable
// by its owner alone.
type StaticFile struct {
	path string
	// byResource holds the entries that name no sandbox and no application,
	// which answer every view that has no entry of its own.
	byResource map[string]string
	// bySandbox holds the entries that name a sandbox, keyed by sandbox and
	// then by resource. byApplication holds the entries that name an
	// application the same way.
	bySandbox     map[string]map[string]string
	byApplication map[string]map[string]string
}

// staticDocument is the credential file as written.
type staticDocument struct {
	Version     int           `json:"version"`
	Credentials []staticEntry `json:"credentials"`
}

// staticEntry is one credential and the resource it is for. Sandbox limits
// the entry to one sandbox and Application to one application. An entry
// names at most one of them. An entry naming neither answers every view.
type staticEntry struct {
	Resource    string `json:"resource"`
	Sandbox     string `json:"sandbox"`
	Application string `json:"application"`
	Value       string `json:"value"`
}

// LoadStaticFile reads the credential file at path.
func LoadStaticFile(path string) (*StaticFile, error) {
	if err := CheckSecretFile(errStaticFile, path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path is credentials.static_file
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errStaticFile, err)
	}
	doc, err := parseStatic(path, data)
	if err != nil {
		return nil, err
	}
	source := &StaticFile{
		path:          path,
		byResource:    make(map[string]string, len(doc.Credentials)),
		bySandbox:     make(map[string]map[string]string),
		byApplication: make(map[string]map[string]string),
	}
	for i, entry := range doc.Credentials {
		if entry.Sandbox != "" && entry.Application != "" {
			return nil, fmt.Errorf("%w %s: credentials[%d]: sandbox %q and application %q both scope the entry; set one",
				errStaticFile, path, i, entry.Sandbox, entry.Application)
		}
		table := source.table(entry)
		if err := entry.validate(path, i, table); err != nil {
			return nil, err
		}
		table[entry.Resource] = entry.Value
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

// validate refuses an entry without a resource, a repeated resource within
// its scope, or a credential the proxy cannot write. The message never
// quotes the value.
func (e staticEntry) validate(path string, i int, seen map[string]string) error {
	switch _, repeated := seen[e.Resource]; {
	case strings.TrimSpace(e.Resource) == "":
		return fmt.Errorf("%w %s: credentials[%d]: resource is empty", errStaticFile, path, i)
	case repeated && e.Sandbox != "":
		return fmt.Errorf("%w %s: credentials[%d]: resource %q repeats an earlier entry for sandbox %q",
			errStaticFile, path, i, e.Resource, e.Sandbox)
	case repeated && e.Application != "":
		return fmt.Errorf("%w %s: credentials[%d]: resource %q repeats an earlier entry for application %q",
			errStaticFile, path, i, e.Resource, e.Application)
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
		s.count(), s.path)
}

// ForSandbox returns the view one sandbox reads: its own entries first, then
// the entries that name no sandbox and no application.
func (s *StaticFile) ForSandbox(sandbox string) *View {
	return &View{file: s, own: s.bySandbox[sandbox], what: "sandbox " + sandbox}
}

// ForApplication returns the view one application reads: its own entries
// first, then the entries that name no sandbox and no application.
func (s *StaticFile) ForApplication(application string) *View {
	return &View{file: s, own: s.byApplication[application], what: "application " + application}
}

// Sandboxes lists every sandbox name the file holds an entry for, sorted.
// A caller refuses a name the document does not map, so a misspelled entry
// cannot silently fall back to the shared credential.
func (s *StaticFile) Sandboxes() []string {
	return sortedKeys(s.bySandbox)
}

// Applications lists every application name the file holds an entry for,
// sorted. A caller refuses a name the document does not map, so a misspelled
// entry cannot silently fall back to the shared credential.
func (s *StaticFile) Applications() []string {
	return sortedKeys(s.byApplication)
}

// Scoped counts the entries that name a sandbox or an application. Such an
// entry answers only through a view, so a caller that reads the file as the
// process source refuses a file holding one.
func (s *StaticFile) Scoped() int {
	total := 0
	for _, table := range s.bySandbox {
		total += len(table)
	}
	for _, table := range s.byApplication {
		total += len(table)
	}
	return total
}

func sortedKeys(tables map[string]map[string]string) []string {
	out := make([]string, 0, len(tables))
	for name := range tables {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// table returns the resource table an entry belongs in, creating a scoped
// table on first use.
func (s *StaticFile) table(entry staticEntry) map[string]string {
	switch {
	case entry.Sandbox != "":
		return scopedTable(s.bySandbox, entry.Sandbox)
	case entry.Application != "":
		return scopedTable(s.byApplication, entry.Application)
	default:
		return s.byResource
	}
}

func scopedTable(tables map[string]map[string]string, name string) map[string]string {
	table, ok := tables[name]
	if !ok {
		table = make(map[string]string)
		tables[name] = table
	}
	return table
}

func (s *StaticFile) count() int {
	return len(s.byResource) + s.Scoped()
}

// View is a StaticFile read as one sandbox or one application. It is a
// Source.
type View struct {
	file *StaticFile
	// own holds the entries scoped to the sandbox or application. Nil when
	// the file holds none for it.
	own map[string]string
	// what names the scope for Describe.
	what string
}

// Credential returns the scope's own credential for the resource, or the
// shared one.
func (v *View) Credential(ctx context.Context, resource string) (string, error) {
	if value, ok := v.own[resource]; ok {
		return value, nil
	}
	return v.file.Credential(ctx, resource)
}

// Describe names the scope and the file.
func (v *View) Describe() string {
	return fmt.Sprintf("%s reading %s", v.what, v.file.Describe())
}
