package credential

import (
	"errors"
	"fmt"
	"strings"
)

var errSelector = errors.New("sandbox selector")

// SandboxKey identifies one sandbox: its name within a runtime workspace.
type SandboxKey struct {
	Name      string
	Workspace string
}

// Selected is the source that answers for one sandbox or application and
// the identity it acts as, for the audit record.
type Selected struct {
	Source Source
	// ClientID is the application credential the source exchanges as.
	// Empty for a source that is not an exchange, and for one that
	// exchanges as the asserted sandbox.
	ClientID string
	// SubjectIsClient reports that the source presents the sandbox
	// assertion as its client, so the record names the assertion's subject
	// as the client id.
	SubjectIsClient bool
}

// Selector maps each sandbox and each application the proxy serves to its
// credential source. The two maps are separate: an assertion names an
// application or falls back to its sandbox, never both.
type Selector struct {
	bySandbox     map[SandboxKey]Selected
	byApplication map[string]Selected
}

// NewSelector returns an empty selector.
func NewSelector() *Selector {
	return &Selector{
		bySandbox:     make(map[SandboxKey]Selected),
		byApplication: make(map[string]Selected),
	}
}

// Add maps a sandbox to its source. A repeated key is refused, because two
// sources for one sandbox could not be told apart on a record.
func (s *Selector) Add(key SandboxKey, selected Selected) error {
	if selected.Source == nil {
		return fmt.Errorf("%w: sandbox %q in workspace %q has no source", errSelector, key.Name, key.Workspace)
	}
	if _, ok := s.bySandbox[key]; ok {
		return fmt.Errorf("%w: sandbox %q in workspace %q is mapped twice", errSelector, key.Name, key.Workspace)
	}
	s.bySandbox[key] = selected
	return nil
}

// AddApplication maps an application to its source. A repeated name is
// refused, because two sources for one application could not be told apart
// on a record.
func (s *Selector) AddApplication(name string, selected Selected) error {
	if selected.Source == nil {
		return fmt.Errorf("%w: application %q has no source", errSelector, name)
	}
	if _, ok := s.byApplication[name]; ok {
		return fmt.Errorf("%w: application %q is mapped twice", errSelector, name)
	}
	s.byApplication[name] = selected
	return nil
}

// Select returns the source for a sandbox, and whether the map names it.
func (s *Selector) Select(key SandboxKey) (Selected, bool) {
	selected, ok := s.bySandbox[key]
	return selected, ok
}

// HasApplications reports whether the document lists any application.
func (s *Selector) HasApplications() bool {
	return len(s.byApplication) > 0
}

// SelectApplication returns the source for an application, and whether the
// map names it.
func (s *Selector) SelectApplication(name string) (Selected, bool) {
	selected, ok := s.byApplication[name]
	return selected, ok
}

// Describe counts the maps for the start-up announcement and the admin
// socket. An empty map is left out, so a proxy serving sandboxes alone
// never mentions applications. It says how many entries exchange as the
// asserted sandbox, so an operator can see the proxy holds no credential
// for them. It names no credential.
func (s *Selector) Describe() string {
	var counts []string
	if n := len(s.byApplication); n > 0 {
		counts = append(counts, fmt.Sprintf("%d application", n))
	}
	if n := len(s.bySandbox); n > 0 {
		counts = append(counts, fmt.Sprintf("%d sandbox", n))
	}
	if len(counts) == 0 {
		return "no identities selected by assertion"
	}
	described := strings.Join(counts, " and ") + " identities selected by assertion"
	if n := s.subjectClients(); n > 0 {
		described += fmt.Sprintf(", %d exchanged as the sandbox", n)
	}
	return described
}

// subjectClients counts the entries whose source presents the assertion as
// its client.
func (s *Selector) subjectClients() int {
	count := 0
	for _, selected := range s.byApplication {
		if selected.SubjectIsClient {
			count++
		}
	}
	for _, selected := range s.bySandbox {
		if selected.SubjectIsClient {
			count++
		}
	}
	return count
}
