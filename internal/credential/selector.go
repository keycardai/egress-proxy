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
	// ImpersonatesOwner reports that the source exchanges for the owner
	// the assertion names, so the record names the owner id as the user.
	ImpersonatesOwner bool
}

// Selector maps each sandbox and each application the proxy serves to its
// credential source. The two maps are separate: an assertion names an
// application or falls back to its sandbox, never both. One source can
// instead answer for every application, when the document names one
// identity for all of them.
type Selector struct {
	bySandbox     map[SandboxKey]Selected
	byApplication map[string]Selected
	every         *Selected
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

// SetEvery makes one source answer for every application an assertion
// names. It is refused beside an application map, because the map would
// never be consulted and a record could not say which answered.
func (s *Selector) SetEvery(selected Selected) error {
	switch {
	case selected.Source == nil:
		return fmt.Errorf("%w: the source for every application is nil", errSelector)
	case len(s.byApplication) > 0:
		return fmt.Errorf("%w: a source for every application cannot be set beside an application map", errSelector)
	}
	s.every = &selected
	return nil
}

// Every returns the source that answers for every application, and
// whether one is set.
func (s *Selector) Every() (Selected, bool) {
	if s.every == nil {
		return Selected{}, false
	}
	return *s.every, true
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
// for them, and how many of those exchange for the sandbox owner. It names
// no credential.
func (s *Selector) Describe() string {
	if s.every != nil {
		return s.describeEvery()
	}
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
	if n := s.count(func(selected Selected) bool { return selected.SubjectIsClient }); n > 0 {
		described += fmt.Sprintf(", %d exchanged as the sandbox", n)
	}
	if n := s.count(func(selected Selected) bool { return selected.ImpersonatesOwner }); n > 0 {
		described += fmt.Sprintf(", %d of them for the sandbox owner", n)
	}
	return described
}

// describeEvery is Describe for one identity serving every application.
func (s *Selector) describeEvery() string {
	described := "one identity for every application selected by assertion"
	switch {
	case s.every.ImpersonatesOwner:
		described += ", exchanged as the sandbox for the sandbox owner"
	case s.every.SubjectIsClient:
		described += ", exchanged as the sandbox"
	}
	return described
}

// count is how many entries in both maps match.
func (s *Selector) count(match func(Selected) bool) int {
	count := 0
	for _, selected := range s.byApplication {
		if match(selected) {
			count++
		}
	}
	for _, selected := range s.bySandbox {
		if match(selected) {
			count++
		}
	}
	return count
}
