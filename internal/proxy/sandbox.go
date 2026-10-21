package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/keycardai/egress-proxy/internal/assertion"
	"github.com/keycardai/egress-proxy/internal/audit"
	"github.com/keycardai/egress-proxy/internal/credential"
	"github.com/keycardai/egress-proxy/internal/policy"
)

var (
	errSandboxOptions      = errors.New("sandbox identification")
	errNoAssertion         = errors.New("the request carries no sandbox assertion")
	errManyAssertions      = errors.New("the request carries more than one sandbox assertion")
	errSandboxUnmapped     = errors.New("no sandbox entry maps")
	errApplicationUnmapped = errors.New("no application entry maps")
)

// SandboxIdentification is how the proxy tells which sandbox sent a request
// when several share one runtime. A component the runtime trusts signs an
// assertion naming the sandbox and places it in Header. The proxy verifies
// it, selects the credential source of the application it names or else of
// the sandbox, removes the header, and names both on the request record.
type SandboxIdentification struct {
	// Header carries the assertion. Exactly one value is accepted.
	Header string
	// Verifier checks the assertion against the issuer's key.
	Verifier *assertion.Verifier
	// Selector maps the asserted application or sandbox to its source.
	Selector *credential.Selector
}

func (s *SandboxIdentification) validate() error {
	switch {
	case s.Header == "":
		return fmt.Errorf("%w: the header name is empty", errSandboxOptions)
	case s.Verifier == nil:
		return fmt.Errorf("%w: no verifier", errSandboxOptions)
	case s.Selector == nil:
		return fmt.Errorf("%w: no selector", errSandboxOptions)
	}
	return nil
}

// identify reads and verifies the request's assertion and puts the selected
// source on the forward. It returns the refusal when it cannot:
// sandbox_unidentified when there is no verifiable assertion, and the
// lookup's reason when a verified one names an application or a sandbox the
// map does not. The claims stay on the forward in the second case, so the
// record names what was refused.
func (s *Server) identify(r *http.Request, fwd *forward) (policy.Decision, bool) {
	ident := s.opts.Sandboxes
	values := r.Header.Values(ident.Header)
	switch len(values) {
	case 0:
		return refuse(policy.ReasonSandboxUnidentified, errNoAssertion), true
	case 1:
	default:
		return refuse(policy.ReasonSandboxUnidentified, errManyAssertions), true
	}
	claims, err := ident.Verifier.Verify(values[0], time.Now())
	if err != nil {
		return refuse(policy.ReasonSandboxUnidentified, err), true
	}
	fwd.sandbox = &claims
	selected, reason, err := ident.lookup(claims)
	if err != nil {
		return refuse(reason, err), true
	}
	fwd.source, fwd.token = selected.Source, values[0]
	fwd.clientID = selected.ClientID
	if selected.SubjectIsClient {
		fwd.clientID = claims.Subject
	}
	if selected.ImpersonatesOwner {
		fwd.user = claims.OwnerID
	}
	return policy.Decision{}, false
}

// lookup selects the source the claims name. The application map answers
// whenever the document lists applications: a sandbox id is new on every
// create, so the identity follows the application, and a mapped sandbox
// never rescues an application the map does not list. One identity for
// every application answers next, whatever the app claim. The sandbox map
// answers for a document that has neither. The reason is the code a
// refusal records, set whenever the error is.
func (s *SandboxIdentification) lookup(claims assertion.Claims) (credential.Selected, policy.Reason, error) {
	if s.Selector.HasApplications() {
		selected, ok := s.Selector.SelectApplication(claims.Application)
		if !ok {
			return credential.Selected{}, policy.ReasonApplicationUnknown,
				fmt.Errorf("%w application %q", errApplicationUnmapped, claims.Application)
		}
		return selected, "", nil
	}
	if selected, ok := s.Selector.Every(); ok {
		return selected, "", nil
	}
	selected, ok := s.Selector.Select(credential.SandboxKey{Name: claims.Sandbox, Workspace: claims.Workspace})
	if !ok {
		return credential.Selected{}, policy.ReasonSandboxUnknown,
			fmt.Errorf("%w sandbox %q in workspace %q", errSandboxUnmapped, claims.Sandbox, claims.Workspace)
	}
	return selected, "", nil
}

func refuse(reason policy.Reason, err error) policy.Decision {
	return policy.Decision{Verdict: policy.VerdictDeny, Reason: reason, Err: err}
}

// stampSandbox names the asserted sandbox, its application, its owner and
// the identity on a request record, with the user the identity exchanged
// for. A record with no asserted sandbox keeps the process-level sandbox.id.
func stampSandbox(record *audit.Record, fwd *forward) {
	if fwd.sandbox == nil {
		return
	}
	record.SandboxID = fwd.sandbox.Sandbox
	record.SandboxUUID = fwd.sandbox.SandboxUUID
	record.Application = fwd.sandbox.Application
	record.OnBehalfOf = fwd.sandbox.Owner
	if fwd.clientID != "" {
		record.Identity = &audit.Identity{ClientID: fwd.clientID, User: fwd.user}
	}
}
