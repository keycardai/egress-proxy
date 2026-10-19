package proxy

import (
	"encoding/json"
	"strconv"

	"github.com/keycardai/egress-proxy/internal/policy"
)

// contentTypeProblem is the media type of every refusal body, RFC 9457.
const contentTypeProblem = "application/problem+json"

// problem is the RFC 9457 document a refusal body carries. The members are
// exactly these: the headers say the same thing, so a client that reads
// either sees one answer. reason is an extension member so a client can
// switch on the code without parsing type.
type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	// Detail is the same already-redacted text as the detail header, so
	// the body can hold nothing the header does not.
	Detail   string        `json:"detail,omitempty"`
	Instance string        `json:"instance,omitempty"`
	Reason   policy.Reason `json:"reason"`
}

// denyBody is the body of every refusal, on each path the proxy answers one:
// the CONNECT line, a request inside a tunnel, and a cleartext connection on
// the transparent listener.
func denyBody(status int, reason policy.Reason, requestID, detail string) []byte {
	doc := problem{
		Type:   "https://keycard.ai/egress-proxy/deny/" + string(reason),
		Title:  reason.Title(),
		Status: status,
		Detail: detail,
		Reason: reason,
	}
	if requestID != "" {
		doc.Instance = "urn:keycard:request:" + requestID
	}
	body, err := json.Marshal(doc)
	if err != nil {
		// Unreachable: strings and an int always encode. The refusal still
		// names its status and reason.
		return []byte(`{"status":` + strconv.Itoa(status) + `,"reason":` + strconv.Quote(string(reason)) + "}\n")
	}
	return append(body, '\n')
}
