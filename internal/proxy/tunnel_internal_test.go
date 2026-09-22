package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestStatusRecorderKeepsOnlyFinalStatuses pins that an informational status
// never becomes the recorded one. The reverse proxy forwards a 1xx through
// WriteHeader and writes a 101 onto the hijacked connection, so a 103 before
// an upgrade must leave the recorder empty for the upstream's status.
func TestStatusRecorderKeepsOnlyFinalStatuses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		writes []int
		want   int
	}{
		{name: "an early hint alone", writes: []int{http.StatusEarlyHints}, want: 0},
		{name: "an early hint then a final status", writes: []int{http.StatusEarlyHints, http.StatusOK}, want: http.StatusOK},
		{name: "a final status alone", writes: []int{http.StatusBadGateway}, want: http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			recorder := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
			for _, status := range tc.writes {
				recorder.WriteHeader(status)
			}
			assert.Equal(t, tc.want, recorder.status, "recorded status")
		})
	}
}
