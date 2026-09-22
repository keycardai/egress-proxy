package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPanicOutcome pins the audit text each panic out of the forward
// produces. The abort is the reverse proxy saying the response did not
// complete; anything else is a defect and says so.
func TestPanicOutcome(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		recovered  any
		requestErr error
		want       string
	}{
		{
			name:      "abort with the request still live",
			recovered: http.ErrAbortHandler,
			want:      "the upstream response body did not complete",
		},
		{
			name:       "abort after the request ended",
			recovered:  http.ErrAbortHandler,
			requestErr: context.Canceled,
			want:       "the client went away or the server stopped before the response completed",
		},
		{
			name:      "an error that is not the abort",
			recovered: io.ErrUnexpectedEOF,
			want:      "the handler panicked: unexpected EOF",
		},
		{
			name:      "a value that is not an error",
			recovered: 42,
			want:      "the handler panicked: 42",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, panicOutcome(tc.recovered, tc.requestErr), "outcome text")
		})
	}
}

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

// TestInflightSealsOnWait pins the seal. A handler that enters before the
// join is counted and joined, the join admits none after it, and a join
// that ran out of time reports the drain once the counted handlers leave.
func TestInflightSealsOnWait(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		running int
		want    bool
	}{
		{name: "no handler running", running: 0, want: true},
		{name: "one handler running", running: 1, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var handlers inflight
			for range tc.running {
				require.True(t, handlers.enter(), "enter before the wait")
			}
			assert.Equal(t, tc.want, handlers.wait(20*time.Millisecond), "wait within the bound")
			assert.False(t, handlers.enter(), "enter after the wait")
			for range tc.running {
				handlers.leave()
			}
			assert.True(t, handlers.wait(20*time.Millisecond), "wait after the handlers left")
		})
	}
}

// TestInflightWaitJoins pins the join: wait blocks while a handler runs,
// reports the drain when the last one leaves, and gives up at the bound.
// synctest makes the blocking and the clock deterministic.
func TestInflightWaitJoins(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		leaves bool
		want   bool
	}{
		{name: "the handler leaves", leaves: true, want: true},
		{name: "the handler stays past the bound", leaves: false, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				var handlers inflight
				require.True(t, handlers.enter(), "enter before the wait")
				joined := make(chan bool, 1)
				go func() { joined <- handlers.wait(handlerJoinBound) }()
				synctest.Wait()
				select {
				case <-joined:
					t.Fatal("wait returned while a handler runs")
				default:
				}
				if tc.leaves {
					handlers.leave()
				} else {
					time.Sleep(handlerJoinBound)
				}
				synctest.Wait()
				select {
				case got := <-joined:
					assert.Equal(t, tc.want, got, "the join reports the drain")
				default:
					t.Fatal("wait did not return")
				}
			})
		})
	}
}
