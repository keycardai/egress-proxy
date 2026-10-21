package exchange

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAuthorizationHintNamesTheZone pins the command the detail carries: the
// CLI's consent command with the zone id, which is the first label of the
// zone's host, and without one when the zone is an address.
func TestAuthorizationHintNamesTheZone(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		zone string
		want string
	}{
		"a hosted zone": {
			zone: "https://greendale.keycard.cloud",
			want: "Run 'keycard auth resource https://api.github.com --zone greendale' as that person, then retry.",
		},
		"an address": {
			zone: "https://127.0.0.1:8443",
			want: "Run 'keycard auth resource https://api.github.com' as that person, then retry.",
		},
		"not a URL": {
			zone: "::",
			want: "Run 'keycard auth resource https://api.github.com' as that person, then retry.",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, authorizationHint(tc.zone, "https://api.github.com"))
		})
	}
}
