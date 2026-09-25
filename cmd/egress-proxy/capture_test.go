package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/config"
	"github.com/keycardai/egress-proxy/internal/netsetup"
	"github.com/keycardai/egress-proxy/internal/transparent"
)

// TestCapture runs the start-up check against a receipt in a temporary
// directory, with the real capability and owner reads. The receipt names
// this process's own uid, so a case passes the check only where an
// unprivileged sidecar would. The sysctl read answers the kernel default,
// because Docker lowers the real one to 0 and the check then refuses every
// case. A platform with no SO_ORIGINAL_DST refuses every case that
// configures a transparent frontend, before any receipt is read.
func TestCapture(t *testing.T) {
	t.Parallel()
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("the check refuses a ruleset that exempts uid 0, and this test runs as root")
	}
	tests := []struct {
		name string
		// listen is the listen section of the document.
		listen string
		// receipt edits the receipt the case writes. Nil writes none.
		receipt func(*netsetup.Receipt)
		// wantErr is the refusal on a platform that can recover a redirected
		// destination.
		wantErr   error
		wantLog   []string
		wantNoLog string
	}{
		{
			name:      "no transparent frontend, which reads no receipt",
			listen:    "listen:\n  connect: \"127.0.0.1:3128\"\n",
			wantNoLog: "network capture in force",
		},
		{
			name:    "a transparent frontend with no receipt",
			listen:  "listen:\n  transparent: \"0.0.0.0:1015\"\n",
			wantErr: netsetup.ErrNoReceipt,
		},
		{
			name:    "a transparent frontend under a receipt that matches it",
			listen:  "listen:\n  transparent: \"0.0.0.0:1015\"\n",
			receipt: func(*netsetup.Receipt) {},
			wantLog: []string{
				`"msg":"network capture in force"`, `"redirect_port":1015`, `"capture_ports":[80,443]`,
			},
			wantNoLog: "the redirect does not cover",
		},
		{
			name:    "a cleartext port the redirect does not cover",
			listen:  "listen:\n  transparent: \"0.0.0.0:1015\"\n  cleartext_ports: [80, 8080]\n",
			receipt: func(*netsetup.Receipt) {},
			wantLog: []string{`names a port the redirect does not cover`, `"port":8080`},
		},
		{
			name:    "a receipt whose rules exclude another uid",
			listen:  "listen:\n  transparent: \"0.0.0.0:1015\"\n",
			receipt: func(r *netsetup.Receipt) { r.ProxyUID = uid + 1 },
			wantErr: netsetup.ErrNotContained,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "netsetup.json")
			if tc.receipt != nil {
				receipt := netsetup.Receipt{
					Version:             1,
					VerifiedAt:          time.Now().Add(-time.Minute).UTC(),
					Verified:            true,
					ProxyUID:            uid,
					RedirectPort:        netsetup.DefaultRedirectPort,
					CapturePorts:        []int{80, 443},
					Families:            []string{"ipv4"},
					RulesetDigest:       "sha256:test",
					CapabilitiesDropped: true,
				}
				tc.receipt(&receipt)
				require.NoError(t, netsetup.WriteReceipt(path, receipt), "write the receipt")
			}
			cfg, err := config.Parse([]byte("version: 1\nsandbox:\n  id: sbx-1\n"+tc.listen+
				"netsetup:\n  receipt: "+path+"\nendpoints:\n  - host: pypi.org\n"), config.Overrides{})
			require.NoError(t, err, "parse the document")
			var logs bytes.Buffer
			frontend, err := capture(cfg, nil, slog.New(slog.NewJSONHandler(&logs, nil)), netsetup.ContainmentRequest{
				PortStart: func() (int, error) { return 1024, nil },
			})
			wantErr := tc.wantErr
			if !transparent.Supported && cfg.Listen.Transparent != "" {
				wantErr = transparent.ErrNotSupported
			}
			if wantErr != nil {
				require.ErrorIs(t, err, wantErr, "the refusal the caller keys on")
				assert.Nil(t, frontend, "a refused check builds no frontend")
				return
			}
			require.NoError(t, err, "the check passes")
			assert.Equal(t, cfg.Listen.Transparent != "", frontend != nil, "a frontend exactly when one is configured")
			for _, want := range tc.wantLog {
				assert.Contains(t, logs.String(), want, "the start-up log")
			}
			if tc.wantNoLog != "" {
				assert.NotContains(t, logs.String(), tc.wantNoLog, "the start-up log")
			}
		})
	}
}

func TestUncaptured(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		captured  []int
		cleartext []int
		want      []int
	}{
		{name: "every cleartext port captured", captured: []int{80, 443}, cleartext: []int{80}},
		{
			name:     "one cleartext port outside the redirect",
			captured: []int{80, 443}, cleartext: []int{80, 8080}, want: []int{8080},
		},
		{name: "a redirect that captures nothing", cleartext: []int{80, 8080}, want: []int{80, 8080}},
		{name: "no cleartext ports", captured: []int{443}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, uncaptured(tc.captured, tc.cleartext), "the ports nothing reaches")
		})
	}
}
