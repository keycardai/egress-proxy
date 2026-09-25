package main

import (
	"bytes"
	"errors"
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
// directory, using the real capability, namespace, and owner reads. The
// receipt names this process's uid and network namespace, so the check passes
// only as it does for an unprivileged sidecar. The test supplies the kernel
// default for the
// port-start check. A live sidecar reads the container's sysctl, which Docker
// and containerd can set to 0. The check rejects 0 because the workload could
// bind port 1015. A platform without SO_ORIGINAL_DST refuses a configured
// transparent frontend before it reads the receipt.
func TestCapture(t *testing.T) {
	t.Parallel()
	uid := os.Getuid()
	require.NotZero(t, uid, "do not run the tests as root. The check refuses a ruleset that exempts uid 0, "+
		"so this test cannot pass as root")
	namespace := thisNetNamespace(t)
	tests := []struct {
		name string
		// listen is the document's listen section.
		listen string
		// receipt edits the receipt this case writes. Nil writes no receipt.
		receipt func(*netsetup.Receipt)
		// wantErr is the refusal on a platform that can recover the redirected
		// destination.
		wantErr   error
		wantLog   []string
		wantNoLog string
	}{
		{
			name:      "no transparent frontend, no receipt read",
			listen:    "listen:\n  connect: \"127.0.0.1:3128\"\n",
			wantNoLog: "transparent network capture enabled",
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
				`"msg":"transparent network capture enabled"`, `"redirect_port":1015`, `"capture_ports":[80,443]`,
			},
			wantNoLog: "outside of the network capture and transparent redirect",
		},
		{
			name:    "a cleartext port outside of the network capture and transparent redirect",
			listen:  "listen:\n  transparent: \"0.0.0.0:1015\"\n  cleartext_ports: [80, 8080]\n",
			receipt: func(*netsetup.Receipt) {},
			wantLog: []string{`names a port outside of the network capture and transparent redirect`, `"port":8080`},
		},
		{
			name:    "a receipt whose rules exclude the wrong uid",
			listen:  "listen:\n  transparent: \"0.0.0.0:1015\"\n",
			receipt: func(r *netsetup.Receipt) { r.ProxyUID = uid + 1 },
			wantErr: netsetup.ErrNotContained,
		},
		{
			name:    "a receipt written in another network namespace",
			listen:  "listen:\n  transparent: \"0.0.0.0:1015\"\n",
			receipt: func(r *netsetup.Receipt) { r.NetNamespace = &netsetup.NetNamespace{Device: 1, Inode: 1} },
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
					NetNamespace:        namespace,
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
				assert.Nil(t, frontend, "a capture error does not build a frontend")
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

// thisNetNamespace reads the network namespace of the test process. It is
// nil on a platform that does not report one, where the check is skipped.
func thisNetNamespace(t *testing.T) *netsetup.NetNamespace {
	t.Helper()
	namespace, err := netsetup.CurrentNetNamespace()
	if errors.Is(err, netsetup.ErrNetNamespaceNotSupported) {
		return nil
	}
	require.NoError(t, err, "read the network namespace")
	return &namespace
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
