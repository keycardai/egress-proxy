package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/config"
	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// runSettingsCommand drives the subcommand the way a chart lint does: the
// built binary, no document and no socket.
func runSettingsCommand(t *testing.T) settingsReport {
	t.Helper()
	var stdout bytes.Buffer
	cmd := command(&stdout, &stdout, func(context.Context, flags) error {
		t.Fatal("the serve path ran for a settings call")
		return nil
	})
	require.NoError(t, cmd.Run(t.Context(), []string{"egress-proxy", settingsName}), "run %s", settingsName)

	var report settingsReport
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &report), "the output is JSON:\n%s", stdout.String())
	return report
}

// TestSettingsCoverEveryFlag pins that the report is derived from the flag
// set rather than written down. Every flag reads exactly one variable, so
// the counts match. A flag added without a variable, and two flags sharing
// one, both fail here without an edit to this test.
func TestSettingsCoverEveryFlag(t *testing.T) {
	t.Parallel()
	var opts flags
	report := runSettingsCommand(t)

	names := map[string]bool{}
	variables := map[string]bool{}
	for _, entry := range report.Settings {
		assert.True(t, strings.HasPrefix(entry.Env, config.EnvPrefix),
			"%s is outside the %s namespace", entry.Env, config.EnvPrefix)
		assert.NotEmpty(t, entry.Usage, "--%s says nothing about what it sets", entry.Flag)
		names[entry.Flag] = true
		variables[entry.Env] = true
	}
	assert.Len(t, report.Settings, len(flagSet(&opts)), "one setting per flag")
	assert.Len(t, names, len(flagSet(&opts)), "one entry per flag name")
	assert.Len(t, variables, len(flagSet(&opts)), "one variable per flag")
}

// TestSettingsPublishWhatADeploymentHasToMatch covers the values a chart
// reads out of the report. The defaults come from the document parser, so
// a changed default reaches the report without an edit here, and these
// rows pin the ones a pod has to agree with.
func TestSettingsPublishWhatADeploymentHasToMatch(t *testing.T) {
	t.Parallel()
	report := runSettingsCommand(t)

	assert.Equal(t, settingsSchema, report.Schema, "schema")
	assert.Equal(t, config.EnvPrefix, report.EnvPrefix, "env_prefix")
	assert.Equal(t, probeName, report.Probe.Subcommand, "the probe subcommand a manifest runs")
	assert.Equal(t, probeRoutes(), report.Probe.Routes, "the routes that subcommand serves")
	assert.Equal(t, netsetupDefaults{
		ProxyUID:     netsetup.DefaultProxyUID,
		RedirectPort: netsetup.DefaultRedirectPort,
		CapturePorts: netsetup.DefaultConfig().CapturePorts,
		ReceiptPath:  netsetup.DefaultReceiptPath,
	}, report.Netsetup, "the capture defaults the pod has to agree with")

	byFlag := map[string]settingEntry{}
	for _, entry := range report.Settings {
		byFlag[entry.Flag] = entry
	}
	tests := []struct {
		flag        string
		wantEnv     string
		wantDefault string
		// noDefault is a setting the parser leaves empty.
		noDefault bool
	}{
		{flag: "config", wantEnv: config.EnvPrefix + "CONFIG", noDefault: true},
		{flag: "connect", wantEnv: config.EnvPrefix + "CONNECT", wantDefault: config.DefaultConnect},
		{flag: "admin", wantEnv: config.EnvPrefix + "ADMIN", wantDefault: config.DefaultAdmin},
		{flag: "transparent-port", wantEnv: config.EnvPrefix + "TRANSPARENT_PORT", noDefault: true},
		{
			flag: "netsetup-receipt", wantEnv: config.EnvPrefix + "NETSETUP_RECEIPT",
			wantDefault: netsetup.DefaultReceiptPath,
		},
		{flag: "ca-out-dir", wantEnv: config.EnvPrefix + "CA_OUT_DIR", wantDefault: config.DefaultCAOutDir},
		{flag: "ca-state-dir", wantEnv: config.EnvPrefix + "CA_STATE_DIR", noDefault: true},
		{flag: "exchange-timeout", wantEnv: config.EnvPrefix + "EXCHANGE_TIMEOUT", wantDefault: "10s"},
	}
	for _, tc := range tests {
		t.Run(tc.flag, func(t *testing.T) {
			t.Parallel()
			entry, ok := byFlag[tc.flag]
			require.True(t, ok, "the report has no --%s", tc.flag)
			assert.Equal(t, tc.wantEnv, entry.Env, "the variable that fills --%s", tc.flag)
			if tc.noDefault {
				assert.Nil(t, entry.Default, "--%s has no default and the report must say so", tc.flag)
				return
			}
			require.NotNil(t, entry.Default, "--%s has a default the report left out", tc.flag)
			assert.Equal(t, tc.wantDefault, *entry.Default, "the default for --%s", tc.flag)
		})
	}
}
