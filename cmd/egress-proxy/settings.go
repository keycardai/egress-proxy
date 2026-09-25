package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/keycardai/egress-proxy/internal/config"
	"github.com/keycardai/egress-proxy/internal/netsetup"
)

// settingsName is the subcommand that publishes the settings surface.
const settingsName = "settings"

// settingsSchema is the version of the JSON this subcommand prints. A
// consumer keys on it. Add a field without changing it, and raise it when a
// field changes meaning or goes away.
const settingsSchema = 1

// errSettings is a settings surface this command refuses to publish.
var errSettings = errors.New(settingsName)

// settingsReport is what the subcommand prints. A chart lint outside this
// repository reads it to decide which variables a manifest may set and
// which defaults it has to match.
type settingsReport struct {
	Schema    int              `json:"schema"`
	Binary    string           `json:"binary"`
	Version   string           `json:"version"`
	EnvPrefix string           `json:"env_prefix"`
	Settings  []settingEntry   `json:"settings"`
	Probe     probeSurface     `json:"probe"`
	Netsetup  netsetupDefaults `json:"netsetup"`
}

// settingEntry is one setting: the variable that fills it, the flag that
// wins over that variable, and the value the document parser applies when
// neither is set.
type settingEntry struct {
	Env string `json:"env"`
	// Flag is the long option, without its leading dashes.
	Flag  string `json:"flag"`
	Usage string `json:"usage"`
	// Default is the value the parser applies, and null for a setting it
	// leaves empty. A duration is a JSON number of whole seconds, so a
	// consumer compares it arithmetically. Every other default is a string.
	Default any `json:"default"`
}

// probeSurface is how a manifest probes this binary.
type probeSurface struct {
	Subcommand string   `json:"subcommand"`
	Routes     []string `json:"routes"`
}

// netsetupDefaults are the values the init container programs and the pod
// has to agree with. egress-netsetup reads no environment variable, so a
// manifest passes each of these as a flag or takes the default.
type netsetupDefaults struct {
	ProxyUID     int    `json:"proxy_uid"`
	RedirectPort int    `json:"redirect_port"`
	CapturePorts []int  `json:"capture_ports"`
	ReceiptPath  string `json:"receipt_path"`
}

// settingsCommand publishes what this binary accepts, with no document, no
// socket and no running proxy.
//
// A chart outside this repository decides the pod, and its lint runs this
// subcommand to learn the settings surface. Publishing it from the flag set
// keeps the two in step: a setting this binary gains appears here on the
// next build.
func settingsCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:  settingsName,
		Usage: "print the settings this binary accepts, as JSON",
		Description: "Prints every " + config.EnvPrefix + " variable, the flag that fills the same\n" +
			"setting, and the value the document parser applies when neither is set. It\n" +
			"also prints the probe routes and the netsetup defaults a pod has to match.\n" +
			"It reads no document and dials no socket, so it answers before the proxy\n" +
			"runs and in an image that has nothing else in it.",
		HideHelpCommand: true,
		Action: func(_ context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() > 0 {
				return fmt.Errorf("%w: unexpected argument %q", errSettings, cmd.Args().First())
			}
			return runSettings(stdout)
		},
	}
}

func runSettings(stdout io.Writer) error {
	report, err := settings()
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("%w: %w", errSettings, err)
	}
	return nil
}

// settings builds the report from the flag set itself. NEVER replace the
// walk with a written list: a list drifts, and a lint that reads a stale
// one refuses a setting this binary accepts or passes one it ignores.
//
// A flag that names no variable, or two flags that name one variable, stop
// the command. Publishing a surface this binary does not have is worse than
// publishing nothing.
func settings() (*settingsReport, error) {
	defaults, err := parserDefaults()
	if err != nil {
		return nil, err
	}
	var opts flags
	entries := make([]settingEntry, 0, len(flagSet(&opts)))
	seen := map[string]string{}
	for _, flag := range flagSet(&opts) {
		entry, err := describeFlag(flag, defaults)
		if err != nil {
			return nil, err
		}
		if other, duplicate := seen[entry.Env]; duplicate {
			return nil, fmt.Errorf("%w: --%s and --%s both read %s", errSettings, other, entry.Flag, entry.Env)
		}
		seen[entry.Env] = entry.Flag
		entries = append(entries, entry)
	}
	capture := netsetup.DefaultConfig()
	return &settingsReport{
		Schema:    settingsSchema,
		Binary:    "egress-proxy",
		Version:   version(),
		EnvPrefix: config.EnvPrefix,
		Settings:  entries,
		Probe:     probeSurface{Subcommand: probeName, Routes: probeRoutes()},
		Netsetup: netsetupDefaults{
			ProxyUID:     capture.ProxyUID,
			RedirectPort: capture.RedirectPort,
			CapturePorts: capture.CapturePorts,
			ReceiptPath:  netsetup.DefaultReceiptPath,
		},
	}, nil
}

// describeFlag reads one flag's name, variable and usage.
func describeFlag(flag cli.Flag, defaults map[string]any) (settingEntry, error) {
	name := flag.Names()[0]
	documented, ok := flag.(cli.DocGenerationFlag)
	if !ok {
		return settingEntry{}, fmt.Errorf("%w: --%s reports no variable", errSettings, name)
	}
	vars := documented.GetEnvVars()
	if len(vars) != 1 {
		return settingEntry{}, fmt.Errorf("%w: --%s reads %d variables and each setting has exactly one",
			errSettings, name, len(vars))
	}
	entry := settingEntry{Env: vars[0], Flag: name, Usage: documented.GetUsage()}
	if value, has := defaults[name]; has {
		entry.Default = value
	}
	return entry, nil
}

// defaultDocument is the smallest document the parser accepts. Parsing it
// with no override gives the defaults in force, so this command prints what
// the parser applies rather than a second copy of the constants.
const defaultDocument = "version: 1\nsandbox:\n  id: settings\nendpoints:\n  - host: example.com\n"

// parserDefaults maps a flag to the value the document parser applies when
// the document, the variable and the flag all leave the setting out.
//
// Every flag is in this map or in flagsWithNoDefault(), and never in both.
// TestEverySettingSaysWhetherItHasADefault holds that, so a flag added to
// the flag set fails the build until its author says which it is. A flag
// missing from both would publish "default": null, and a consumer reads
// that as a setting the parser leaves empty.
func parserDefaults() (map[string]any, error) {
	cfg, err := config.Parse([]byte(defaultDocument), config.Overrides{})
	if err != nil {
		return nil, fmt.Errorf("%w: read the defaults: %w", errSettings, err)
	}
	return map[string]any{
		"connect":                 cfg.Listen.Connect,
		"admin":                   cfg.Listen.Admin,
		"netsetup-receipt":        cfg.Netsetup.Receipt,
		"ca-out-dir":              cfg.CA.OutDir,
		"leaf-ttl":                seconds(cfg.CA.LeafTTL.Duration()),
		"cache-size":              strconv.Itoa(cfg.CA.CacheSize),
		"max-connections":         strconv.Itoa(cfg.Limits.MaxConnections),
		"idle-timeout":            seconds(cfg.Limits.IdleTimeout.Duration()),
		"response-header-timeout": seconds(cfg.Limits.ResponseHeaderTimeout.Duration()),
		"exchange-timeout":        seconds(cfg.Limits.ExchangeTimeout.Duration()),
	}, nil
}

// flagsWithNoDefault names the settings the document parser leaves empty.
// The report publishes null for each of them, which says the setting is
// unset until a document, a variable or a flag fills it.
func flagsWithNoDefault() map[string]bool {
	return map[string]bool{
		"config":                 true,
		"sandbox-id":             true,
		"zone-url":               true,
		"client-id":              true,
		"workload-token-file":    true,
		"impersonate-user":       true,
		"transparent-port":       true,
		"ca-state-dir":           true,
		"client-secret-file":     true,
		"credential-static-file": true,
		"upstream-ca-file":       true,
	}
}

// seconds is a duration as the report publishes it. A consumer compares a
// number arithmetically, where Go's "24h0m0s" needs a parser the chart lint
// reading this does not have.
func seconds(d time.Duration) int64 {
	return int64(d / time.Second)
}
