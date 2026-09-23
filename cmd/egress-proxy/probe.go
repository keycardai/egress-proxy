package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/keycardai/egress-proxy/internal/config"
)

// probeTimeout bounds one probe. The kubelet applies its own timeout on top
// of it, and this one keeps a probe from outliving the period between
// probes when the socket accepts and the process never answers.
const probeTimeout = 5 * time.Second

// probeName is the subcommand a manifest's probe runs.
const probeName = "probe"

// maxProbeBody bounds what a probe reads off the socket. /info is a few
// kilobytes. The request context bounds a socket that accepts and never
// answers, and this bounds one that answers without stopping.
const maxProbeBody = 1 << 20

// probeRoutes are the admin routes this subcommand dials, in help order.
func probeRoutes() []string { return []string{"healthz", "readyz", "info"} }

// errProbe is every probe refusal: an unknown route, a socket that does not
// answer, or a status other than 200.
var errProbe = errors.New("probe")

// probeCommand dials the admin Unix socket, prints the answer and exits
// non-zero on anything but a 200.
//
// This is how the kubelet, an operator and the cluster lane reach the admin
// surface. That surface is a socket in the proxy's mount namespace and
// never a port, so an httpGet probe has nothing to dial, and the image has
// no shell and no curl to dial it with.
func probeCommand(opts *flags, stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:      probeName,
		Usage:     "dial the admin socket, print one route's answer and exit non-zero on anything but a 200",
		ArgsUsage: "<" + strings.Join(probeRoutes(), "|") + ">",
		Description: "Reads the socket named by --admin or " + config.EnvPrefix + "ADMIN, the same\n" +
			"setting the serving process reads, and defaults to " + config.DefaultAdmin + ".\n" +
			"healthz says the process is alive. readyz says every frontend this process\n" +
			"runs is bound and ca.crt is written. info reports what the process enforces.",
		HideHelpCommand: true,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 1 {
				return fmt.Errorf("%w: name one route: %s", errProbe, strings.Join(probeRoutes(), ", "))
			}
			return runProbe(ctx, cmd.Args().First(), adminSocket(opts), stdout)
		},
	}
}

// adminSocket is the socket the serving process in this container listens
// on. The probe runs in that container, so the same flag and the same
// variable name it.
func adminSocket(opts *flags) string {
	if opts.admin != "" {
		return opts.admin
	}
	return config.DefaultAdmin
}

// runProbe writes the route's body to stdout and returns an error unless
// the answer was a 200.
func runProbe(ctx context.Context, route, socket string, stdout io.Writer) error {
	if !slices.Contains(probeRoutes(), route) {
		return fmt.Errorf("%w: %q is not a route: %s", errProbe, route, strings.Join(probeRoutes(), ", "))
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://admin/"+route, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", errProbe, err)
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s on %s: %w", errProbe, route, socket, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
	if err != nil {
		return fmt.Errorf("%w: %s on %s: %w", errProbe, route, socket, err)
	}
	fmt.Fprint(stdout, string(body))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s on %s answered %d", errProbe, route, socket, resp.StatusCode)
	}
	return nil
}
