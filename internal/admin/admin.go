// Package admin serves health, readiness and process information over a
// Unix socket.
//
// The admin surface is NEVER a TCP port, loopback included, because the proxy
// may share the pod's network namespace with the workload it governs. In such a
// configuration the workload could reach any network port that the proxy binds.
// A directory which only this proxy's uid can traverse keeps that workload
// out of the socket. The socket path could be a volume another container also
// mounts, so this process sets the directory mode on every start.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	// socketMode and dirMode keep the socket readable by the proxy's uid
	// alone.
	socketMode fs.FileMode = 0o600
	dirMode    fs.FileMode = 0o700
	// maxSocketPath is the longest path a Unix socket address holds on
	// every supported platform: sun_path is 104 bytes on macOS and 108 on
	// Linux.
	maxSocketPath = 103

	readHeaderTimeout = 5 * time.Second
	// shutdownGrace bounds how long Shutdown waits for a handler that is
	// still writing its response. Every request context derives from the run
	// context, so cancelling that context has already told each handler to
	// stop. A health probe is short.
	shutdownGrace = 5 * time.Second
)

var errSocketPath = errors.New("admin: socket path refused")

// Server answers /healthz, /readyz and /info on a Unix socket.
type Server struct {
	path     string
	listener net.Listener
	server   *http.Server
	logger   *slog.Logger
}

// Options are the socket and the answers the server gives on it.
type Options struct {
	// Path is the socket's absolute file system path.
	Path string
	// Info is called for every /info request and its result is written as
	// JSON.
	Info func() any
	// Ready decides /readyz. A nil error answers 200 and an error answers
	// 503 with the error text, so a probe reads why the process is not
	// serving yet. A nil Ready answers 503: readiness is what the kubelet
	// releases a workload on, so a server with no gate reports not ready
	// rather than ready.
	Ready func() error
	// Logger discards when nil.
	Logger *slog.Logger
}

// New creates the socket at opts.Path and serves the routes opts describes.
func New(ctx context.Context, opts Options) (*Server, error) {
	path, logger := opts.Path, opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: %q is not absolute", errSocketPath, path)
	}
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("%w: %q is %d bytes and a socket address holds at most %d",
			errSocketPath, path, len(path), maxSocketPath)
	}
	if err := prepareDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("admin: listen on %s: %w", path, err)
	}
	// Listen creates the socket with the process umask applied, so the socket
	// is world-connectable until the chmod below. The directory mode is what
	// closes that window: no other uid can traverse into it.
	if err := os.Chmod(path, socketMode); err != nil {
		return nil, errors.Join(fmt.Errorf("admin: set mode on %s: %w", path, err), listener.Close(), removeSocket(path))
	}

	return &Server{
		path:     path,
		listener: listener,
		server:   &http.Server{Handler: routes(opts), ReadHeaderTimeout: readHeaderTimeout},
		logger:   logger,
	}, nil
}

// routes builds the admin surface. /healthz says the process is alive,
// /readyz says it is serving, and /info reports what it enforces.
func routes(opts Options) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeText(w, http.StatusOK, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if opts.Ready == nil {
			writeText(w, http.StatusServiceUnavailable, "no readiness gate is configured\n")
			return
		}
		if err := opts.Ready(); err != nil {
			writeText(w, http.StatusServiceUnavailable, err.Error()+"\n")
			return
		}
		writeText(w, http.StatusOK, "ok\n")
	})
	mux.HandleFunc("GET /info", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(opts.Info())
	})
	return mux
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// Run answers requests until ctx is cancelled, then shuts down and unlinks
// the socket. It returns a serve failure, or nil after a shutdown the
// context asked for. A request gets the run context's values and not its
// cancellation, so cancelling ctx starts the drain rather than ending the
// requests in flight.
func (s *Server) Run(ctx context.Context) error {
	requestCtx := context.WithoutCancel(ctx)
	s.server.BaseContext = func(net.Listener) context.Context { return requestCtx }
	served := make(chan error, 1)
	go func() { served <- s.server.Serve(s.listener) }()
	var failure error
	select {
	case <-ctx.Done():
		s.stop(ctx)
		// Serve closes the listener as it returns, and closing a Unix
		// listener unlinks its path. Run waits for Serve, so no unlink is
		// pending once Run has returned and nothing can remove a socket a
		// later listener put at the same path.
		if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Warn("admin: serve returned after shutdown", slog.String("error", err.Error()))
		}
	case err := <-served:
		failure = fmt.Errorf("admin: serve: %w", err)
		s.stop(ctx)
	}
	return failure
}

// Path is the socket's filesystem path.
func (s *Server) Path() string {
	return s.path
}

// stop closes the listener and idle connections, waits up to shutdownGrace for
// a handler that is still writing, and unlinks the listen socket. A shutdown
// that runs out of time is logged and the remaining connections are closed.
func (s *Server) stop(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		s.logger.Warn("admin: graceful shutdown did not finish; closing the remaining connections",
			slog.String("error", err.Error()))
		if err := s.server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.logger.Warn("admin: closing the server", slog.String("error", err.Error()))
		}
	}
	if err := removeSocket(s.path); err != nil {
		s.logger.Warn("admin: unlinking the socket", slog.String("error", err.Error()))
	}
}

// prepareDir creates the socket's directory and leaves it traversable by the
// proxy's uid alone. MkdirAll applies dirMode only to a directory it creates,
// and a restart finds the one an earlier start left behind, so the mode is
// set on every start. Only the owner may set it: listen.admin must name a
// directory this process creates inside a volume, never the mount point.
func prepareDir(dir string) error {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("admin: create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return fmt.Errorf("admin: set mode on %s: %w", dir, err)
	}
	return checkDirMode(dir)
}

// checkDirMode refuses a socket directory another uid can traverse. Such a uid
// can unlink the socket and bind its own in its place, so the admin surface
// would answer for something the proxy does not control.
func checkDirMode(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("admin: stat %s: %w", dir, err)
	}
	if perm := info.Mode().Perm(); perm != dirMode {
		return fmt.Errorf("%w: the socket directory %s has mode %#o and must have mode %#o",
			errSocketPath, dir, perm, dirMode)
	}
	return nil
}

// removeSocket unlinks the socket if it exists.
func removeSocket(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("admin: remove %s: %w", path, err)
	}
	return nil
}

// removeStaleSocket clears a socket a previous run left behind. It refuses to
// unlink anything that is not a socket, preventing misconfiguration from
// causing unintended behavior.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("admin: stat %s: %w", path, err)
	}
	if info.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("%w: %s exists and is not a socket", errSocketPath, path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("admin: remove the stale socket %s: %w", path, err)
	}
	return nil
}
