//go:build acceptance

// Package acceptance drives the built egress-proxy binary the way a pod
// does: through its flags and environment, with an external client, reading
// its audit stream and its exit status. Each scenario is a testscript under
// testdata, named for what it proves. Beyond testscript's own commands, the
// scripts use the commands registered in TestAcceptance.
//
// The package is behind the acceptance build tag, so `go test ./...` does
// not build and run binaries. `make acceptance` does.
package acceptance_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/keycardai/egress-proxy/internal/ca"
	"github.com/keycardai/egress-proxy/test/fakeas"
)

// waitFor bounds every wait a script asks for.
const waitFor = 10 * time.Second

// binDir holds the binary TestMain builds, prepended to every script's PATH.
var binDir string //nolint:gochecknoglobals // set once in TestMain

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "egress-proxy-acceptance-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	build := exec.CommandContext(context.Background(), "go", "build", "-o", filepath.Join(dir, "egress-proxy"),
		"../../cmd/egress-proxy")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build egress-proxy: %v\n", err)
		os.Exit(1)
	}
	binDir = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestAcceptance(t *testing.T) {
	t.Parallel()
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		Setup: func(env *testscript.Env) error {
			env.Setenv("PATH", binDir+string(os.PathListSeparator)+env.Getenv("PATH"))
			return nil
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"upstream": cmdUpstream,
			"fakeas":   cmdFakeAS,
			"satoken":  cmdSAToken,
			"expand":   cmdExpand,
			"freeport": cmdFreePort,
			"shortdir": cmdShortDir,
			"waitfile": cmdWaitFile,
			"waitport": cmdWaitPort,
			"sigterm":  cmdSigterm,
			"audit":    cmdAudit,
		},
	})
}

// cmdUpstream starts a TLS server for localhost in the test process:
//
//	upstream DIR
//
// It writes its CA certificate to DIR/ca.crt, appends one line per request
// to DIR/requests.log, and exports its port as $UPSTREAM_PORT. It stops when
// the script ends.
//
// A path under /truncated answers a body shorter than the Content-Length it
// declares. A path under /stream answers an event stream that keeps sending
// for longer than a short idle timeout. Every other path answers "hello from
// upstream <path>".
//
// The log line includes the target with its query and the Authorization
// header. A scenario can then verify what the proxy wrote into the request.
func cmdUpstream(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 1 {
		ts.Fatalf("usage: upstream DIR")
	}
	dir := ts.MkAbs(args[0])
	authority, err := ca.New(ca.Options{CommonName: "acceptance upstream CA"})
	ts.Check(err)
	leaf, err := authority.Leaf("localhost")
	ts.Check(err)
	_, err = authority.WriteCertificate(dir)
	ts.Check(err)
	requests, err := os.OpenFile(filepath.Join(dir, "requests.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	ts.Check(err)

	server := httptest.NewUnstartedServer(upstreamHandler(requests))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	ts.Defer(func() {
		server.Close()
		_ = requests.Close()
	})
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	ts.Check(err)
	ts.Setenv("UPSTREAM_PORT", port)
}

// These are the client values that the fake authorization server knows. A
// scenario reads them from the environment.
const (
	zoneClientID     = "acceptance-app-credential"
	zoneClientSecret = "acceptance-client-secret"
)

// cmdFakeAS starts a fake Keycard zone over TLS in the test process:
//
//	fakeas DIR RESOURCE=CREDENTIAL...
//
// It grants each named resource the credential beside it and refuses other
// resources with access_denied. It writes its CA certificate to DIR/ca.crt,
// appends one line per token request to DIR/requests.log, and exports its port
// as $ZONE_PORT. It exports the known client as $ZONE_CLIENT_ID and
// $ZONE_CLIENT_SECRET. It stops when the script ends.
func cmdFakeAS(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) < 2 {
		ts.Fatalf("usage: fakeas DIR RESOURCE=CREDENTIAL...")
	}
	dir := ts.MkAbs(args[0])
	grants := make(map[string]string, len(args)-1)
	for _, arg := range args[1:] {
		resource, value, ok := strings.Cut(arg, "=")
		if !ok {
			ts.Fatalf("fakeas: %q is not RESOURCE=CREDENTIAL", arg)
		}
		grants[resource] = value
	}
	authority, err := ca.New(ca.Options{CommonName: "acceptance zone CA"})
	ts.Check(err)
	leaf, err := authority.Leaf("localhost")
	ts.Check(err)
	_, err = authority.WriteCertificate(dir)
	ts.Check(err)
	requests, err := os.OpenFile(filepath.Join(dir, "requests.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	ts.Check(err)

	zone := fakeas.New(fakeas.Options{
		Credentials:   grants,
		ClientSecrets: map[string]string{zoneClientID: zoneClientSecret},
	})
	server := httptest.NewUnstartedServer(logExchanges(zone, requests))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	ts.Defer(func() {
		server.Close()
		_ = requests.Close()
	})
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	ts.Check(err)
	ts.Setenv("ZONE_PORT", port)
	ts.Setenv("ZONE_CLIENT_ID", zoneClientID)
	ts.Setenv("ZONE_CLIENT_SECRET", zoneClientSecret)
}

// cmdSAToken writes a projected ServiceAccount token to a file:
//
//	satoken FILE SUBJECT
//
// The token is an unsigned JWT with SUBJECT as its sub claim. The fake zone
// reads that claim and does not verify a signature, so the scenario needs no
// signing secret.
func cmdSAToken(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 2 {
		ts.Fatalf("usage: satoken FILE SUBJECT")
	}
	claims, err := json.Marshal(map[string]string{"sub": args[1]})
	ts.Check(err)
	encode := base64.RawURLEncoding.EncodeToString
	token := encode([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + encode(claims) + "." + encode([]byte("signature"))
	// The kubelet writes the projected token with mode 0644.
	ts.Check(os.WriteFile(ts.MkAbs(args[0]), []byte(token), 0o644))
}

// logExchanges writes one line per token request that the zone reads. A
// scenario can count exchanges for allowed requests and confirm that denied
// requests make none. The line never includes the issued credential or the
// client secret.
func logExchanges(zone *fakeas.Server, log io.Writer) http.Handler {
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen := len(zone.Requests())
		zone.ServeHTTP(w, r)
		for _, request := range zone.Requests()[seen:] {
			fmt.Fprintf(log, "exchange client=%s actor=%q subject=%s resource=%s error=%q\n",
				request.ClientID, request.Actor, request.Subject, request.Form.Get("resource"), request.Error)
		}
	})
}

// streamEvents and streamInterval shape the event stream: the stream runs
// for longer than the idle timeout a scenario sets, and no gap in it comes
// close to that timeout.
const (
	streamEvents   = 20
	streamInterval = 100 * time.Millisecond
	// truncatedLength is the Content-Length the truncated path declares over
	// the body it writes.
	truncatedLength = "100"
)

// upstreamHandler answers the paths cmdUpstream documents and logs every
// request to requests.
func upstreamHandler(requests io.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(requests, "request %s %s host=%s authorization=%q\n",
			r.Method, r.URL.RequestURI(), r.Host, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		switch {
		case r.URL.Path == "/header/bad-trailer":
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				panic(err)
			}
			defer func() { _ = conn.Close() }()
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"+
				"Trailer: X-End\r\n\r\n1\r\nx\r\n0\r\n%s\r\n\r\n",
				r.Header.Get("Authorization"))
		case strings.HasPrefix(r.URL.Path, "/truncated"):
			w.Header().Set("Content-Length", truncatedLength)
			fmt.Fprint(w, "short")
		case strings.HasPrefix(r.URL.Path, "/stream"):
			w.Header().Set("Content-Type", "text/event-stream")
			writeStream(w, r)
		default:
			//nolint:gosec // G705: a fixture echoing as text/plain
			fmt.Fprintf(w, "hello from upstream %s\n", r.URL.Path)
		}
	}
}

// writeStream sends streamEvents events, one every streamInterval, and stops
// early when the request ends.
func writeStream(w http.ResponseWriter, r *http.Request) {
	controller := http.NewResponseController(w)
	for range streamEvents {
		fmt.Fprint(w, "data: active\n\n")
		if err := controller.Flush(); err != nil {
			return
		}
		select {
		case <-time.After(streamInterval):
		case <-r.Context().Done():
			return
		}
	}
}

// cmdFreePort exports a free TCP port on loopback:
//
//	freeport NAME
func cmdFreePort(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 1 {
		ts.Fatalf("usage: freeport NAME")
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	ts.Check(err)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	ts.Check(listener.Close())
	ts.Check(err)
	ts.Setenv(args[0], port)
}

// cmdExpand rewrites a file in place, replacing every $NAME with the script
// variable of that name:
//
//	expand FILE
//
// testscript expands a variable in a script line and in an archive file's
// name, never in its data. A document that must name a value the script
// chose, such as the upstream's port, is written with $NAME and expanded
// before the proxy reads it.
func cmdExpand(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 1 {
		ts.Fatalf("usage: expand FILE")
	}
	path := ts.MkAbs(args[0])
	data, err := os.ReadFile(path)
	ts.Check(err)
	expanded := os.Expand(string(data), func(name string) string {
		value := ts.Getenv(name)
		if value == "" {
			ts.Fatalf("expand %s: $%s is not set", args[0], name)
		}
		return value
	})
	//nolint:gosec // G703: the path is inside the script's work directory
	ts.Check(os.WriteFile(path, []byte(expanded), 0o600))
}

// cmdShortDir exports a fresh directory under the system temporary
// directory, removed when the script ends:
//
//	shortdir NAME
//
// $WORK is too long for a Unix socket address on macOS, and the admin socket
// needs one.
func cmdShortDir(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 1 {
		ts.Fatalf("usage: shortdir NAME")
	}
	dir, err := os.MkdirTemp("", "egress-acceptance-*")
	ts.Check(err)
	ts.Defer(func() { _ = os.RemoveAll(dir) })
	ts.Setenv(args[0], dir)
}

// cmdWaitFile waits for a file to exist and be non-empty:
//
//	waitfile FILE
func cmdWaitFile(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 1 {
		ts.Fatalf("usage: waitfile FILE")
	}
	path := ts.MkAbs(args[0])
	wait(ts, "file "+args[0], func() bool {
		info, err := os.Stat(path)
		return err == nil && info.Size() > 0
	})
}

// cmdWaitPort waits until a TCP address accepts a connection:
//
//	waitport HOST:PORT
func cmdWaitPort(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 1 {
		ts.Fatalf("usage: waitport HOST:PORT")
	}
	wait(ts, "port "+args[0], func() bool {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", args[0])
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})
}

func wait(ts *testscript.TestScript, what string, ready func() bool) {
	deadline := time.Now().Add(waitFor)
	for !ready() {
		if time.Now().After(deadline) {
			ts.Fatalf("%s not ready after %s", what, waitFor)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// cmdSigterm sends SIGTERM to every background command, which is how the
// kubelet stops a container. testscript's own kill sends only INT or KILL.
//
//	sigterm
func cmdSigterm(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 0 {
		ts.Fatalf("usage: sigterm")
	}
	cmds := ts.BackgroundCmds()
	if len(cmds) == 0 {
		ts.Fatalf("sigterm: no background command")
	}
	for _, cmd := range cmds {
		ts.Check(cmd.Process.Signal(syscall.SIGTERM))
	}
}

// cmdAudit asserts on the records of an audit stream, one JSON object per
// line:
//
//	[!] audit [-all] FILE key=value... key~regexp...
//
// Without -all, at least one record must carry every named field. With !, no
// record can carry them all. With -all, every record must carry them. Keys
// are dotted paths into the record, such as decision.reason or
// outcome.status, and values compare as strings. FILE can be stdout, the
// last command's output.
func cmdAudit(ts *testscript.TestScript, neg bool, args []string) {
	all := len(args) > 0 && args[0] == "-all"
	if all {
		args = args[1:]
	}
	if len(args) < 2 || (all && neg) {
		ts.Fatalf("usage: [!] audit [-all] FILE key=value...")
	}
	matchers := make([]fieldMatcher, 0, len(args)-1)
	for _, arg := range args[1:] {
		matchers = append(matchers, parseMatcher(ts, arg))
	}
	want := strings.Join(args[1:], " ")
	var matched, unmatched []string
	for line := range strings.SplitSeq(strings.TrimSpace(ts.ReadFile(args[0])), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			ts.Fatalf("audit: %s holds a line that is not JSON: %s", args[0], line)
		}
		if allMatch(matchers, flatten("", record, map[string]string{})) {
			matched = append(matched, line)
		} else {
			unmatched = append(unmatched, line)
		}
	}
	switch {
	case all && len(unmatched) > 0:
		ts.Fatalf("audit: %d records do not match %s:\n%s", len(unmatched), want, strings.Join(unmatched, "\n"))
	case neg && len(matched) > 0:
		ts.Fatalf("audit: %d records match %s, want none:\n%s", len(matched), want, strings.Join(matched, "\n"))
	case !neg && !all && len(matched) == 0:
		ts.Fatalf("audit: no record matches %s in:\n%s", want, ts.ReadFile(args[0]))
	}
}

type fieldMatcher struct {
	key     string
	value   string
	pattern *regexp.Regexp
}

func parseMatcher(ts *testscript.TestScript, arg string) fieldMatcher {
	if key, value, ok := strings.Cut(arg, "="); ok && !strings.Contains(key, "~") {
		return fieldMatcher{key: key, value: value}
	}
	if key, pattern, ok := strings.Cut(arg, "~"); ok {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			ts.Fatalf("audit: %q is not a regexp: %v", pattern, err)
		}
		return fieldMatcher{key: key, pattern: compiled}
	}
	ts.Fatalf("audit: %q is not key=value or key~regexp", arg)
	return fieldMatcher{}
}

func allMatch(matchers []fieldMatcher, fields map[string]string) bool {
	for _, m := range matchers {
		value, ok := fields[m.key]
		if !ok {
			return false
		}
		if m.pattern != nil {
			if !m.pattern.MatchString(value) {
				return false
			}
		} else if value != m.value {
			return false
		}
	}
	return true
}

// flatten renders nested JSON as dotted keys with string values, so a script
// names outcome.status=200 without caring that it decoded as a float.
func flatten(prefix string, value any, out map[string]string) map[string]string {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			flatten(strings.TrimPrefix(prefix+"."+key, "."), child, out)
		}
	case []any:
		for i, child := range v {
			flatten(prefix+"["+strconv.Itoa(i)+"]", child, out)
		}
	case float64:
		out[prefix] = strconv.FormatFloat(v, 'f', -1, 64)
	case nil:
		out[prefix] = ""
	default:
		out[prefix] = fmt.Sprint(v)
	}
	return out
}
