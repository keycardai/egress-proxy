package proxy_test

import (
	"net/http"
	// net/http/cgi does not pass the Proxy request header to the child
	// (Go issue 16405), so httpoxy (CVE-2016-5386) does not apply.
	// .golangci.yml does not exempt tests from G504.
	//nolint:gosec // G504: net/http/cgi drops the Proxy header, and this import is test-only
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/internal/policy"
)

// gitPathPrefix is the path prefix of the one endpoint the cases share. It
// covers every repository the upstream serves, so a case gets a repository
// of its own and the cases run in parallel.
const gitPathPrefix = "/"

// seenRequest is one request git-http-backend answered.
type seenRequest struct {
	path          string
	authorization string
}

// gitUpstream serves a directory of bare repositories over git's smart HTTP
// protocol and records what arrived. git-http-backend is the server git
// ships, run over CGI, so the test drives the same protocol a forge does.
//
// It answers 401 to anything but one Authorization value, the way a forge
// answers a wrong token. A case that reached it with the workload's own
// credentials fails at the clone rather than at an assertion.
type gitUpstream struct {
	handler http.Handler
	mu      sync.Mutex
	seen    []seenRequest
}

func newGitUpstream(t *testing.T, root, wantAuthorization string) *gitUpstream {
	t.Helper()
	execPath, err := exec.CommandContext(t.Context(), "git", "--exec-path").Output()
	require.NoError(t, err, "git --exec-path")
	backend := &cgi.Handler{
		Path: filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend"),
		Env: []string{
			"GIT_PROJECT_ROOT=" + root,
			// The repositories hold no secret and the proxy decides who
			// reaches them, so the backend exports every one it is given.
			"GIT_HTTP_EXPORT_ALL=1",
		},
	}
	up := &gitUpstream{}
	up.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		up.mu.Lock()
		up.seen = append(up.seen, seenRequest{path: r.URL.Path, authorization: got})
		up.mu.Unlock()
		if got != wantAuthorization {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(w, r)
	})
	return up
}

// requestsUnder returns what arrived for one repository.
func (u *gitUpstream) requestsUnder(prefix string) []seenRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	var under []seenRequest
	for _, req := range u.seen {
		if strings.HasPrefix(req.path, prefix) {
			under = append(under, req)
		}
	}
	return under
}

// gitEnv is the environment every git command in this file runs under.
//
// NEVER run git in a test without it. git hands a user name to a credential
// helper, and a helper reaches the developer's own credential store. Apple's
// git sets credential.helper=osxkeychain in the system gitconfig, so
// GIT_CONFIG_NOSYSTEM=1 skips that file and an empty credential.helper resets
// the list. HOME, XDG_CONFIG_HOME and GIT_CONFIG_GLOBAL point at a directory
// of this test's own, and a prompt fails rather than blocking.
func gitEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	home := t.TempDir()
	return slices.Concat([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"GIT_CONFIG_GLOBAL=" + filepath.Join(home, "gitconfig"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=true",
		"SSH_ASKPASS=true",
		"GIT_AUTHOR_NAME=test",
		"GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=test",
		"GIT_COMMITTER_EMAIL=test@example.invalid",
	}, extra)
}

// runGit runs one git command and fails the test with its output. Every
// command sets an empty credential.helper, so no run reaches a helper
// whatever the environment holds.
func runGit(t *testing.T, dir string, env []string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-c", "credential.helper="}, args...)...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %s in %s:\n%s", strings.Join(args, " "), dir, out)
}

// newBareRepo creates a bare repository under root with one commit on main
// and returns its path. It writes the repository on disk, not through the
// proxy.
func newBareRepo(t *testing.T, root, name string) string {
	t.Helper()
	bare := filepath.Join(root, name)
	env := gitEnv(t)
	runGit(t, root, env, "init", "--bare", "--initial-branch=main", bare)
	// git-http-backend serves receive-pack only where the repository says
	// it may, and the test pushes over HTTP.
	runGit(t, bare, env, "config", "http.receivepack", "true")
	seed := t.TempDir()
	runGit(t, seed, env, "init", "--initial-branch=main", ".")
	require.NoError(t, os.WriteFile(filepath.Join(seed, "README"), []byte("seed\n"), 0o600), "write the seed file")
	runGit(t, seed, env, "add", "README")
	runGit(t, seed, env, "commit", "-m", "seed")
	runGit(t, seed, env, "push", bare, "main")
	return bare
}

// TestGitOverHTTPS drives real git clone and git push through the proxy at a
// basic placement, once per shape of userinfo a clone URL can hold. The
// placement decides the credentials in every case, so the upstream receives
// one Authorization value whatever the URL said.
func TestGitOverHTTPS(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	up := newGitUpstream(t, root, basicAuthorization())
	h := start(t, harnessOptions{
		upstream: up.handler,
		endpoints: func(port int) []policy.Endpoint {
			return []policy.Endpoint{{
				Host: upstreamHost, Port: port, PathPrefix: gitPathPrefix,
				Resource: headerResource, Credential: &basicPlacement,
			}}
		},
		credentials: staticSource(t),
	})
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(caFile, h.authority.CertificatePEM(), 0o600), "write the proxy CA")
	env := gitEnv(t,
		"HTTPS_PROXY=http://"+h.addr,
		"GIT_SSL_CAINFO="+caFile,
	)

	tests := []struct {
		name string
		repo string
		// userinfo is what the clone URL holds before the host, with its
		// trailing "@".
		userinfo string
	}{
		{name: "no userinfo", repo: "none.git"},
		{name: "a user", repo: "user.git", userinfo: "alice@"},
		{name: "a user and a password", repo: "userpass.git", userinfo: "alice:" + workloadPassword + "@"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			newBareRepo(t, root, tc.repo)
			remote := "https://" + tc.userinfo + h.upstreamAuthority() + "/" + tc.repo
			work := filepath.Join(t.TempDir(), "clone")

			runGit(t, root, env, "clone", remote, work)
			require.FileExists(t, filepath.Join(work, "README"), "the clone holds the seeded file")

			require.NoError(t, os.WriteFile(filepath.Join(work, "NEW"), []byte("pushed\n"), 0o600), "write a file")
			runGit(t, work, env, "add", "NEW")
			runGit(t, work, env, "commit", "-m", "push me")
			runGit(t, work, env, "push", "origin", "main")

			seen := up.requestsUnder("/" + tc.repo + "/")
			require.NotEmpty(t, seen, "the upstream answered requests for %s", tc.repo)
			for _, req := range seen {
				assert.Equal(t, basicAuthorization(), req.authorization,
					"the Authorization header the upstream received for %s", req.path)
			}
			assert.Contains(t, paths(seen), "/"+tc.repo+"/git-upload-pack", "the clone fetched the pack")
			assert.Contains(t, paths(seen), "/"+tc.repo+"/git-receive-pack", "the push sent the pack")
		})
	}
}

func paths(seen []seenRequest) []string {
	out := make([]string, 0, len(seen))
	for _, req := range seen {
		out = append(out, req.path)
	}
	return out
}

// workloadPassword is what a workload puts in a clone URL. The placement
// wins, so the upstream never receives it.
const workloadPassword = "hunter2"
