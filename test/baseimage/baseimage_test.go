package baseimage_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keycardai/egress-proxy/test/baseimage"
)

const root = "../.."

func TestReferences(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		dockerfile string
		want       []string
		wantErr    string
	}{
		{
			name:       "one stage",
			dockerfile: "FROM debian:trixie-slim@sha256:00\nRUN true\n",
			want:       []string{"debian:trixie-slim@sha256:00"},
		},
		{
			name:       "named stages and a build arg, in order",
			dockerfile: "ARG KO_IMAGE\nFROM ${KO_IMAGE} AS ko\nFROM debian:trixie-slim AS setcap\nFROM ${KO_IMAGE}\n",
			want:       []string{"${KO_IMAGE}", "debian:trixie-slim", "${KO_IMAGE}"},
		},
		{
			name:       "a platform flag and a lower-case instruction",
			dockerfile: "from --platform=$BUILDPLATFORM golang:1.27 AS build\n",
			want:       []string{"golang:1.27"},
		},
		{
			name:       "a comment and a RUN that mention FROM",
			dockerfile: "# FROM is the base\nFROM debian\nRUN echo FROM x\n",
			want:       []string{"debian"},
		},
		{
			name:       "a FROM split across lines",
			dockerfile: "FROM \\\n  debian:trixie-slim \\\n  AS base\n",
			want:       []string{"debian:trixie-slim"},
		},
		{
			name:       "an escape directive",
			dockerfile: "# escape=`\nFROM `\n  debian:trixie-slim\n",
			want:       []string{"debian:trixie-slim"},
		},
		{
			name:       "no FROM line",
			dockerfile: "RUN true\n",
			want:       nil,
		},
		{
			name:       "a FROM with only a flag",
			dockerfile: "RUN true\nFROM --platform=linux/amd64\n",
			wantErr:    "line 2: a FROM does not name an image",
		},
		{
			name:       "a FROM with nothing after it",
			dockerfile: "FROM\n",
			wantErr:    "line 1: a FROM does not name an image",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := baseimage.References([]byte(tt.dockerfile))
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDebianIsAPinnedReference(t *testing.T) {
	t.Parallel()
	ref, err := baseimage.Debian(root)
	require.NoError(t, err)
	assert.Regexp(t, `^debian:[^@\s]+@sha256:[0-9a-f]{64}$`, ref,
		"the pin names a tag and a digest")
}

// TestEveryImageNamesTheSamePin checks that every Debian FROM line under
// images/ names the same pin. Dependabot updates them in one grouped PR, so
// they differ only after a hand edit to one of them.
func TestEveryImageNamesTheSamePin(t *testing.T) {
	t.Parallel()
	want, err := baseimage.Debian(root)
	require.NoError(t, err)

	paths, err := filepath.Glob(filepath.Join(root, "images", "*", "Dockerfile"))
	require.NoError(t, err)

	var pinned []string
	for _, path := range paths {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		refs, err := baseimage.References(data)
		require.NoError(t, err, path)
		for _, ref := range refs {
			if !strings.HasPrefix(ref, "debian:") {
				continue
			}
			rel, err := filepath.Rel(root, path)
			require.NoError(t, err)
			pinned = append(pinned, rel)
			assert.Equal(t, want, ref, "the Debian base in %s", rel)
		}
	}
	// Each image has one Debian stage. If a file is missing here, its pin
	// was removed or the file moved, and the loop above skipped it.
	assert.Equal(t, []string{
		"images/netsetup/Dockerfile",
		"images/proxy/Dockerfile",
		"images/sandbox-base/Dockerfile",
	}, pinned)
}
