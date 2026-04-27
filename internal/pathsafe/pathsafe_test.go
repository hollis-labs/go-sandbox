package pathsafe

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func mustEvalRoot(t *testing.T, root string) string {
	t.Helper()
	evald, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", root, err)
	}
	return evald
}

func TestResolveUnder_Table(t *testing.T) {
	root := t.TempDir()
	root = mustEvalRoot(t, root)

	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "file.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "other"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(filepath.Join(root, "sub", "file.txt"),
		filepath.Join(root, "inside-link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	outside := t.TempDir()
	outside = mustEvalRoot(t, outside)
	if err := os.Symlink(outside, filepath.Join(root, "escape-link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	cases := []struct {
		name       string
		input      string
		wantErr    bool
		wantEscape bool
		wantSuffix string
	}{
		{name: "simple relative", input: "sub/file.txt", wantSuffix: "sub/file.txt"},
		{name: "dot-slash prefix", input: "./sub/file.txt", wantSuffix: "sub/file.txt"},
		{name: "absolute treated as root-relative", input: "/sub/file.txt", wantSuffix: "sub/file.txt"},
		{name: "nonexistent leaf", input: "sub/newfile.txt", wantSuffix: "sub/newfile.txt"},
		{name: "nonexistent deep path", input: "sub/nested/deep/new.txt", wantSuffix: "sub/nested/deep/new.txt"},
		{name: "dotdot escape", input: "../elsewhere", wantErr: true, wantEscape: true},
		{name: "dotdot mid-path", input: "sub/../../elsewhere", wantErr: true, wantEscape: true},
		{name: "dotdot back inside", input: "sub/../other", wantSuffix: "other"},
		{name: "root itself", input: ".", wantSuffix: filepath.Base(root)},
		{name: "null byte", input: "sub/\x00bad", wantErr: true, wantEscape: true},
		{name: "symlink within root", input: "inside-link", wantSuffix: "sub/file.txt"},
		{name: "symlink escape", input: "escape-link", wantErr: true, wantEscape: true},
		{name: "symlink escape subpath", input: "escape-link/child", wantErr: true, wantEscape: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveUnder(root, tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				if tc.wantEscape {
					var esc *EscapeError
					if !errors.As(err, &esc) {
						t.Fatalf("expected *EscapeError, got %T: %v", err, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.HasPrefix(got, root) {
				t.Fatalf("resolved %q not under root %q", got, root)
			}
			if tc.wantSuffix != "" {
				want := filepath.Join(root, filepath.FromSlash(tc.wantSuffix))
				if tc.name == "root itself" {
					want = root
				}
				if got != want {
					t.Fatalf("got %q, want %q", got, want)
				}
			}
		})
	}
}

func TestResolveUnder_EmptyRoot(t *testing.T) {
	if _, err := ResolveUnder("", "x"); err == nil {
		t.Fatal("expected error on empty root")
	}
}

func TestEscapeError_Unwrap(t *testing.T) {
	cause := errors.New("boom")
	e := &EscapeError{Root: "/a", Attempt: "x", Cause: cause}
	if !errors.Is(e, cause) {
		t.Fatal("errors.Is(cause) should be true")
	}
	if e.Error() == "" {
		t.Fatal("empty Error()")
	}
}

func TestResolveUnder_NonexistentRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "does", "not", "exist")
	got, err := ResolveUnder(root, "child.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "child.txt") {
		t.Fatalf("got %q, want suffix child.txt", got)
	}
}

func TestResolveUnder_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only test")
	}
}
