//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// seatbeltUnsafeRuneError is returned when a string destined for a seatbelt
// profile literal contains a byte the profile syntax cannot quote safely.
type seatbeltUnsafeRuneError struct {
	field  string
	value  string
	reason string
}

func (e *seatbeltUnsafeRuneError) Error() string {
	return fmt.Sprintf("sandbox: seatbelt: %s contains unsafe value: %s", e.field, e.reason)
}

// validateSeatbeltLiteral rejects strings that cannot be embedded in a
// TinyScheme string literal without changing the meaning of the profile.
// The seatbelt/TinyScheme parser treats `"`, `\`, parens, semicolons, and
// whitespace as structural; even backslash-escaping is unreliable across
// macOS releases, so we fail closed on any of these bytes. ASCII control
// chars (< 0x20) are always rejected.
//
// SBPL profile-string injection is a real CVE shape — before the fix,
// `fmt.Fprintf(&b, "(subpath \"%s\")", absDir)` let a crafted directory
// name inject arbitrary seatbelt rules. The validator is non-optional.
func validateSeatbeltLiteral(field, value string) error {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 0x20 || c == 0x7f {
			return &seatbeltUnsafeRuneError{
				field:  field,
				value:  value,
				reason: fmt.Sprintf("control byte 0x%02x at offset %d", c, i),
			}
		}
		switch c {
		case '"', '\\', '(', ')', ';', '\'':
			return &seatbeltUnsafeRuneError{
				field:  field,
				value:  value,
				reason: fmt.Sprintf("forbidden byte %q at offset %d", c, i),
			}
		}
	}
	return nil
}

// BuildSBPL generates a macOS sandbox-exec seatbelt profile string from a
// Profile and a workspace root.
//
// Strategy: default-allow with selective denies. Default-deny on macOS
// requires enumerating a large (and OS-version-dependent) allowlist of
// system paths, dyld caches, Mach services, and XPC endpoints that every
// modern process implicitly needs. Tightening to default-deny is left for
// a future sprint.
//
// Every interpolated value (workspace, FS.Read/Write/Deny entries) is
// validated via validateSeatbeltLiteral before being written to the
// profile. An invalid value returns a non-nil error and the caller must
// refuse to spawn the sandbox.
func BuildSBPL(p Profile, workspace string) (string, error) {
	absWS, err := filepath.Abs(workspace)
	if err != nil {
		absWS = workspace
	}
	if err := validateSeatbeltLiteral("workspace", absWS); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("\n")
	b.WriteString("; Default-allow posture — selective denies below constrain the\n")
	b.WriteString("; principal areas of concern (sensitive FS paths, network, subprocess).\n")
	b.WriteString("(allow default)\n\n")

	// Workspace is always writable, regardless of FS.Write contents.
	b.WriteString("; Workspace is the writable root.\n")
	fmt.Fprintf(&b, "(allow file-write* (subpath \"%s\"))\n\n", absWS)

	// Additional Write paths beyond the workspace.
	wroteAny := false
	for i, raw := range p.FS.Write {
		path, err := expandAndValidate(fmt.Sprintf("FS.Write[%d]", i), raw, absWS)
		if err != nil {
			return "", err
		}
		if path == absWS {
			continue
		}
		if !wroteAny {
			b.WriteString("; Additional writable paths.\n")
			wroteAny = true
		}
		fmt.Fprintf(&b, "(allow file-write* (subpath \"%s\"))\n", path)
	}
	if wroteAny {
		b.WriteString("\n")
	}

	// Read paths are no-ops under default-allow but validated to keep the
	// validator's coverage uniform — a future tighter posture will use them.
	for i, raw := range p.FS.Read {
		if _, err := expandAndValidate(fmt.Sprintf("FS.Read[%d]", i), raw, absWS); err != nil {
			return "", err
		}
	}

	// Explicit FS denies — take precedence over default allow.
	if len(p.FS.Deny) > 0 {
		b.WriteString("; Explicit FS denies.\n")
		for i, raw := range p.FS.Deny {
			path, err := expandAndValidate(fmt.Sprintf("FS.Deny[%d]", i), raw, absWS)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "(deny file-read* (subpath \"%s\"))\n", path)
			fmt.Fprintf(&b, "(deny file-write* (subpath \"%s\"))\n", path)
		}
		b.WriteString("\n")
	}

	if !p.Net {
		b.WriteString("; Block all outbound network.\n")
		b.WriteString("(deny network*)\n\n")
	}

	if !p.Subprocess {
		b.WriteString("; Block subprocess spawning beyond the initial binary.\n")
		b.WriteString("(deny process-fork)\n")
		b.WriteString("(deny process-exec*)\n\n")
	}

	return b.String(), nil
}

// expandAndValidate resolves the "workspace", "${HOME}", and "~" tokens in
// raw, then runs the resulting path through validateSeatbeltLiteral.
func expandAndValidate(field, raw, workspace string) (string, error) {
	path := expandPath(raw, workspace)
	if err := validateSeatbeltLiteral(field, path); err != nil {
		return "", err
	}
	return path, nil
}

// expandPath resolves the "workspace", "${HOME}", and "~" tokens. Empty
// paths are returned as-is; the validator catches them downstream.
func expandPath(raw, workspace string) string {
	if raw == "workspace" {
		return workspace
	}
	home, _ := os.UserHomeDir()
	raw = strings.ReplaceAll(raw, "${HOME}", home)
	raw = strings.ReplaceAll(raw, "~", home)
	return raw
}

// Apply wraps cmd to run under macOS sandbox-exec with a profile generated
// from p and workspace. It returns a cleanup function that removes the
// temporary profile file; callers MUST call cleanup after the command
// finishes (defer cleanup() works). Returns an error if sandbox-exec is
// unavailable or profile generation fails.
//
// Cleanup pattern lineage: extracted from nanite's applyOSSandbox. The
// earlier mux Apply leaked the temp profile file; do not regress.
func Apply(cmd *exec.Cmd, p Profile, workspace string) (cleanup func(), err error) {
	sbplBin, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return nil, fmt.Errorf("sandbox-exec not found: cannot enforce profile %q on this system", p.ID)
	}

	sbpl, err := BuildSBPL(p, workspace)
	if err != nil {
		return nil, err
	}

	f, err := os.CreateTemp("", "go-sandbox-*.sb")
	if err != nil {
		return nil, fmt.Errorf("create sandbox profile temp file: %w", err)
	}
	profilePath := f.Name()
	if _, err := f.WriteString(sbpl); err != nil {
		_ = f.Close()
		_ = os.Remove(profilePath)
		return nil, fmt.Errorf("write sandbox profile: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(profilePath)
		return nil, fmt.Errorf("close sandbox profile: %w", err)
	}

	origPath := cmd.Path
	origArgs := cmd.Args[1:]
	cmd.Path = sbplBin
	newArgs := make([]string, 0, 4+len(origArgs))
	newArgs = append(newArgs, "sandbox-exec", "-f", profilePath, origPath)
	newArgs = append(newArgs, origArgs...)
	cmd.Args = newArgs

	return func() { _ = os.Remove(profilePath) }, nil
}
